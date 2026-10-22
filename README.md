# FlowCone

基于 eBPF 与 TCX 实现的通用 Linux 双栈 RFC 4787 Full-Cone NAT 引擎（提供 OpenWrt 深度集成支持）。

---

## 概述

FlowCone 是面向现代 Linux 内核（Linux 6.6 / 6.12+）构建的高性能 RFC 4787 Full-Cone（完全圆锥型）NAT 解决方案。核心数据面运行于网络接口的 TCX（Ingress 与 Egress）钩子上，全栈采用纯 Rust 开发（内核态基于 `aya-ebpf`，用户态控制面基于 `aya`）。

项目设计为**通用 Linux 原生组件**，可无缝运行于任何现代 Linux 发行版（如 Debian、Ubuntu、Arch Linux、Alpine 等），同时为 **OpenWrt** 路由器系统提供了开箱即用的深度增强与打包支持。

---

## 核心特性

### 1. 通用 Linux 网络层特性
- **RFC 4787 规范实现 (UDP)**：
  - **EIM (Endpoint-Independent Mapping)**：相同内网 IP 和端口在映射有效期内固定使用相同的公网端口。
  - **EIF (Endpoint-Independent Filtering)**：任意外部主机向已建立的公网端口发送 UDP 报文均可直接穿透转发至内网对应主机。
  - **端口保留与奇偶保持**：内置基于 BPF Array Bitmap 的高效端口分配器，优先保持内网原始端口及其奇偶性（符合 RFC 4787 建议）。
- **TCX Link Order 编排（多 BPF 扩展安全共存）**：
  - 数据面以 `LinkOrder::last()` 顺序挂载于 TCX Ingress 和 Egress 链尾。
  - **入站 (Ingress)**：保持链尾挂载，确保上游其他 BPF 过滤器与透明代理程序优先审视合法的公网 WAN IP；未被上游拦截或重定向的直连流量，才流经 FlowCone 执行 DNAT 还原为内网 IP，避免因目的 IP 过早被改写为私网地址而破坏上游组件的路由检查或安全校验。
  - **出站 (Egress)**：同样挂载于链尾，使上游流量调度与策略路由组件能依据真实的内网源 IP 进行规则匹配与分流；直连发往公网的数据包在最终离开网卡前由 FlowCone 执行 SNAT。
  - 支持通过 `--bypass-mark` 配合 fwmark 机制直接放行特定标记的报文。
- **内核软件流表兼容 (Software Flowtable)**：
  - FlowCone 在 TC Ingress 执行 DNAT，在 TC Egress 执行 SNAT，进出 Netfilter 协议栈的报文始终呈现对称的五元组，可被内核 Software Flowtable 正常卸载加速。
- **IPv4 / IPv6 双栈自适应**：
  - 默认启用 IPv4 Full-Cone NAT。
  - IPv6 支持自适应模式：
    - 无 Masquerade 时（原生公网路由环境）：仅对 ULA (`fc00::/7`) 实施 NAT66，原生 GUA 公网流量走系统路由线速直通。
    - 探测到系统开启 IPv6 Masquerade 时：自动切换为全局 NAT66 Full-Cone。
- **nftables 规则自闭环管理**：
  - 启动时自动配置所需的防火墙规则（包括端口范围 NAT 豁免与标记流量放行）。
  - 在通用 Linux 环境下，自动创建独立的 `table inet flowcone` 表；
  - 退出时自动清理规则，不留历史残留。
- **Fail-Open 贯通保证**：
  - 非 UDP 报文、异常报文及退出清理阶段一律返回 `TC_ACT_UNSPEC`，确保常规网络通信在任何情况下不被阻断。

### 2. OpenWrt 专属集成增强
- **fw4 深度集成**：自动探测 OpenWrt 的 `table inet fw4`，在 `srcnat` 与 `forward` 链中热注入规则，并自动注册到 `/etc/firewall4.user`，免疫防火墙热重载。
- **外挂 BTF 支持**：针对官方 OpenWrt 原版内核未内置 `CONFIG_DEBUG_INFO_BTF=y` 的情况，自动探测外挂 BTF（如 `vmlinux-btf` 提供的 `/usr/lib/debug/boot/vmlinux`），免重编译内核即可完成 CO-RE 重定位。
- **系统服务与 Web 管理**：开箱提供 Procd 进程托管脚本、UCI 配置文件（`/etc/config/flowcone`）以及 LuCI Web 管理界面（`luci-app-flowcone`）。

---

## 架构拓扑

```
入站 (WAN Ingress):
  外部报文 (dst: WAN_IP:Port)
    └─► TCX Ingress (链首/前序 BPF: 流量过滤 / 代理接入 / 策略路由)
          └─► FlowCone Ingress (链尾: EIF 查表 DNAT -> LAN_IP:Port, 打标 0x4643)
                └─► Netfilter / Software Flowtable / 内核路由
                      └─► 发往 LAN 客户端

出站 (WAN Egress):
  LAN 报文 (src: LAN_IP:Port)
    └─► 内核路由 / Software Flowtable
          └─► TCX Egress (链首/前序 BPF: 基于内网源 IP 进行策略分流)
                └─► FlowCone Egress (链尾: EIM 查表/建表 SNAT -> WAN_IP:Port)
                      └─► 物理网卡发往 WAN
```

---

## 仓库结构

```
FlowCone/
├── Cargo.toml                  # Cargo Workspace 配置
├── crates/
│   ├── flowcone-common/        # 共享数据结构 (五元组、配置结构体、RFC 4787 算法, #![no_std])
│   ├── flowcone-daemon/        # 用户态控制面守护进程 (BTF 加载, Netlink 监听, GC, nftables)
│   └── flowcone-ebpf/          # 内核态 eBPF 数据面 (#![no_std], aya-ebpf)
└── openwrt/
    ├── flowcone/               # OpenWrt 主程序包定义
    │   ├── Makefile            # 包构建脚本
    │   └── files/
    │       ├── flowcone.config # UCI 默认配置文件 (/etc/config/flowcone)
    │       └── flowcone.init   # Procd 启动管理脚本 (/etc/init.d/flowcone)
    └── luci-app-flowcone/      # OpenWrt LuCI Web 管理界面
        ├── Makefile
        ├── htdocs/             # 前端视图 (基于 JavaScript View)
        ├── po/                 # 多语言翻译 (zh_Hans)
        └── root/               # 菜单与 RPCD ucode 状态接口定义
```

---

## 系统要求

- **操作系统**：Linux Kernel >= 6.6（推荐 6.12+，具备完整 TCX 支持）。
- **内核配置**：
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_NET_CLS_ACT=y`
  - 内核内置 BTF (`CONFIG_DEBUG_INFO_BTF=y`) 或存在外挂 BTF 文件（如 `/usr/lib/debug/boot/vmlinux`）。
- **防火墙工具**：`nftables`。

---

## 编译指南

### 1. 本地独立编译（通用 Linux / 开发环境）

编译 eBPF 模块需要使用 Rust Nightly 工具链及 `bpfel-unknown-none` 目标：

```bash
# 1. 安装 eBPF 目标架构组件
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly

# 2. 编译 eBPF 数据面二进制
cargo +nightly build --release \
  --target=bpfel-unknown-none \
  -Z build-std=core \
  --manifest-path crates/flowcone-ebpf/Cargo.toml

# 3. 编译用户态控制面守护进程 (自动嵌入上一步产出的 eBPF 字节码)
cargo build --release -p flowcone-daemon

# 产物位于 target/release/flowcone
```

### 2. OpenWrt 源码树打包编译

将 `openwrt/flowcone` 和 `openwrt/luci-app-flowcone` 放入 OpenWrt 源码树的 `package/` 目录：

```bash
# 在 OpenWrt 源码根目录下
./scripts/feeds update -a && ./scripts/feeds install -a
make menuconfig
# 进入 Network -> Routing and Redirection -> 选择 flowcone
# 进入 LuCI -> Applications -> 选择 luci-app-flowcone
make package/flowcone/compile V=s
make package/luci-app-flowcone/compile V=s
```

---

## 配置与运行

### 命令行运行参数（通用 Linux）

`flowcone` 支持直接以命令行方式在前台或通过 systemd 运行：

```text
FlowCone — Dual-Stack RFC 4787 Full-Cone NAT for Linux
用法: flowcone [选项]

选项:
  -i, --iface <IFACE>            WAN 物理/逻辑接口名 (默认: wan)
  -b, --btf <PATH>               指定 vmlinux BTF 文件路径 (可选, 默认自动探测)
      --enable-v4 <1|0>          启用 IPv4 Full-Cone NAT (默认: 1)
      --enable-v6 <1|0>          启用 IPv6 Full-Cone NAT (自适应模式, 默认: 0)
      --min-port <PORT>          端口分配池起始端口 (默认: 1024)
      --max-port <PORT>          端口分配池截止端口 (默认: 65535)
      --timeout <SEC>            会话空闲超时时间，单位秒 (默认: 120)
      --interval <SEC>           垃圾回收 (GC) 扫描周期，单位秒 (默认: 5)
      --bypass-mark <VAL[/MASK]> 绕过 FlowCone 处理的 skb mark 标记 (如: 0x1/0x1)
      --manage-nft <1|0>         是否自动管理 nftables 防火墙规则 (默认: 1)
  -v, --verbose                  输出详细调试日志
  -h, --help                     显示帮助信息
```

### OpenWrt 配置文件与服务管理

在 OpenWrt 系统中，服务由 procd 统一管理，配置文件位于 `/etc/config/flowcone`：

```uci
config flowcone 'config'
	option enable_v4 '1'
	option enable_v6 '0'
	option interface 'wan'
	option min_port '1024'
	option max_port '65535'
	option timeout '120'
	option interval '5'
	option manage_nft '1'
	# option bypass_mark '0x1'
```

服务启停：

```bash
/etc/init.d/flowcone start      # 启动服务
/etc/init.d/flowcone stop       # 停止服务并自动撤销防火墙规则
/etc/init.d/flowcone restart    # 重启服务
/etc/init.d/flowcone enable     # 开启开机自启
```

### Web 管理界面 (LuCI)

安装 `luci-app-flowcone` 后，登录 OpenWrt Web 界面，进入 **网络 (Network) -> FlowCone**，即可查看运行状态、进程内存占用，并直接配置端口池与超时参数。

---

## 许可证

本项目采用 [GPL-3.0-or-later](LICENSE) 许可证开源。
