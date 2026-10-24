use rustix::event::{PollFd, PollFlags, poll};
use rustix::fd::{AsRawFd, BorrowedFd, OwnedFd};
use rustix::net::{AddressFamily, SocketFlags, SocketType, recv, send, socket_with};
use rustix::time::Timespec;
use std::time::Duration;


#[inline(always)]
fn read_u16_ne(buf: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([buf[off], buf[off + 1]])
}

#[inline(always)]
fn read_u32_ne(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline(always)]
fn read_u32_bytes(buf: &[u8], off: usize) -> [u8; 4] {
    [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkError {
    SocketError,
    SendError,
    RecvError,
    ProtocolError,
}

/// Retrieve IPv4 address for an interface via Linux Netlink (RTM_GETADDR).
/// Correctly distinguishes IFA_LOCAL (local address) from IFA_ADDRESS (peer on P2P/PPPoE).
///
/// Returns:
/// - `Ok(Some(ip))` if a global IPv4 address is found
/// - `Ok(None)` if the netlink dump completed successfully (NLMSG_DONE) or interface doesn't exist,
///   confirming that the interface truly has no global IPv4 address
/// - `Err(NetlinkError)` if socket creation, send, or recv times out/fails (transient error).
pub fn get_iface_ipv4(ifname: &str) -> Result<Option<[u8; 4]>, NetlinkError> {
    let ifindex_str = match std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifname)) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let target_ifindex: u32 = match ifindex_str.trim().parse() {
        Ok(idx) => idx,
        Err(_) => return Ok(None),
    };

    let sock = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| NetlinkError::SocketError)?;

    let _ = rustix::net::sockopt::set_socket_timeout(
        &sock,
        rustix::net::sockopt::Timeout::Recv,
        Some(std::time::Duration::from_secs(1)),
    );

    let mut req_bytes = [0u8; 24];
    req_bytes[0..4].copy_from_slice(&(24u32).to_ne_bytes());
    req_bytes[4..6].copy_from_slice(&(22u16).to_ne_bytes()); // RTM_GETADDR
    req_bytes[6..8].copy_from_slice(&(0x0301u16).to_ne_bytes()); // NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH
    req_bytes[8..12].copy_from_slice(&(1u32).to_ne_bytes());
    req_bytes[12..16].copy_from_slice(&(0u32).to_ne_bytes());
    req_bytes[16] = 2; // AF_INET
    req_bytes[20..24].copy_from_slice(&target_ifindex.to_ne_bytes());

    if send(&sock, &req_bytes, rustix::net::SendFlags::empty()).is_err() {
        return Err(NetlinkError::SendError);
    }

    let mut buf = [0u8; 32768];
    loop {
        let (n, _) = recv(&sock, &mut buf, rustix::net::RecvFlags::empty())
            .map_err(|_| NetlinkError::RecvError)?;
        if n == 0 {
            break;
        }

        let mut offset = 0;
        while offset + 16 <= n {
            let nlmsg_len = read_u32_ne(&buf, offset) as usize;
            let nlmsg_type = read_u16_ne(&buf, offset + 4);

            if nlmsg_type == 2 {
                return Err(NetlinkError::ProtocolError);
            }
            if nlmsg_type == 3 {
                return Ok(None);
            }
            if nlmsg_type == 20 && offset + 16 + 8 <= n {
                let ifa_family = buf[offset + 16];
                let ifa_flags = buf[offset + 18];
                let ifa_scope = buf[offset + 19];
                let ifa_index = read_u32_ne(&buf, offset + 20);
                if ifa_family == 2 && ifa_index == target_ifindex && ifa_scope == 0 && (ifa_flags & 0x01) == 0 {
                    let mut rta_offset = offset + 24;
                    let end = (offset + nlmsg_len).min(n);
                    let mut ifa_local = None;
                    let mut ifa_address = None;
                    while rta_offset + 4 <= end {
                        let rta_len = read_u16_ne(&buf, rta_offset) as usize;
                        let rta_type = read_u16_ne(&buf, rta_offset + 2);
                        if rta_len < 4 {
                            break;
                        }
                        if rta_type == 2 && rta_offset + 8 <= end {
                            ifa_local = Some(read_u32_bytes(&buf, rta_offset + 4));
                        } else if rta_type == 1 && rta_offset + 8 <= end {
                            ifa_address = Some(read_u32_bytes(&buf, rta_offset + 4));
                        }
                        rta_offset += (rta_len + 3) & !3;
                    }
                    if let Some(ip) = ifa_local.or(ifa_address) {
                        return Ok(Some(ip));
                    }
                }
            }

            let aligned_len = (nlmsg_len + 3) & !3;
            if aligned_len == 0 || offset + aligned_len > n {
                break;
            }
            offset += aligned_len;
        }
    }

    Ok(None)
}

/// Detect L2 header length for interface.
/// Returns 14 for Ethernet (ARPHRD_ETHER = 1), 0 for PPP (512), NONE (65534), RAWIP (519), etc.
pub fn get_iface_l2_len(ifname: &str) -> u32 {
    let type_path = format!("/sys/class/net/{}/type", ifname);
    if let Ok(content) = std::fs::read_to_string(type_path) {
        if let Ok(dev_type) = content.trim().parse::<u16>() {
            if dev_type == 1 {
                return 14;
            } else {
                return 0;
            }
        }
    }
    14
}

/// rtnetlink multicast groups: link state and IPv4/IPv6 address changes.
const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

/// Subscription to rtnetlink link/address notifications.
pub struct EventMonitor {
    sock: OwnedFd,
}

impl EventMonitor {
    pub fn new() -> Result<Self, NetlinkError> {
        let sock = socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| NetlinkError::SocketError)?;

        let groups = (1u32 << (RTNLGRP_LINK - 1))
            | (1u32 << (RTNLGRP_IPV4_IFADDR - 1))
            | (1u32 << (RTNLGRP_IPV6_IFADDR - 1));
        // rustix does not expose sockaddr_nl, so bind(2) is called directly.
        unsafe {
            let mut addr: libc::sockaddr_nl = core::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            addr.nl_groups = groups;
            let ret = libc::bind(
                sock.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(NetlinkError::SocketError);
            }
        }

        Ok(Self { sock })
    }

    /// Wait for a notification, a wake pipe byte or the timeout.
    pub fn wait(&self, wake: BorrowedFd<'_>, timeout: Duration) -> bool {
        let ts = Timespec {
            tv_sec: timeout.as_secs() as i64,
            tv_nsec: timeout.subsec_nanos() as i64,
        };
        let mut fds = [
            PollFd::new(&self.sock, PollFlags::IN),
            PollFd::new(&wake, PollFlags::IN),
        ];

        match poll(&mut fds, Some(&ts)) {
            Ok(n) if n > 0 => {
                if fds[0].revents().contains(PollFlags::IN) {
                    // Drain the socket, otherwise the next poll returns at once.
                    let mut buf = [0u8; 4096];
                    while let Ok((n, _)) = recv(&self.sock, &mut buf, rustix::net::RecvFlags::DONTWAIT)
                    {
                        if n == 0 {
                            break;
                        }
                    }
                }
                true
            }
            _ => false,
        }
    }
}

/// Read the kernel ifindex of an interface (`None` if it does not exist).
pub fn get_ifindex(ifname: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifname))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Retrieve global IPv6 address from standard Linux /proc/net/if_inet6.
/// Returns `Ok(Some(ip))` if found, `Ok(None)` if file read succeeded but interface has no global IPv6,
/// or `Err(e)` on filesystem I/O error.
pub fn get_iface_ipv6(ifname: &str) -> Result<Option<[u8; 16]>, std::io::Error> {
    let content = std::fs::read_to_string("/proc/net/if_inet6")?;
    Ok(parse_proc_inet6(&content, ifname))
}

/// Pure parser for /proc/net/if_inet6 lines.
///
/// Skips temporary, tentative, failed and deprecated addresses and prefers
/// permanent ones. Only 2000::/3 is accepted: ULA also has scope 00 but is
/// not a valid WAN address. The kernel prints the flags as a u8.
pub fn parse_proc_inet6(content: &str, target_ifname: &str) -> Option<[u8; 16]> {
    let mut fallback = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hex_addr), Some(_ifindex), Some(_plen), Some(scope), Some(flags_str), Some(dev)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            // A short line must not abort the whole scan.
            continue;
        };

        // scope 00 = global scope
        if dev != target_ifname || scope != "00" || hex_addr.len() != 32 {
            continue;
        }

        let Ok(flags) = u8::from_str_radix(flags_str, 16) else {
            continue;
        };
        // Skip IFA_F_TEMPORARY (0x01), IFA_F_DADFAILED (0x08), IFA_F_DEPRECATED (0x20), IFA_F_TENTATIVE (0x40)
        if (flags & 0x69) != 0 {
            continue;
        }

        let mut bytes = [0u8; 16];
        let mut valid = true;
        for i in 0..16 {
            if let Ok(b) = u8::from_str_radix(&hex_addr[i * 2..i * 2 + 2], 16) {
                bytes[i] = b;
            } else {
                valid = false;
                break;
            }
        }
        // RFC 4291 global unicast 2000::/3; excludes ULA fc00::/7.
        if !valid || (bytes[0] & 0xe0) != 0x20 {
            continue;
        }

        // Prefer permanent address (IFA_F_PERMANENT = 0x80)
        if (flags & 0x80) != 0 {
            return Some(bytes);
        } else if fallback.is_none() {
            fallback = Some(bytes);
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_inet6() {
        let sample = "\
00000000000000000000000000000001 01 80 10 80       lo
fe8000000000000002155dfffe123456 02 40 20 80     eth0
240e0123456789abcdef0123456789ad 03 40 00 01     eth1
240e0123456789abcdef0123456789ac 03 40 00 40     eth1
240e0123456789abcdef0123456789ab 03 40 00 80     eth1
";
        // 240e...ad has flag 0x01 (IFA_F_TEMPORARY, privacy extension) and should be skipped.
        // 240e...ac has flag 0x40 (IFA_F_TENTATIVE, DAD in progress) and should be skipped.
        // 240e...ab has flag 0x80 (permanent) and should be chosen.
        let res = parse_proc_inet6(sample, "eth1").expect("should find global IPv6 for eth1");
        assert_eq!(
            res,
            [
                0x24, 0x0e, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab
            ]
        );

        assert_eq!(parse_proc_inet6(sample, "lo"), None); // scope 10 != 00
        assert_eq!(parse_proc_inet6(sample, "eth0"), None); // scope 20 != 00
    }

    #[test]
    fn test_parse_proc_inet6_rejects_ula() {
        // ULA has scope 00 as well; it must never become the WAN NAT66 source.
        let sample = "\
fd60202600000000001132fffe2c2777 03 40 00 80     eth1
";
        assert_eq!(parse_proc_inet6(sample, "eth1"), None);

        // A permanent ULA must not shadow a (non permanent) GUA.
        let sample2 = "\
fd60202600000000001132fffe2c2777 03 40 00 80     eth1
240e039010879391001132fffe243f6f 03 40 00 00     eth1
";
        assert_eq!(
            parse_proc_inet6(sample2, "eth1"),
            Some([
                0x24, 0x0e, 0x03, 0x90, 0x10, 0x87, 0x93, 0x91, 0x00, 0x11, 0x32, 0xff, 0xfe, 0x24,
                0x3f, 0x6f
            ])
        );
    }

    #[test]
    fn test_parse_proc_inet6_skips_short_lines() {
        // A truncated line must not abort the scan (no `?` early return).
        let sample = "\
this line is broken
240e039010879391001132fffe243f6f 03 40 00 80     eth1
";
        assert!(parse_proc_inet6(sample, "eth1").is_some());
    }

    #[test]
    fn test_parse_proc_inet6_bad_flags() {
        // Unparsable flags (defensive; the kernel always prints a u8) skip the line.
        let sample = "\
240e039010879391001132fffe243f6f 03 40 00 zz     eth1
";
        assert_eq!(parse_proc_inet6(sample, "eth1"), None);
    }

    #[test]
    fn test_get_ifindex_loopback() {
        // lo always exists and has ifindex 1.
        assert_eq!(get_ifindex("lo"), Some(1));
        assert_eq!(get_ifindex("does-not-exist-xyz"), None);
    }
}
