use rustix::net::{AddressFamily, SocketFlags, SocketType, recv, send, socket_with};

#[repr(C)]
struct NlReq {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

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

/// Retrieve IPv4 address for an interface via Linux Netlink (RTM_GETADDR).
/// Correctly distinguishes IFA_LOCAL (local address) from IFA_ADDRESS (peer on P2P/PPPoE).
pub fn get_iface_ipv4(ifname: &str) -> Option<[u8; 4]> {
    let ifindex_str = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifname)).ok()?;
    let target_ifindex: u32 = ifindex_str.trim().parse().ok()?;

    let sock = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )
    .ok()?;

    let req = NlReq {
        nlmsg_len: std::mem::size_of::<NlReq>() as u32,
        nlmsg_type: 22,               // RTM_GETADDR
        nlmsg_flags: 0x0001 | 0x0300, // NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH
        nlmsg_seq: 1,
        nlmsg_pid: 0,
        ifa_family: 2, // AF_INET
        ifa_prefixlen: 0,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: target_ifindex,
    };

    let req_bytes = unsafe {
        std::slice::from_raw_parts(
            &req as *const NlReq as *const u8,
            std::mem::size_of::<NlReq>(),
        )
    };

    if send(&sock, req_bytes, rustix::net::SendFlags::empty()).is_err() {
        return None;
    }

    let mut buf = [0u8; 4096];
    loop {
        let (n, _) = recv(&sock, &mut buf, rustix::net::RecvFlags::empty()).ok()?;
        if n == 0 {
            break;
        }

        let mut offset = 0;
        while offset + 16 <= n {
            let nlmsg_len = read_u32_ne(&buf, offset) as usize;
            let nlmsg_type = read_u16_ne(&buf, offset + 4);

            if nlmsg_type == 3 || nlmsg_type == 2 {
                // NLMSG_DONE or NLMSG_ERROR
                return None;
            }
            if nlmsg_type == 20 && offset + 16 + 8 <= n {
                // RTM_NEWADDR
                let ifa_family = buf[offset + 16];
                let ifa_index = read_u32_ne(&buf, offset + 20);
                if ifa_family == 2 && ifa_index == target_ifindex {
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
                        // IFA_LOCAL = 2 (local address), IFA_ADDRESS = 1 (peer on P2P/PPPoE)
                        if rta_type == 2 && rta_offset + 8 <= end {
                            ifa_local = Some(read_u32_bytes(&buf, rta_offset + 4));
                        } else if rta_type == 1 && rta_offset + 8 <= end {
                            ifa_address = Some(read_u32_bytes(&buf, rta_offset + 4));
                        }
                        rta_offset += (rta_len + 3) & !3;
                    }
                    if let Some(ip) = ifa_local.or(ifa_address) {
                        return Some(ip);
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

    None
}

/// Retrieve global IPv6 address from standard Linux /proc/net/if_inet6
pub fn get_iface_ipv6(ifname: &str) -> Option<[u8; 16]> {
    let content = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    parse_proc_inet6(&content, ifname)
}

/// Pure parser function for /proc/net/if_inet6 lines (enables unit testing).
/// Filters out tentative (0x40, DAD in progress) and failed (0x08) addresses.
/// Prefers non-deprecated over deprecated (0x20) global addresses.
pub fn parse_proc_inet6(content: &str, target_ifname: &str) -> Option<[u8; 16]> {
    let mut fallback_deprecated = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let hex_addr = parts.next()?;
        let _ifindex = parts.next()?;
        let _plen = parts.next()?;
        let scope = parts.next()?;
        let flags_str = parts.next()?;
        let dev = parts.next()?;

        // scope 00 = global scope
        if dev == target_ifname && scope == "00" && hex_addr.len() == 32 {
            let flags = u8::from_str_radix(flags_str, 16).unwrap_or(0);
            // Skip IFA_F_TENTATIVE (0x40, DAD in progress) and IFA_F_DADFAILED (0x08)
            if (flags & 0x48) != 0 {
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
            if !valid {
                continue;
            }

            // Prefer non-deprecated (IFA_F_DEPRECATED = 0x20) address
            if (flags & 0x20) == 0 {
                return Some(bytes);
            } else if fallback_deprecated.is_none() {
                fallback_deprecated = Some(bytes);
            }
        }
    }
    fallback_deprecated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_inet6() {
        let sample = "\
00000000000000000000000000000001 01 80 10 80       lo
fe8000000000000002155dfffe123456 02 40 20 80     eth0
240e0123456789abcdef0123456789ac 03 40 00 40     eth1
240e0123456789abcdef0123456789ab 03 40 00 80     eth1
";
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
}
