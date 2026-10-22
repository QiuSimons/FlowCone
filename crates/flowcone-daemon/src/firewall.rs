use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

const FW4_USER_PATH: &str = "/etc/firewall4.user";
const FLOWCONE_TAG_START: &str = "# --- flowcone start ---";
const FLOWCONE_TAG_END: &str = "# --- flowcone end ---";

pub fn generate_fw4_user_block(min_port: u16, max_port: u16) -> String {
    format!(
        "{}\n\
         nft insert rule inet fw4 srcnat meta l4proto udp udp sport {min_port}-{max_port} counter return comment \"flowcone\" 2>/dev/null || true\n\
         nft insert rule inet fw4 forward meta mark 0x4643 counter accept comment \"flowcone\" 2>/dev/null || true\n\
         {}\n",
        FLOWCONE_TAG_START, FLOWCONE_TAG_END
    )
}

pub fn generate_standalone_script(min_port: u16, max_port: u16) -> String {
    format!(
        "table inet flowcone {{\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter - 1; policy accept;\n\
         \x20       meta mark 0x4643 counter accept\n\
         \x20   }}\n\
         \x20   chain srcnat {{\n\
         \x20       type nat hook postrouting priority srcnat - 1; policy accept;\n\
         \x20       meta l4proto udp udp sport {min_port}-{max_port} counter return\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Check if OpenWrt's `table inet fw4` exists in the system
pub fn has_table_inet_fw4() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "fw4"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Parse nftables rules text to detect if IPv6 masquerade is enabled
pub fn parse_has_ipv6_masq(nft_output: &str) -> bool {
    for line in nft_output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("masquerade")
            && (trimmed.contains("nfproto ipv6")
                || trimmed.contains("meta nfproto 10")
                || trimmed.contains("ip6")
                || trimmed.contains("ipv6"))
            && !trimmed.contains("nfproto ipv4")
        {
            return true;
        }
    }
    false
}

/// Check if system nftables (inet fw4) has IPv6 masquerade enabled
pub fn is_ipv6_masq_enabled() -> bool {
    if let Ok(out) = Command::new("nft")
        .args(["list", "table", "inet", "fw4"])
        .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        return parse_has_ipv6_masq(&text);
    }
    false
}

/// Parse nftables chain output with handles and return handles matching flowcone rules
pub fn find_rule_handles_to_delete(chain_output: &str, is_srcnat: bool) -> Vec<u64> {
    let mut handles = Vec::new();
    for line in chain_output.lines() {
        let trimmed = line.trim();
        let matches = if is_srcnat {
            trimmed.contains("comment \"flowcone\"")
                || (trimmed.contains("udp sport")
                    && trimmed.contains("counter")
                    && trimmed.contains("return"))
        } else {
            trimmed.contains("comment \"flowcone\"")
                || trimmed.contains("0x4643")
                || trimmed.contains("0x00004643")
        };
        if matches && let Some(idx) = trimmed.rfind("# handle ") {
            let handle_str = &trimmed[idx + "# handle ".len()..];
            if let Ok(h) = handle_str.trim().parse::<u64>() {
                handles.push(h);
            }
        }
    }
    handles
}

/// Delete injected flowcone rules from inet fw4 chains (srcnat & forward)
pub fn delete_injected_fw4_rules(verbose: bool) {
    for &(chain, is_srcnat) in &[("srcnat", true), ("forward", false)] {
        if let Ok(out) = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "fw4", chain])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let handles = find_rule_handles_to_delete(&text, is_srcnat);
            for h in handles {
                let _ = Command::new("nft")
                    .args([
                        "delete",
                        "rule",
                        "inet",
                        "fw4",
                        chain,
                        "handle",
                        &h.to_string(),
                    ])
                    .output();
                if verbose {
                    println!(
                        "flowcone: removed rule from inet fw4 {} (handle {})",
                        chain, h
                    );
                }
            }
        }
    }
}

pub fn strip_fw4_user_block(content: &str) -> String {
    let mut result = content.to_string();
    while let (Some(start), Some(end)) = (
        result.find(FLOWCONE_TAG_START),
        result.find(FLOWCONE_TAG_END),
    ) {
        if start < end {
            let before = &result[..start];
            let after = &result[end + FLOWCONE_TAG_END.len()..];
            result = format!("{}{}", before.trim_end(), after);
        } else {
            break;
        }
    }
    result
}

pub fn update_firewall4_user_file(min_port: u16, max_port: u16) {
    let block = generate_fw4_user_block(min_port, max_port);
    let current = fs::read_to_string(FW4_USER_PATH).unwrap_or_default();
    let stripped = strip_fw4_user_block(&current);

    let updated = if stripped.trim().is_empty() {
        format!("#!/bin/sh\n{}", block)
    } else {
        format!("{}\n\n{}", stripped.trim_end(), block)
    };

    let _ = fs::write(FW4_USER_PATH, updated);
}

pub fn clean_firewall4_user_file() {
    if let Ok(current) = fs::read_to_string(FW4_USER_PATH) {
        let cleaned = strip_fw4_user_block(&current);
        let _ = fs::write(FW4_USER_PATH, cleaned.trim());
    }
}

pub fn apply_rules(min_port: u16, max_port: u16, verbose: bool) {
    let is_fw4 = has_table_inet_fw4();

    if is_fw4 {
        // 1. Purge any stale/duplicate rules before inserting to guarantee clean state
        delete_injected_fw4_rules(verbose);

        // 2. Hot-insert into active fw4 table (srcnat bypass & forward accept) with comment "flowcone"
        let _ = Command::new("nft")
            .args([
                "insert",
                "rule",
                "inet",
                "fw4",
                "srcnat",
                "meta",
                "l4proto",
                "udp",
                "udp",
                "sport",
                &format!("{}-{}", min_port, max_port),
                "counter",
                "return",
                "comment",
                "flowcone",
            ])
            .output();

        let _ = Command::new("nft")
            .args([
                "insert", "rule", "inet", "fw4", "forward", "meta", "mark", "0x4643", "counter",
                "accept", "comment", "flowcone",
            ])
            .output();

        // 3. Persist in /etc/firewall4.user for automatic fw4 reload immunity
        update_firewall4_user_file(min_port, max_port);
        if verbose {
            println!(
                "flowcone: registered persistent reload hook in {}",
                FW4_USER_PATH
            );
        }

        if verbose {
            println!(
                "flowcone: integrated with inet fw4 (ports {}-{} bypassed from masquerade, mark 0x4643 forwarded)",
                min_port, max_port
            );
        }
    } else {
        // Fallback for standalone Linux environments (non-OpenWrt)
        let script = generate_standalone_script(min_port, max_port);
        let child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .spawn();

        if let Ok(mut c) = child {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            let _ = c.wait();
            if verbose {
                println!(
                    "flowcone: applied standalone nftables rules (table inet flowcone, ports {}-{})",
                    min_port, max_port
                );
            }
        }
    }
}

pub fn remove_rules(verbose: bool) {
    // 1. Clean persistent hook in /etc/firewall4.user
    clean_firewall4_user_file();

    // 2. Clean in-memory injected rules from table inet fw4
    if has_table_inet_fw4() {
        delete_injected_fw4_rules(verbose);
    }

    // 3. Clean standalone table if created
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "flowcone"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();

    if verbose {
        println!("flowcone: cleaned firewall rules");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rules_script() {
        let script = generate_standalone_script(1024, 65535);
        assert!(script.contains("table inet flowcone"));
        assert!(script.contains("priority filter - 1"));
        assert!(script.contains("priority srcnat - 1"));
        assert!(script.contains("meta mark 0x4643 counter accept"));
        assert!(script.contains("sport 1024-65535 counter return"));
    }

    #[test]
    fn test_generate_fw4_user_block() {
        let inc = generate_fw4_user_block(1024, 65535);
        assert!(inc.contains(FLOWCONE_TAG_START));
        assert!(
            inc.contains(
                "meta l4proto udp udp sport 1024-65535 counter return comment \"flowcone\""
            )
        );
        assert!(inc.contains("meta mark 0x4643 counter accept comment \"flowcone\""));
        assert!(inc.contains(FLOWCONE_TAG_END));
    }

    #[test]
    fn test_find_rule_handles_to_delete() {
        let sample_srcnat = "\
table inet fw4 {
        chain srcnat { # handle 19
                type nat hook postrouting priority srcnat; policy accept;
                udp sport 1024-65535 counter packets 0 bytes 0 return comment \"flowcone\" # handle 96
                udp sport 1024-65535 counter packets 2 bytes 508 return # handle 94
                oifname \"eth1\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\" # handle 86
                jump upnp_postrouting comment \"Hook into miniupnpd postrouting chain\" # handle 87
        }
}";
        let handles = find_rule_handles_to_delete(sample_srcnat, true);
        assert_eq!(handles, vec![96, 94]);

        let sample_forward = "\
table inet fw4 {
        chain forward { # handle 2
                type filter hook forward priority filter; policy drop;
                meta mark 0x00004643 counter packets 0 bytes 0 accept comment \"flowcone\" # handle 95
                meta l4proto { tcp, udp } flow add @ft # handle 38
        }
}";
        let handles_fwd = find_rule_handles_to_delete(sample_forward, false);
        assert_eq!(handles_fwd, vec![95]);
    }

    #[test]
    fn test_parse_has_ipv6_masq() {
        let v4_only = "\
table inet fw4 {
        chain srcnat_wan {
                meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"
        }
}";
        assert!(!parse_has_ipv6_masq(v4_only));

        let v6_masq = "\
table inet fw4 {
        chain srcnat_wan {
                meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"
                meta nfproto ipv6 masquerade comment \"!fw4: Masquerade IPv6 wan traffic\"
        }
}";
        assert!(parse_has_ipv6_masq(v6_masq));
    }

    #[test]
    fn test_strip_fw4_user_block() {
        let original = "#!/bin/sh\n# custom rule\n# --- flowcone start ---\ninjected\n# --- flowcone end ---\n# footer\n";
        let stripped = strip_fw4_user_block(original);
        assert_eq!(stripped, "#!/bin/sh\n# custom rule\n# footer\n");

        let no_block = "#!/bin/sh\necho hi\n";
        assert_eq!(strip_fw4_user_block(no_block), no_block);
    }
}
