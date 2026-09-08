use crate::config::{Action, Config, Proto, Rule};
use std::io::Write;
use std::process::{Command, Stdio};

const TABLE: &str = "guardit";
pub const LOG_PREFIX_IN: &str = "guardit-in: ";
pub const LOG_PREFIX_OUT: &str = "guardit-out: ";
/// NFQUEUE numbers the daemon (src/daemon.rs) binds for per-app enforcement.
/// Deliberately no `bypass` flag: without it, the kernel drops any new
/// connection that reaches the queue while no daemon is listening — fail
/// CLOSED, not open. This is the actual "100% of traffic is enforced"
/// guarantee: nothing can silently sail through just because the daemon
/// crashed or was never started. The real cost is real too — `guardit
/// apply` without a running `guardit daemon` kills all new connections
/// stone dead (IP/port `Rule`s above still get evaluated first and still
/// work; it's only the fallback to per-app matching that goes dark) —
/// install.sh keeps it supervised (systemd or cron) for exactly that reason.
pub const QUEUE_IN: u16 = 0;
pub const QUEUE_OUT: u16 = 1;

fn rule_line(r: &Rule) -> String {
    let mut parts = vec![];
    if r.src != "any" {
        let family = if r.src.contains(':') { "ip6" } else { "ip" };
        parts.push(format!("{family} saddr {}", r.src));
    }
    match r.proto {
        Proto::Tcp => parts.push("tcp".into()),
        Proto::Udp => parts.push("udp".into()),
        Proto::Any => {}
    }
    if let Some(port) = r.port {
        let proto = match r.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Any => "tcp", // port needs a proto; default tcp if unset
        };
        parts.retain(|p| p != "tcp" && p != "udp");
        parts.push(format!("{proto} dport {port}"));
    }
    let verdict = match r.action {
        Action::Allow => "accept",
        Action::Deny => "drop",
    };
    if parts.is_empty() {
        format!("    {verdict}")
    } else {
        format!("    {} {verdict}", parts.join(" "))
    }
}

/// Renders the config as an nft ruleset (plain nft syntax, not JSON —
/// simpler to read/debug than hand-building the -j schema).
pub fn render(cfg: &Config) -> String {
    let mut out = String::new();
    out.push_str(&format!("table inet {TABLE} {{\n"));
    out.push_str("  chain input {\n");
    out.push_str("    type filter hook input priority 0; policy drop;\n");
    out.push_str("    iif lo accept\n");
    out.push_str("    ct state established,related accept\n");
    for r in cfg.rule.iter().filter(|r| r.enabled) {
        out.push_str(&rule_line(r));
        out.push('\n');
    }
    // anything not already accepted/dropped by an IP/port rule above falls
    // through to the daemon for per-app matching
    out.push_str(&format!(
        "    ct state new log prefix \"{LOG_PREFIX_IN}\" queue num {QUEUE_IN}\n"
    ));
    out.push_str("  }\n");
    // outbound: used to be visibility-only (policy accept, never blocked) —
    // now every new outbound connection is queued to the daemon too, so
    // per-app rules can actually deny outgoing traffic
    out.push_str("  chain output {\n");
    out.push_str("    type filter hook output priority 0; policy accept;\n");
    out.push_str(&format!(
        "    ct state new log prefix \"{LOG_PREFIX_OUT}\" queue num {QUEUE_OUT}\n"
    ));
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

pub fn apply(cfg: &Config) -> Result<(), String> {
    let ruleset = render(cfg);
    // flush any previous guardit table so disabled/removed rules disappear
    let flush = format!("table inet {TABLE} {{ }}\ndelete table inet {TABLE}\n{ruleset}");
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nft failed: {e} (is nftables installed?)"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(flush.as_bytes())
        .map_err(|e| format!("write to nft stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "nft rejected ruleset: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

pub fn status() -> String {
    let out = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => format!("table inet {TABLE} not loaded in kernel (run `guardit apply`)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, Proto};

    fn rule(action: Action, proto: Proto, src: &str, port: Option<u16>) -> Rule {
        Rule {
            id: 1,
            action,
            proto,
            src: src.into(),
            port,
            enabled: true,
        }
    }

    #[test]
    fn allow_with_src_and_port() {
        let cfg = Config {
            rule: vec![rule(Action::Allow, Proto::Tcp, "192.168.1.0/24", Some(22))],
            ..Config::default()
        };
        let out = render(&cfg);
        assert!(out.contains("ip saddr 192.168.1.0/24 tcp dport 22 accept"));
    }

    #[test]
    fn deny_any_any_drops_everything() {
        let cfg = Config {
            rule: vec![rule(Action::Deny, Proto::Any, "any", None)],
            ..Config::default()
        };
        let out = render(&cfg);
        assert!(out.contains("drop"));
        assert!(!out.contains("saddr"));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let mut r = rule(Action::Allow, Proto::Any, "any", None);
        r.enabled = false;
        let cfg = Config {
            rule: vec![r],
            ..Config::default()
        };
        let out = render(&cfg);
        let input_chain = out.split("chain output").next().unwrap();
        // only the fixed lo/established lines should mention accept
        assert_eq!(input_chain.matches("accept").count(), 2);
    }

    #[test]
    fn ipv6_src_uses_ip6_saddr() {
        let cfg = Config {
            rule: vec![rule(Action::Allow, Proto::Tcp, "fd00::1/64", Some(22))],
            ..Config::default()
        };
        let out = render(&cfg);
        assert!(out.contains("ip6 saddr fd00::1/64 tcp dport 22 accept"));
    }

    #[test]
    fn queue_line_present_in_both_chains_without_bypass() {
        // no `bypass`: a dead/missing daemon must fail closed (drop), not open
        let cfg = Config {
            rule: vec![],
            ..Config::default()
        };
        let out = render(&cfg);
        assert!(out.contains(&format!("queue num {QUEUE_IN}\n")));
        assert!(out.contains(&format!("queue num {QUEUE_OUT}\n")));
        assert!(!out.contains("bypass"));
    }

    #[test]
    fn queue_line_comes_after_ip_rules_in_input_chain() {
        let cfg = Config {
            rule: vec![rule(Action::Deny, Proto::Tcp, "1.2.3.4", None)],
            ..Config::default()
        };
        let out = render(&cfg);
        let input_chain = out.split("chain output").next().unwrap();
        let rule_pos = input_chain.find("1.2.3.4 tcp drop").unwrap();
        let queue_pos = input_chain.find("queue num").unwrap();
        assert!(
            rule_pos < queue_pos,
            "ip rule must be evaluated before the queue fallback"
        );
    }

    #[test]
    fn port_without_explicit_proto_defaults_tcp() {
        let cfg = Config {
            rule: vec![rule(Action::Allow, Proto::Any, "any", Some(443))],
            ..Config::default()
        };
        let out = render(&cfg);
        assert!(out.contains("tcp dport 443 accept"));
    }
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
