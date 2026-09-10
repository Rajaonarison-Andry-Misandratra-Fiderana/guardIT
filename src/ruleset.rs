use crate::blocklist;
use crate::config::{Action, Config, Direction, Proto, Rule};
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
/// DNS replies, for IP -> name display only (daemon::dns_loop). This one
/// DOES bypass: it decides nothing, so a stopped daemon must not stall
/// name resolution on top of everything else it already blocks.
pub const QUEUE_DNS: u16 = 2;
/// Forwarded traffic — containers, bridged VMs — when `filter_forwarded` is
/// on. This one DOES bypass, and the chain's policy is accept: there is no
/// local process behind a forwarded packet, so per-app control cannot mean
/// anything here, and a default-drop forward chain would take down every
/// container runtime on the machine the first time the daemon hiccuped.
pub const QUEUE_FWD: u16 = 3;

/// One nft line for one `Rule`, as seen from `dir`.
///
/// `Rule::src` is the peer, so which nft keyword it becomes depends on the
/// chain: the peer is the source of an inbound packet and the destination of
/// an outbound one. `port` is the destination port either way — the service
/// being reached, which is the only port worth writing a rule about (see
/// `queue_loop`'s `rule_port`).
/// the enabled rules that have anything to say about `dir` — a rule with no
/// direction of its own applies to both, which is what every rule written
/// before `Rule::direction` existed means
fn rules_for(cfg: &Config, dir: Direction) -> impl Iterator<Item = &Rule> {
    cfg.rule
        .iter()
        .filter(move |r| r.enabled && r.direction.is_none_or(|d| d == dir))
}

fn rule_line(r: &Rule, dir: Direction) -> String {
    let mut parts = vec![];
    if r.src != "any" {
        let family = if r.src.contains(':') { "ip6" } else { "ip" };
        let side = match dir {
            Direction::In => "saddr",
            Direction::Out => "daddr",
        };
        parts.push(format!("{family} {side} {}", r.src));
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

/// The nft half of `blocklist.block_encrypted_dns`: shut the doors an app
/// can use to resolve names the daemon's DNS tap will never see.
///
/// Names are handled elsewhere (blocklist::DOH_BOOTSTRAP and the `hagezi:doh`
/// list, both blocked at the DNS layer). This covers the case name blocking
/// structurally cannot: a client with the resolver's address compiled in,
/// which never asks a question anyone can filter.
///
/// This half is the table-level set definitions; `encrypted_dns_chain` emits
/// the rules that use them. nft wants the two in those two places.
fn encrypted_dns_sets(out: &mut String) {
    for (family, set, addrs) in doh_sets() {
        let elements = addrs
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "  set {set} {{ type {family}; elements = {{ {elements} }} }}\n"
        ));
    }
}

/// the cached DoH addresses split by family, skipping an empty family — nft
/// rejects a set declared with no element type in use
fn doh_sets() -> Vec<(&'static str, &'static str, Vec<std::net::IpAddr>)> {
    let ips = blocklist::doh_ips();
    let (v4, v6): (Vec<_>, Vec<_>) = ips.into_iter().partition(|ip| ip.is_ipv4());
    [("ipv4_addr", "doh4", v4), ("ipv6_addr", "doh6", v6)]
        .into_iter()
        .filter(|(_, _, a)| !a.is_empty())
        .collect()
}

/// Output-chain rules for the same thing.
///
/// `reject` rather than `drop` on purpose. A dropped packet leaves the client
/// retrying until its own timeout, which reads to the user as a hang; a
/// refused one makes it fall back to plain DNS immediately, which is exactly
/// where these lists can act. Only ports 853 (DoT/DoQ) and 443 to a known
/// DoH address (DoH, and DoH3 over QUIC) are touched, so a resolver ip that
/// also serves a website stays reachable for everything else.
fn encrypted_dns_chain(out: &mut String) {
    out.push_str("    tcp dport 853 reject with tcp reset\n");
    out.push_str("    udp dport 853 reject\n");
    for (_, set, _) in doh_sets() {
        let family = if set == "doh4" { "ip" } else { "ip6" };
        out.push_str(&format!(
            "    {family} daddr @{set} tcp dport 443 reject with tcp reset\n"
        ));
        out.push_str(&format!("    {family} daddr @{set} udp dport 443 reject\n"));
    }
}

/// Renders the config as an nft ruleset (plain nft syntax, not JSON —
/// simpler to read/debug than hand-building the -j schema).
pub fn render(cfg: &Config) -> String {
    let block_dns = cfg.blocklist.enabled && cfg.blocklist.block_encrypted_dns;
    let mut out = String::new();
    out.push_str(&format!("table inet {TABLE} {{\n"));
    if block_dns {
        encrypted_dns_sets(&mut out);
    }
    out.push_str("  chain input {\n");
    out.push_str("    type filter hook input priority 0; policy drop;\n");
    // before `iif lo`: a local resolver's replies to apps come over lo
    out.push_str(&format!("    udp sport 53 queue num {QUEUE_DNS} bypass\n"));
    // tcp too: a truncated answer is retried over tcp, and filtering only udp
    // left that retry as a way past the lists
    out.push_str(&format!("    tcp sport 53 queue num {QUEUE_DNS} bypass\n"));
    out.push_str("    iif lo accept\n");
    out.push_str("    ct state established,related accept\n");
    for r in rules_for(cfg, Direction::In) {
        out.push_str(&rule_line(r, Direction::In));
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
    // before the queue: an encrypted-dns attempt is refused outright rather
    // than held open waiting for a per-app decision nobody wants to make
    if block_dns {
        encrypted_dns_chain(&mut out);
    }
    // the same ip/port rules as the input chain, matched on the peer as a
    // destination. Without these, an ip/port rule was inbound-only while
    // every outbound connection went to the daemon — so "deny 1.2.3.4" did
    // not stop anything here from reaching 1.2.3.4, and no rule could
    // short-circuit the per-app queue on the way out.
    for r in rules_for(cfg, Direction::Out) {
        out.push_str(&rule_line(r, Direction::Out));
        out.push('\n');
    }
    // queries, not just the replies the input chain taps: a blocked name is
    // answered from here, so the question never leaves the machine
    out.push_str(&format!("    udp dport 53 queue num {QUEUE_DNS} bypass\n"));
    out.push_str(&format!(
        "    ct state new log prefix \"{LOG_PREFIX_OUT}\" queue num {QUEUE_OUT}\n"
    ));
    out.push_str("  }\n");
    if cfg.filter_forwarded {
        forward_chain(&mut out, cfg, block_dns);
    }
    out.push_str("}\n");
    out
}

/// What guardit can say about traffic that is only passing through.
///
/// Not per-app: a forwarded packet has no local process to attribute it to,
/// which is not a gap to be closed but a fact about routing. What it can
/// carry is everything that is about addresses and names — the ip/port
/// rules, the encrypted-dns refusals, and the blocklists via the DNS tap,
/// which sees a container's lookups the same way it sees anything else.
///
/// Accept by default, and the queue bypasses. A container runtime that
/// stops working because the firewall daemon restarted would be a far worse
/// bargain than the filtering is worth.
fn forward_chain(out: &mut String, cfg: &Config, block_dns: bool) {
    out.push_str("  chain forward {\n");
    out.push_str("    type filter hook forward priority 0; policy accept;\n");
    out.push_str(&format!("    udp sport 53 queue num {QUEUE_DNS} bypass\n"));
    out.push_str(&format!("    tcp sport 53 queue num {QUEUE_DNS} bypass\n"));
    out.push_str(&format!("    udp dport 53 queue num {QUEUE_DNS} bypass\n"));
    if block_dns {
        encrypted_dns_chain(out);
    }
    // both sides here: a forwarded flow passes through this chain in both
    // directions, so "deny 1.2.3.4" has to mean "no traffic with 1.2.3.4",
    // not just "none from it"
    for dir in [Direction::In, Direction::Out] {
        for r in rules_for(cfg, dir) {
            out.push_str(&rule_line(r, dir));
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "    ct state new queue num {QUEUE_FWD} bypass\n"
    ));
    out.push_str("  }\n");
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

/// Is guardit's table actually in the kernel right now?
///
/// nftables keeps nothing across a reboot, and any privileged thing on the
/// machine — another firewall front-end, a container runtime, a hand-typed
/// `nft flush ruleset` — can take the table out from under a running daemon.
/// The daemon would go on holding its queues while no rule sent anything to
/// them, which is not a failure anybody would notice: traffic simply stops
/// being controlled.
pub fn is_loaded() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .is_ok_and(|o| o.status.success())
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

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, Proto};

    fn rule(action: Action, proto: Proto, src: &str, port: Option<u16>) -> Rule {
        Rule {
            direction: None,
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
    fn forwarded_traffic_is_untouched_unless_asked_for_and_never_fails_closed() {
        let mut cfg = Config::default();
        cfg.rule.push(Rule {
            id: 1,
            action: Action::Deny,
            proto: Proto::Tcp,
            src: "any".into(),
            port: Some(23),
            direction: None,
            enabled: true,
        });
        assert!(
            !render(&cfg).contains("hook forward"),
            "off by default — a forward chain nobody asked for can only break things"
        );

        cfg.filter_forwarded = true;
        let out = render(&cfg);
        let chain = out.split("chain forward").nth(1).unwrap();
        assert!(chain.contains("policy accept;"), "must never default-drop");
        assert!(
            chain.contains(&format!("queue num {QUEUE_FWD} bypass")),
            "must bypass: a restarting daemon cannot be allowed to cut container networking"
        );
        assert!(chain.contains("tcp dport 23 drop"), "the ip rules apply here too");
        // the tap, so a container's own lookups feed the same name map
        assert!(chain.contains(&format!("udp sport 53 queue num {QUEUE_DNS} bypass")));
        assert!(chain.contains(&format!("udp dport 53 queue num {QUEUE_DNS} bypass")));
    }

    #[test]
    fn encrypted_dns_is_only_refused_when_asked_for() {
        let mut cfg = Config::default();
        assert!(
            !render(&cfg).contains("853"),
            "off by default, like the whole blocklist"
        );

        cfg.blocklist.enabled = true;
        cfg.blocklist.block_encrypted_dns = true;
        let out = render(&cfg);
        assert!(out.contains("tcp dport 853 reject with tcp reset\n"));
        assert!(out.contains("udp dport 853 reject\n"));
        // refused, never dropped: a dropped packet hangs the client until its
        // own timeout instead of falling back to the dns we can filter
        let chain = out.split("chain output").nth(1).unwrap();
        assert!(!chain.contains("853 drop"));

        cfg.blocklist.block_encrypted_dns = false;
        assert!(!render(&cfg).contains("853"));
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
        for line in out.lines().filter(|l| l.contains("bypass")) {
            assert!(
                line.contains("sport 53") || line.contains("dport 53"),
                "unexpected bypass: {line}"
            );
        }
        assert!(out.contains(&format!("queue num {QUEUE_OUT}\n")));
        assert_eq!(
            out.matches("bypass").count(),
            3,
            "only the DNS tap bypasses — replies over udp and tcp, and queries"
        );
        assert!(out.contains(&format!("udp sport 53 queue num {QUEUE_DNS} bypass\n")));
        let dns = out.find("sport 53").unwrap();
        let lo = out.find("iif lo accept").unwrap();
        assert!(dns < lo, "DNS tap must see local-resolver replies on lo");
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
        let queue_pos = input_chain.find(&format!("queue num {QUEUE_IN}")).unwrap();
        assert!(
            rule_pos < queue_pos,
            "ip rule must be evaluated before the queue fallback"
        );
    }

    /// what the TUI's "Allow everything (pause filtering)" preset renders to.
    /// A bare `accept` with no match expression, above the queue lines in
    /// both chains — if it ever rendered as `any accept` or landed below the
    /// queue, the preset would look like an off switch and not be one.
    #[test]
    fn an_unqualified_allow_short_circuits_both_chains_before_the_queue() {
        let cfg = Config {
            rule: vec![rule(Action::Allow, Proto::Any, "any", None)],
            ..Config::default()
        };
        let out = render(&cfg);
        let (input_chain, output_chain) = out.split_once("chain output").unwrap();
        for (name, chain, queue) in [
            ("input", input_chain, QUEUE_IN),
            ("output", output_chain, QUEUE_OUT),
        ] {
            let accept = chain
                .find("\n    accept\n")
                .unwrap_or_else(|| panic!("{name} chain has no unqualified accept:\n{chain}"));
            let queue_pos = chain.find(&format!("queue num {queue}")).unwrap();
            assert!(accept < queue_pos, "{name}: accept must precede the queue");
        }
    }

    /// `Rule::src` is the peer, so the nft keyword has to flip per chain —
    /// `ip saddr` inbound, `ip daddr` outbound. Rendering `saddr` in the
    /// output chain would match this machine's own address and so match
    /// nothing anyone meant.
    #[test]
    fn the_peer_is_a_source_inbound_and_a_destination_outbound() {
        let cfg = Config {
            rule: vec![rule(Action::Deny, Proto::Tcp, "1.2.3.4", Some(25))],
            ..Config::default()
        };
        let out = render(&cfg);
        let (input_chain, output_chain) = out.split_once("chain output").unwrap();
        assert!(input_chain.contains("ip saddr 1.2.3.4 tcp dport 25 drop"));
        assert!(output_chain.contains("ip daddr 1.2.3.4 tcp dport 25 drop"));
    }

    #[test]
    fn a_directional_rule_only_renders_into_its_own_chain() {
        for (dir, mine, theirs) in [
            (Direction::In, "chain input", "chain output"),
            (Direction::Out, "chain output", "chain input"),
        ] {
            let mut r = rule(Action::Allow, Proto::Tcp, "any", Some(22));
            r.direction = Some(dir);
            let out = render(&Config {
                rule: vec![r],
                ..Config::default()
            });
            // the chains are emitted input-then-output, so slice on whichever
            // marker starts the half we care about
            let hit = |marker: &str| {
                let rest = &out[out.find(marker).unwrap() + marker.len()..];
                let end = rest.find("  chain ").unwrap_or(rest.len());
                rest[..end].contains("tcp dport 22 accept")
            };
            assert!(hit(mine), "{dir:?} rule missing from {mine}");
            assert!(!hit(theirs), "{dir:?} rule leaked into {theirs}");
        }
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
