use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub action: Action,
    pub proto: Proto,
    /// "any" or an ip/cidr — see `validate_src`. It is the *peer*'s address
    /// in both directions: matched as `ip saddr` in the input chain and as
    /// `ip daddr` in the output chain, so one rule means the same thing
    /// ("this host, this port") whichever way the connection is opened.
    pub src: String,
    pub port: Option<u16>,
    /// `None` = both directions, which is what every rule written before
    /// this field existed means. `Some(In)` is "someone reaching this
    /// machine", `Some(Out)` is "this machine reaching out" — the escape
    /// hatch for the asymmetric case ("let people ssh in, but no app here
    /// may ssh out").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub enabled: bool,
}

/// `src` goes verbatim into the nft ruleset (ruleset::rule_line), so it
/// must be exactly "any", an ip, or ip/prefix — nothing nft could read as
/// more than one address expression. Every way a Rule gets in (CLI, TUI,
/// import) checks this.
pub fn validate_src(src: &str) -> Result<(), String> {
    if src == "any" {
        return Ok(());
    }
    let (ip, prefix) = match src.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (src, None),
    };
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("bad source {src:?}: want any, an ip, or ip/prefix"))?;
    if let Some(p) = prefix {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        match p.parse::<u8>() {
            Ok(n) if n <= max => {}
            _ => return Err(format!("bad prefix in {src:?}: want /0../{max}")),
        }
    }
    Ok(())
}

/// does `name` (the peer name the DNS tap resolved, if any) fall under the
/// rule's host pattern? `*.example.com` deliberately covers the apex too —
/// "block this domain" means the whole domain, not everything but the bare
/// name. Comparison is case- and trailing-dot-insensitive, as DNS is.
/// A peer with no resolved name matches nothing: a host rule is a statement
/// about a named destination, and guessing on an unnamed one would silently
/// widen a deny into a block on unrelated traffic.
pub fn host_matches(pat: &str, name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let pat = pat.trim_end_matches('.').to_ascii_lowercase();
    match pat.strip_prefix("*.") {
        Some(apex) => name == apex || name.ends_with(&format!(".{apex}")),
        None => name == pat,
    }
}

/// a host pattern is only ever compared against a resolved name (never fed
/// to nft, unlike `Rule::src`), so this is a typo guard rather than an
/// injection one: a leading `*.` wildcard, then hostname characters only.
pub fn validate_host(pat: &str) -> Result<(), String> {
    let bare = pat.strip_prefix("*.").unwrap_or(pat).trim_end_matches('.');
    let bad = bare.is_empty()
        || bare.starts_with('.')
        || bare.contains("..")
        || !bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    if bad {
        return Err(format!(
            "bad host {pat:?}: want a hostname like example.com or *.example.com"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// A per-application rule: matched by canonical executable path, resolved at
/// connection time by the daemon (see src/daemon.rs) via /proc, and pinned
/// to the binary's size+mtime (`fingerprint`) so an updated or swapped
/// binary gets asked again instead of inheriting the rule.
///
/// `port: None` is a whole-app default (every port); `port: Some(p)` is a
/// per-port override that wins over the app's default when both exist for
/// the same app (see daemon's matching in queue_loop). The TUI's Apps pane
/// sets `None` (allow/deny everything); the Flow pane sets `Some(p)` for
/// just the port of the request being decided — they're deliberately
/// independent axes, not one overriding the other except port beats default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    pub id: u32,
    pub exe: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// `None` = both directions. `Some(Out)` is "this app reaching port P
    /// somewhere", `Some(In)` is "someone reaching this app's local port P"
    /// — same number, different meaning, so the daemon records the direction
    /// of the request it answered
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub action: Action,
    pub enabled: bool,
    /// unix epoch seconds after which this rule no longer matches (`guardit
    /// app allow --for 1h`); the daemon sweeps expired rules out of the file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// `fingerprint(exe)` at the time the rule was made. When the binary
    /// changes afterwards (update, or something replaced it) the daemon
    /// treats the rule as absent and asks again; `None` = never checked
    /// (hand-written rule). See `stale`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// `None` = any peer. `Some(pat)` restricts the rule to connections
    /// whose peer the daemon's DNS tap resolved to a name matching `pat`
    /// ("example.com" or "*.example.com" — see `host_matches`). A peer with
    /// no known name never matches such a rule, so it falls through to the
    /// app's less specific rules. Best-effort by construction: the tap only
    /// sees plain DNS, so DoH/DoT and cached lookups are invisible to it.
    /// ponytail: plain-DNS tap only, an app that resolves its own names
    /// bypasses host rules — needs an nftables-set-per-domain to close
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl AppRule {
    pub fn expired(&self, now: u64) -> bool {
        self.expires.is_some_and(|t| t <= now)
    }

    /// the binary this rule was made for is not the one on disk any more
    pub fn stale(&self) -> bool {
        self.fingerprint.is_some() && self.fingerprint != fingerprint(&self.exe)
    }
}

/// cheap identity of a binary: size and mtime. Catches package updates and
/// swapped binaries, not an attacker who forges both — a hash would cost a
/// full read of the exe per new connection.
/// ponytail: size:mtime, upgrade to a cached sha256 if forgery matters
pub fn fingerprint(exe: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(exe).ok()?;
    Some(format!("{}:{}", m.len(), m.mtime()))
}

pub fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// the one matching rule for (exe, port, direction, peer name): the most
/// specific rule wins — a host rule over a per-port rule over the app's
/// whole-app default (`port: None`), and within each a directional rule
/// over one that covers both. Host is the most specific axis on purpose:
/// "this app must not reach *that domain*" is a narrower claim than "this
/// app may use port 443", so it has to survive the broader allow.
/// Used by the daemon to verdict and by the TUI to show what would happen
/// right now; `host` is the name the DNS tap resolved for the peer, `None`
/// when it saw no lookup for it.
pub fn match_rule<'a>(
    rules: &'a [AppRule],
    exe: &str,
    port: Option<u16>,
    dir: Option<Direction>,
    host: Option<&str>,
) -> Option<&'a AppRule> {
    let now = now_ts();
    rules
        .iter()
        .filter(|r| r.enabled && r.exe == exe && !r.expired(now))
        .filter(|r| r.port.is_none() || r.port == port)
        .filter(|r| r.direction.is_none() || r.direction == dir)
        .filter(|r| r.host.as_deref().is_none_or(|pat| host_matches(pat, host)))
        .max_by_key(|r| (r.host.is_some(), r.port.is_some(), r.direction.is_some()))
}

fn default_pending_timeout() -> u32 {
    25
}

fn default_verdict() -> Action {
    Action::Deny
}

fn default_true() -> bool {
    true
}

fn default_update_hours() -> u32 {
    24
}

/// Ads / tracking blocking (see src/blocklist.rs). Off until someone turns
/// it on: it changes what every DNS lookup on the machine resolves to, which
/// is not something an install should start doing on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub enabled: bool,
    /// what to block, in blocklist::CATEGORIES terms — "ads", "phishing",
    /// "porn"… Each enables the lists it names; several at once is the
    /// normal case
    #[serde(default)]
    pub categories: Vec<String>,
    /// extra `id:level` keys from blocklist::SOURCES, on top of whatever the
    /// categories bring in — the escape hatch for a list no category picks
    #[serde(default)]
    pub sources: Vec<String>,
    /// names that are never blocked, whatever the lists say — an entry also
    /// rescues everything under it (blocklist::Blocklist::blocked)
    #[serde(default)]
    pub allow: Vec<String>,
    /// refuse DoT/DoQ and known DoH endpoints, so apps fall back to the
    /// plain DNS these lists can actually filter. Without it a browser doing
    /// its own DoH ignores blocking entirely — see the README
    #[serde(default = "default_true")]
    pub block_encrypted_dns: bool,
    /// refuse outbound HTTPS to an address no lookup was ever seen for.
    /// `block_encrypted_dns` closes the DoH endpoints we know about; this
    /// closes the ones we don't, because an app that resolved out of band
    /// has no other way to have learnt the address. Off by default: an app
    /// with a hardcoded ip is refused too, which is the point and also the
    /// risk — see the README
    #[serde(default)]
    pub require_resolved: bool,
    /// how often the daemon refetches the enabled lists; 0 = never
    #[serde(default = "default_update_hours")]
    pub update_hours: u32,
    /// see `Config::extra`
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        BlocklistConfig {
            enabled: false,
            categories: Vec::new(),
            sources: Vec::new(),
            allow: Vec::new(),
            block_encrypted_dns: true,
            require_resolved: false,
            update_hours: default_update_hours(),
            extra: toml::Table::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub rule: Vec<Rule>,
    #[serde(default)]
    pub app_rule: Vec<AppRule>,
    /// how long the daemon holds a packet open waiting for a TUI decision
    /// before falling back to `default_verdict`
    #[serde(default = "default_pending_timeout")]
    pub pending_timeout_secs: u32,
    #[serde(default = "default_verdict")]
    pub default_verdict: Action,
    /// send a desktop notification (`notify-send`) to every logged-in
    /// session when a new app asks — so you hear about it without the TUI
    /// open, and can answer with `guardit answer`
    #[serde(default = "default_true")]
    pub notify: bool,
    /// Also filter traffic that only passes through this machine —
    /// containers, bridged VMs. Off by default, and accept-by-default when
    /// on: there is no local process behind a forwarded packet, so per-app
    /// control cannot apply, and only the ip/port rules and the name-based
    /// blocking do. See `ruleset::forward_chain`
    #[serde(default)]
    pub filter_forwarded: bool,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    /// Settings this build does not know about, carried through untouched.
    ///
    /// Every write of this file is a read-modify-write, so without this a
    /// binary older than the file silently deletes whatever was added since
    /// — which is not hypothetical: a daemon left running across an upgrade
    /// erased a `categories` list it had never heard of, on its next
    /// unrelated write. Unknown keys now survive the round trip, so an
    /// update, a downgrade, or a stale daemon costs nothing.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rule: Vec::new(),
            app_rule: Vec::new(),
            pending_timeout_secs: default_pending_timeout(),
            default_verdict: default_verdict(),
            notify: true,
            filter_forwarded: false,
            blocklist: BlocklistConfig::default(),
            extra: toml::Table::new(),
        }
    }
}

/// fixed system-wide path: the daemon runs as root under systemd/cron and the
/// TUI/CLI run under sudo, so a `$HOME`-relative path would silently point
/// each of them at a different file depending on how sudo sets HOME
pub fn config_path() -> PathBuf {
    PathBuf::from("/etc/guardit/rules.toml")
}

impl Config {
    /// exits on a malformed file — for the CLI/TUI, where there is nothing
    /// sensible to do with a config that can't be read
    pub fn load() -> Self {
        Config::try_load().unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        })
    }

    /// missing file = defaults; malformed file = Err (the daemon's
    /// hot-reload keeps its current rules rather than dying on a typo)
    pub fn try_load() -> Result<Self, String> {
        let path = config_path();
        match fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("bad config {}: {e}", path.display())),
            Err(_) => Ok(Config::default()),
        }
    }

    pub fn save(&self) {
        let path = config_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).expect("create config dir");
        }
        let s = toml::to_string_pretty(self).expect("serialize config");
        fs::write(&path, s).expect("write config");
    }

    pub fn next_id(&self) -> u32 {
        self.rule.iter().map(|r| r.id).max().unwrap_or(0) + 1
    }

    pub fn next_app_id(&self) -> u32 {
        self.app_rule.iter().map(|r| r.id).max().unwrap_or(0) + 1
    }

    /// load -> mutate -> save, holding an exclusive flock on a sidecar
    /// `.lock` file for the whole round trip. The daemon (app_rule writes)
    /// and the TUI (rule writes) both go through this now, so a
    /// load-modify-save from one side can't clobber a concurrent write from
    /// the other — the previous "narrow the window" approach just did the
    /// same read-modify-write without any actual mutual exclusion.
    pub fn update(mutate: impl FnOnce(&mut Config)) -> Config {
        let path = config_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).expect("create config dir");
        }
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.with_extension("toml.lock"))
            .expect("open lock file");
        // released automatically when `lock_file` drops at the end of this fn
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(rc, 0, "flock failed: {}", std::io::Error::last_os_error());

        let mut cfg = Config::load();
        mutate(&mut cfg);
        cfg.save();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(exe: &str, port: Option<u16>, action: Action) -> AppRule {
        AppRule {
            id: 0,
            exe: exe.into(),
            port,
            direction: None,
            action,
            enabled: true,
            expires: None,
            fingerprint: None,
            host: None,
        }
    }

    /// the host-less case, which is what every test below this one is about
    fn match_rule<'a>(
        rules: &'a [AppRule],
        exe: &str,
        port: Option<u16>,
        dir: Option<Direction>,
    ) -> Option<&'a AppRule> {
        super::match_rule(rules, exe, port, dir, None)
    }

    fn act(r: Option<&AppRule>) -> Option<Action> {
        r.map(|r| r.action)
    }

    #[test]
    fn port_override_wins_over_whole_app_default_only_for_its_port() {
        let rules = vec![
            rule("/usr/bin/a", None, Action::Allow),
            rule("/usr/bin/a", Some(443), Action::Deny),
        ];
        assert_eq!(
            act(match_rule(&rules, "/usr/bin/a", Some(443), None)),
            Some(Action::Deny)
        );
        assert_eq!(
            act(match_rule(&rules, "/usr/bin/a", Some(80), None)),
            Some(Action::Allow),
            "other ports keep the app default"
        );
        assert_eq!(act(match_rule(&rules, "/usr/bin/b", Some(443), None)), None);
    }

    #[test]
    fn port_rule_alone_leaves_other_ports_unruled() {
        let rules = vec![rule("/usr/bin/a", Some(443), Action::Deny)];
        assert_eq!(
            act(match_rule(&rules, "/usr/bin/a", Some(53), None)),
            None,
            "denying one port must not deny the app"
        );
    }

    #[test]
    fn host_pattern_covers_subdomains_and_the_apex() {
        assert!(host_matches("*.foo.com", Some("a.foo.com")));
        assert!(host_matches("*.foo.com", Some("deep.a.foo.com")));
        assert!(host_matches("*.foo.com", Some("foo.com")), "apex included");
        assert!(host_matches("*.foo.com", Some("FOO.COM")), "case-insensitive");
        assert!(host_matches("*.foo.com", Some("foo.com.")), "trailing dot");
        assert!(!host_matches("*.foo.com", Some("evilfoo.com")));
        assert!(!host_matches("*.foo.com", Some("foo.com.evil.net")));
        assert!(!host_matches("foo.com", Some("a.foo.com")), "exact means exact");
        assert!(!host_matches("*.foo.com", None), "unresolved peer matches nothing");
    }

    #[test]
    fn host_rule_beats_port_rule_but_only_for_that_host() {
        let mut blocked = rule("/usr/bin/a", None, Action::Deny);
        blocked.host = Some("*.ads.net".into());
        let rules = vec![rule("/usr/bin/a", Some(443), Action::Allow), blocked];
        assert_eq!(
            act(super::match_rule(
                &rules,
                "/usr/bin/a",
                Some(443),
                None,
                Some("tracker.ads.net")
            )),
            Some(Action::Deny),
            "the host rule survives the broader port allow"
        );
        assert_eq!(
            act(super::match_rule(
                &rules,
                "/usr/bin/a",
                Some(443),
                None,
                Some("github.com")
            )),
            Some(Action::Allow)
        );
        assert_eq!(
            act(super::match_rule(&rules, "/usr/bin/a", Some(443), None, None)),
            Some(Action::Allow),
            "an unresolved peer falls through to the port rule"
        );
    }

    #[test]
    fn host_rule_alone_leaves_other_hosts_unruled() {
        let mut r = rule("/usr/bin/a", None, Action::Deny);
        r.host = Some("*.ads.net".into());
        assert_eq!(
            act(super::match_rule(
                &[r],
                "/usr/bin/a",
                Some(443),
                None,
                Some("github.com")
            )),
            None,
            "denying one domain must not deny the app"
        );
    }

    #[test]
    fn host_must_be_a_hostname_or_wildcard() {
        for ok in ["example.com", "*.example.com", "a-b_c.example.com", "localhost"] {
            assert!(validate_host(ok).is_ok(), "{ok}");
        }
        for bad in ["", "*.", "*", "ex ample.com", "a//b", "a..b", ".example.com", "http://x"] {
            assert!(validate_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_this_build_does_not_know_survive_a_rewrite() {
        // what a newer version might have written
        let newer = r#"
notify = true
some_future_setting = 7

[[rule]]
id = 1
action = "allow"
proto = "tcp"
src = "any"
port = 22
enabled = true

[blocklist]
enabled = true
categories = ["ads"]
some_future_blocklist_setting = "yes"
"#;
        let mut cfg: Config = toml::from_str(newer).expect("parses");
        // an older binary changes something it does understand
        cfg.notify = false;
        let out = toml::to_string_pretty(&cfg).expect("serializes");

        assert!(out.contains("some_future_setting"), "{out}");
        assert!(out.contains("some_future_blocklist_setting"), "{out}");
        assert!(out.contains("categories"), "{out}");
        assert!(out.contains("notify = false"), "{out}");
        // and what came back out is still a config, not just text that
        // happens to contain the right words
        let again: Config = toml::from_str(&out).expect("round trips");
        assert_eq!(again.rule.len(), 1);
        assert!(again.blocklist.enabled);
        assert!(!again.notify);
    }

    #[test]
    fn src_must_be_any_ip_or_cidr() {
        for ok in [
            "any",
            "10.0.0.1",
            "192.168.1.0/24",
            "fd00::1",
            "fd00::/64",
            "0.0.0.0/0",
        ] {
            assert!(validate_src(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "lan",
            "10.0.0.1/33",
            "fd00::/129",
            "1.2.3.4 accept",
            "1.2.3",
            "10.0.0.0/",
        ] {
            assert!(validate_src(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn expired_rule_does_not_match() {
        let mut r = rule("/usr/bin/a", None, Action::Allow);
        r.expires = Some(now_ts() - 1);
        assert_eq!(
            act(match_rule(&[r.clone()], "/usr/bin/a", Some(80), None)),
            None
        );
        r.expires = Some(now_ts() + 60);
        assert_eq!(
            act(match_rule(&[r], "/usr/bin/a", Some(80), None)),
            Some(Action::Allow)
        );
    }

    #[test]
    fn fingerprint_tracks_size_and_mtime() {
        let dir = std::env::temp_dir().join(format!("guardit-fp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("bin");
        fs::write(&exe, b"v1").unwrap();
        let mut r = rule(exe.to_str().unwrap(), None, Action::Allow);
        assert!(!r.stale(), "no fingerprint = never stale");
        r.fingerprint = fingerprint(&r.exe);
        assert!(!r.stale());
        fs::write(&exe, b"v2 longer").unwrap();
        assert!(r.stale(), "size changed");
        fs::remove_dir_all(&dir).unwrap();
        assert!(r.stale(), "gone binary is stale too");
    }

    #[test]
    fn directional_rule_beats_both_ways_rule_only_for_its_direction() {
        let mut out_only = rule("/usr/bin/a", Some(443), Action::Deny);
        out_only.direction = Some(Direction::Out);
        let rules = vec![rule("/usr/bin/a", Some(443), Action::Allow), out_only];
        assert_eq!(
            act(match_rule(
                &rules,
                "/usr/bin/a",
                Some(443),
                Some(Direction::Out)
            )),
            Some(Action::Deny)
        );
        assert_eq!(
            act(match_rule(
                &rules,
                "/usr/bin/a",
                Some(443),
                Some(Direction::In)
            )),
            Some(Action::Allow)
        );
        // whole-app directional loses to a per-port both-ways rule
        let mut app_in = rule("/usr/bin/a", None, Action::Deny);
        app_in.direction = Some(Direction::In);
        let rules = vec![rule("/usr/bin/a", Some(22), Action::Allow), app_in];
        assert_eq!(
            act(match_rule(
                &rules,
                "/usr/bin/a",
                Some(22),
                Some(Direction::In)
            )),
            Some(Action::Allow)
        );
    }
}
