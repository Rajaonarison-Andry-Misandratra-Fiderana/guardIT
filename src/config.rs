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
    /// "any" or an ip/cidr
    pub src: String,
    pub port: Option<u16>,
    pub enabled: bool,
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
/// connection time by the daemon (see src/daemon.rs) via /proc — no notion
/// of app identity beyond that (no hash/signature; breaks on binary updates).
///
/// `port: None` is a whole-app default (every port); `port: Some(p)` is a
/// per-port override that wins over the app's default when both exist for
/// the same app (see daemon's matching in queue_loop). The TUI's Apps pane
/// sets `None` (allow/deny everything); the Flow pane sets `Some(p)` for
/// just the port of the request being decided — they're deliberately
/// independent axes, not one overriding the other except port beats default.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// the one matching rule for (exe, port, direction): the most specific rule
/// wins — a per-port rule over the app's whole-app default (`port: None`),
/// and within that a directional rule over one that covers both. Used by
/// the daemon to verdict and by the TUI to show what would happen right now
pub fn match_rule<'a>(
    rules: &'a [AppRule],
    exe: &str,
    port: Option<u16>,
    dir: Option<Direction>,
) -> Option<&'a AppRule> {
    rules
        .iter()
        .filter(|r| r.enabled && r.exe == exe)
        .filter(|r| r.port.is_none() || r.port == port)
        .filter(|r| r.direction.is_none() || r.direction == dir)
        .max_by_key(|r| (r.port.is_some(), r.direction.is_some()))
}

fn default_pending_timeout() -> u32 {
    25
}

fn default_verdict() -> Action {
    Action::Deny
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rule: Vec::new(),
            app_rule: Vec::new(),
            pending_timeout_secs: default_pending_timeout(),
            default_verdict: default_verdict(),
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
    pub fn load() -> Self {
        let path = config_path();
        match fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).unwrap_or_else(|e| {
                eprintln!("bad config {}: {e}", path.display());
                std::process::exit(1);
            }),
            Err(_) => Config::default(),
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
        }
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
