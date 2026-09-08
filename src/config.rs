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
    Both,
}

impl Direction {
    /// does a rule set for `self` apply to traffic actually flowing in `dir`?
    pub fn covers(self, dir: Direction) -> bool {
        self == Direction::Both || self == dir
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
    pub direction: Direction,
    #[serde(default)]
    pub port: Option<u16>,
    pub action: Action,
    pub enabled: bool,
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

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/guardit/rules.toml")
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        match fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).unwrap_or_else(|e| panic!("bad config {}: {e}", path.display())),
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
        let lock_file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(path.with_extension("toml.lock")).expect("open lock file");
        // released automatically when `lock_file` drops at the end of this fn
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(rc, 0, "flock failed: {}", std::io::Error::last_os_error());

        let mut cfg = Config::load();
        mutate(&mut cfg);
        cfg.save();
        cfg
    }
}
