use crate::config::{Action, AppRule, Direction};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::PathBuf;

pub fn socket_path() -> PathBuf {
    PathBuf::from("/run/guardit/ipc.sock")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    Pending,
    Allowed,
    Denied,
}

impl From<Action> for FlowStatus {
    fn from(a: Action) -> Self {
        match a {
            Action::Allow => FlowStatus::Allowed,
            Action::Deny => FlowStatus::Denied,
        }
    }
}

/// one connection attempt: either still awaiting a decision (`req_id: Some`,
/// `status: Pending`) or already verdicted — either because it matched an
/// existing AppRule immediately (`req_id: None`) or because a pending one
/// got decided/timed out (`req_id: Some`, `status` updated in place via
/// `ServerMsg::FlowResolved`). The daemon keeps a capped history of these
/// (see daemon::HISTORY_CAP) so a TUI that reconnects still sees what an
/// app has been doing, not just requests still awaiting a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowWire {
    pub req_id: Option<u32>,
    pub exe: String,
    pub direction: Direction,
    pub proto: String,
    pub port: Option<u16>,
    pub peer_ip: String,
    pub status: FlowStatus,
    /// unix epoch seconds when this was logged — `#[serde(default)]` so
    /// history.jsonl lines written before this field existed still parse
    #[serde(default)]
    pub ts: u64,
}

/// one currently-LISTENing (or, for UDP, bound-and-receiving) local socket —
/// "who owns this port right now", the actual answer to a real port
/// conflict question. `addr` is "0.0.0.0"/"::" for a wildcard bind or a
/// specific address; see daemon::addrs_overlap for the conflict rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenEntry {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub exe: String,
}

/// daemon -> tui
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
    /// sent once right after a client connects
    Snapshot {
        app_rules: Vec<AppRule>,
        flow: Vec<FlowWire>,
        listening: Vec<ListenEntry>,
    },
    /// a new row to append (a fresh ask, or an already-verdicted matched connection)
    FlowNew(FlowWire),
    /// an existing pending row (by req_id) got its final status
    FlowResolved {
        req_id: u32,
        status: FlowStatus,
    },
    AppRules(Vec<AppRule>),
    /// full replace — pushed whenever a periodic rescan sees the set of
    /// listening sockets change (see daemon::LISTEN_SCAN_INTERVAL)
    Listening(Vec<ListenEntry>),
}

/// tui -> daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMsg {
    /// verdict a held packet — always also persisted as a per-port rule for
    /// that app (there is no one-off decision: every answer is remembered)
    Decide {
        req_id: u32,
        verdict: Action,
    },
    /// set (creating if needed) a rule for `exe` — `port: None` is the
    /// whole-app default (Apps/Conflicts panes), `port: Some(p)` is a
    /// per-port override (Flow pane) that wins over the default; `direction:
    /// None` covers both ways, see daemon::upsert_rule and config::match_rule
    SetAppRule {
        exe: String,
        port: Option<u16>,
        #[serde(default)]
        direction: Option<Direction>,
        action: Action,
    },
    ToggleAppRule {
        id: u32,
    },
    /// removes every rule for `exe` — the whole-app default AND every
    /// per-port override, i.e. "forget this app" rather than "remove one rule"
    RmAppRule {
        exe: String,
    },
}

/// writes one JSON value terminated by '\n' — the wire is line-delimited so
/// both ends can use a plain BufRead::read_line loop, no framing needed for
/// a single trusted local client
pub fn send_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> std::io::Result<()> {
    let mut line = serde_json::to_string(msg)?;
    line.push('\n');
    w.write_all(line.as_bytes())
}

/// reads one line and parses it; Ok(None) means the peer closed the connection
pub fn read_msg<T: for<'de> Deserialize<'de>>(r: &mut impl BufRead) -> std::io::Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let msg = serde_json::from_str(line.trim_end())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}
