use crate::config::{Action, AppRule, Direction};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn socket_path() -> PathBuf {
    PathBuf::from("/run/guardit/ipc.sock")
}

impl FlowWire {
    /// "github.com (140.82.121.4)" when the name is known, else the ip
    pub fn peer(&self) -> String {
        match &self.peer_name {
            Some(n) => format!("{n} ({})", self.peer_ip),
            None => self.peer_ip.clone(),
        }
    }
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
    /// the name an app resolved to get `peer_ip`, when the daemon's DNS tap
    /// saw the answer (daemon::dns_loop). Shown in the UI, and what host
    /// rules match against (config::host_matches) — a flow with no name here
    /// can never match one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_name: Option<String>,
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

/// What the ads/tracking dashboard shows. Counters are since the daemon
/// started — this is a "what is it doing right now" panel, not an audit
/// trail; the per-connection trail is history.jsonl.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistStats {
    pub enabled: bool,
    pub encrypted_dns_blocked: bool,
    /// `id:level` keys currently in force
    pub sources: Vec<String>,
    /// domains loaded across all of them, after merging
    pub domains: usize,
    /// DNS replies the daemon saw at all
    pub queries: u64,
    /// how many of those it rewrote to NXDOMAIN
    pub blocked: u64,
    /// most recent blocked names, oldest first — a false positive is
    /// supposed to be visible here the moment a page breaks
    pub recent: Vec<(u64, String)>,
    /// unix seconds of the oldest enabled list's last download; None = at
    /// least one list has never been fetched
    pub updated_at: Option<u64>,
}

/// daemon -> tui
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
    /// sent once right after a client connects
    Snapshot {
        app_rules: Vec<AppRule>,
        flow: Vec<FlowWire>,
        listening: Vec<ListenEntry>,
        #[serde(default)]
        blocklist: BlocklistStats,
    },
    /// refreshed counters for the ads/tracking dashboard
    Blocklist(BlocklistStats),
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
        /// unix epoch seconds; None = permanent
        #[serde(default)]
        expires: Option<u64>,
        /// restrict to peers resolving to this hostname pattern; None = any
        /// peer. Wins over port and direction, see config::match_rule
        #[serde(default)]
        host: Option<String>,
    },
    ToggleAppRule {
        id: u32,
    },
    /// removes every rule for `exe` — the whole-app default AND every
    /// per-port override, i.e. "forget this app" rather than "remove one rule"
    RmAppRule {
        exe: String,
    },
    /// re-read rules.toml (after `guardit import` or a hand edit) and
    /// broadcast the app rules it now holds
    Reload,
}

/// blocking client for one-shot CLI use (`guardit app`, `pending`,
/// `answer`): the daemon sends a Snapshot first, which `connect` leaves
/// unread for the caller. Err = daemon not running (or not root).
pub struct Client {
    pub reader: BufReader<UnixStream>,
    pub writer: UnixStream,
}

impl Client {
    pub fn connect() -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path())?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        Ok(Client {
            writer: stream.try_clone()?,
            reader: BufReader::new(stream),
        })
    }

    pub fn send(&mut self, msg: &ClientMsg) -> std::io::Result<()> {
        send_msg(&mut self.writer, msg)
    }

    pub fn recv(&mut self) -> std::io::Result<Option<ServerMsg>> {
        read_msg(&mut self.reader)
    }
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
