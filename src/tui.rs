use crate::config;
use crate::config::now_ts;
use crate::config::{Action, AppRule, Config, Direction, Proto, Rule, config_path, match_rule};
use crate::daemon;
use crate::daemon::ago;
use crate::ipc::{self, ClientMsg, FlowStatus, FlowWire, ServerMsg};
use crate::ruleset;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, List, ListItem, ListState, Padding,
    Paragraph, Row, Sparkline, Table, TableState,
};
use ratatui::{Frame, Terminal};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufReader, Read as _, stdout};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

/// covers the whole interface, not just a couple of accent colors: panel
/// background/text, both border states, allow/deny/new status, chart
/// accents, and the 5 pane-identity colors (footer segment + border tint
/// per pane). Every color pairing here is picked for contrast against its
/// own `bg` — `fg`/`allow`/`deny`/`warn`/`accents` all read clearly on it.
#[derive(Clone, Copy)]
struct Theme {
    name: &'static str,
    bg: Color,
    fg: Color,
    border_idle: Color,
    border_focus: Color,
    allow: Color,
    deny: Color,
    warn: Color,
    chart: Color,
    /// per-pane identity color, in Focus tab order: Rules, Apps, Conflicts
    /// (listening ports), TopApps, Flow
    accents: [Color; 5],
}

impl Theme {
    fn base(self) -> Style {
        Style::new().bg(self.bg).fg(self.fg)
    }

    /// the one bordered box every pane uses: thick + focus color when
    /// focused (color alone is too easy to miss), plain + idle color otherwise
    fn pane(self, title: String, focused: bool) -> Block<'static> {
        let (border, kind) = if focused {
            (
                Style::new()
                    .fg(self.border_focus)
                    .add_modifier(Modifier::BOLD),
                BorderType::Thick,
            )
        } else {
            (Style::new().fg(self.border_idle), BorderType::Plain)
        };
        Block::default()
            .style(self.base())
            .borders(Borders::ALL)
            .padding(Padding::horizontal(1))
            .border_style(border)
            .border_type(kind)
            .title(title)
            .title_alignment(Alignment::Center)
    }
}

const THEMES: &[Theme] = &[
    Theme {
        name: "default",
        bg: Color::Reset,
        fg: Color::Reset,
        border_idle: Color::DarkGray,
        border_focus: Color::Yellow,
        allow: Color::Green,
        deny: Color::Red,
        warn: Color::Yellow,
        chart: Color::Yellow,
        accents: [
            Color::Blue,
            Color::Green,
            Color::Magenta,
            Color::Yellow,
            Color::Cyan,
        ],
    },
    Theme {
        name: "dracula",
        bg: Color::Rgb(40, 42, 54),
        fg: Color::Rgb(248, 248, 242),
        border_idle: Color::Rgb(98, 114, 164),
        border_focus: Color::Rgb(189, 147, 249),
        allow: Color::Rgb(80, 250, 123),
        deny: Color::Rgb(255, 85, 85),
        warn: Color::Rgb(241, 250, 140),
        chart: Color::Rgb(255, 121, 198),
        accents: [
            Color::Rgb(139, 233, 253),
            Color::Rgb(80, 250, 123),
            Color::Rgb(255, 121, 198),
            Color::Rgb(241, 250, 140),
            Color::Rgb(189, 147, 249),
        ],
    },
    Theme {
        name: "nord",
        bg: Color::Rgb(46, 52, 64),
        fg: Color::Rgb(229, 233, 240),
        border_idle: Color::Rgb(76, 86, 106),
        border_focus: Color::Rgb(136, 192, 208),
        allow: Color::Rgb(163, 190, 140),
        deny: Color::Rgb(191, 97, 106),
        warn: Color::Rgb(235, 203, 139),
        chart: Color::Rgb(180, 142, 173),
        accents: [
            Color::Rgb(129, 161, 193),
            Color::Rgb(163, 190, 140),
            Color::Rgb(180, 142, 173),
            Color::Rgb(235, 203, 139),
            Color::Rgb(136, 192, 208),
        ],
    },
    Theme {
        name: "mono",
        bg: Color::Black,
        fg: Color::White,
        border_idle: Color::Gray,
        border_focus: Color::White,
        allow: Color::White,
        deny: Color::Gray,
        warn: Color::White,
        chart: Color::White,
        accents: [
            Color::White,
            Color::White,
            Color::White,
            Color::White,
            Color::White,
        ],
    },
    Theme {
        name: "gruvbox",
        bg: Color::Rgb(0x28, 0x28, 0x28),
        fg: Color::Rgb(0xeb, 0xdb, 0xb2),
        border_idle: Color::Rgb(0x92, 0x83, 0x74),
        border_focus: Color::Rgb(0xfa, 0xbd, 0x2f),
        allow: Color::Rgb(0xb8, 0xbb, 0x26),
        deny: Color::Rgb(0xfb, 0x49, 0x34),
        warn: Color::Rgb(0xfa, 0xbd, 0x2f),
        chart: Color::Rgb(0xd3, 0x86, 0x9b),
        accents: [
            Color::Rgb(0x83, 0xa5, 0x98),
            Color::Rgb(0xb8, 0xbb, 0x26),
            Color::Rgb(0xd3, 0x86, 0x9b),
            Color::Rgb(0xfa, 0xbd, 0x2f),
            Color::Rgb(0x8e, 0xc0, 0x7c),
        ],
    },
    Theme {
        name: "solarized-dark",
        bg: Color::Rgb(0x00, 0x2b, 0x36),
        fg: Color::Rgb(0x83, 0x94, 0x96),
        border_idle: Color::Rgb(0x58, 0x6e, 0x75),
        border_focus: Color::Rgb(0x26, 0x8b, 0xd2),
        allow: Color::Rgb(0x85, 0x99, 0x00),
        deny: Color::Rgb(0xdc, 0x32, 0x2f),
        warn: Color::Rgb(0xb5, 0x89, 0x00),
        chart: Color::Rgb(0xd3, 0x36, 0x82),
        accents: [
            Color::Rgb(0x26, 0x8b, 0xd2),
            Color::Rgb(0x85, 0x99, 0x00),
            Color::Rgb(0xd3, 0x36, 0x82),
            Color::Rgb(0xb5, 0x89, 0x00),
            Color::Rgb(0x2a, 0xa1, 0x98),
        ],
    },
    Theme {
        name: "monokai",
        bg: Color::Rgb(0x27, 0x28, 0x22),
        fg: Color::Rgb(0xf8, 0xf8, 0xf2),
        border_idle: Color::Rgb(0x75, 0x71, 0x5e),
        border_focus: Color::Rgb(0x66, 0xd9, 0xef),
        allow: Color::Rgb(0xa6, 0xe2, 0x2e),
        deny: Color::Rgb(0xf9, 0x26, 0x72),
        warn: Color::Rgb(0xe6, 0xdb, 0x74),
        chart: Color::Rgb(0xae, 0x81, 0xff),
        accents: [
            Color::Rgb(0x66, 0xd9, 0xef),
            Color::Rgb(0xa6, 0xe2, 0x2e),
            Color::Rgb(0xae, 0x81, 0xff),
            Color::Rgb(0xe6, 0xdb, 0x74),
            Color::Rgb(0xfd, 0x97, 0x1f),
        ],
    },
    Theme {
        name: "tokyonight",
        bg: Color::Rgb(0x1a, 0x1b, 0x26),
        fg: Color::Rgb(0xc0, 0xca, 0xf5),
        border_idle: Color::Rgb(0x56, 0x5f, 0x89),
        border_focus: Color::Rgb(0x7a, 0xa2, 0xf7),
        allow: Color::Rgb(0x9e, 0xce, 0x6a),
        deny: Color::Rgb(0xf7, 0x76, 0x8e),
        warn: Color::Rgb(0xe0, 0xaf, 0x68),
        chart: Color::Rgb(0xbb, 0x9a, 0xf7),
        accents: [
            Color::Rgb(0x7a, 0xa2, 0xf7),
            Color::Rgb(0x9e, 0xce, 0x6a),
            Color::Rgb(0xbb, 0x9a, 0xf7),
            Color::Rgb(0xe0, 0xaf, 0x68),
            Color::Rgb(0x7d, 0xcf, 0xff),
        ],
    },
    Theme {
        name: "catppuccin",
        bg: Color::Rgb(0x1e, 0x1e, 0x2e),
        fg: Color::Rgb(0xcd, 0xd6, 0xf4),
        border_idle: Color::Rgb(0x6c, 0x70, 0x86),
        border_focus: Color::Rgb(0xcb, 0xa6, 0xf7),
        allow: Color::Rgb(0xa6, 0xe3, 0xa1),
        deny: Color::Rgb(0xf3, 0x8b, 0xa8),
        warn: Color::Rgb(0xf9, 0xe2, 0xaf),
        chart: Color::Rgb(0xfa, 0xb3, 0x87),
        accents: [
            Color::Rgb(0x89, 0xb4, 0xfa),
            Color::Rgb(0xa6, 0xe3, 0xa1),
            Color::Rgb(0xcb, 0xa6, 0xf7),
            Color::Rgb(0xf9, 0xe2, 0xaf),
            Color::Rgb(0x94, 0xe2, 0xd5),
        ],
    },
    Theme {
        name: "onedark",
        bg: Color::Rgb(0x28, 0x2c, 0x34),
        fg: Color::Rgb(0xab, 0xb2, 0xbf),
        border_idle: Color::Rgb(0x5c, 0x63, 0x70),
        border_focus: Color::Rgb(0x61, 0xaf, 0xef),
        allow: Color::Rgb(0x98, 0xc3, 0x79),
        deny: Color::Rgb(0xe0, 0x6c, 0x75),
        warn: Color::Rgb(0xe5, 0xc0, 0x7b),
        chart: Color::Rgb(0xc6, 0x78, 0xdd),
        accents: [
            Color::Rgb(0x61, 0xaf, 0xef),
            Color::Rgb(0x98, 0xc3, 0x79),
            Color::Rgb(0xc6, 0x78, 0xdd),
            Color::Rgb(0xe5, 0xc0, 0x7b),
            Color::Rgb(0x56, 0xb6, 0xc2),
        ],
    },
    Theme {
        name: "everforest",
        bg: Color::Rgb(0x2d, 0x35, 0x3b),
        fg: Color::Rgb(0xd3, 0xc6, 0xaa),
        border_idle: Color::Rgb(0x7a, 0x84, 0x78),
        border_focus: Color::Rgb(0xa7, 0xc0, 0x80),
        allow: Color::Rgb(0xa7, 0xc0, 0x80),
        deny: Color::Rgb(0xe6, 0x7e, 0x80),
        warn: Color::Rgb(0xdb, 0xbc, 0x7f),
        chart: Color::Rgb(0xd6, 0x99, 0xb6),
        accents: [
            Color::Rgb(0x7f, 0xbb, 0xb3),
            Color::Rgb(0xa7, 0xc0, 0x80),
            Color::Rgb(0xd6, 0x99, 0xb6),
            Color::Rgb(0xdb, 0xbc, 0x7f),
            Color::Rgb(0x83, 0xc0, 0x92),
        ],
    },
    Theme {
        name: "ayu",
        bg: Color::Rgb(0x0b, 0x0e, 0x14),
        fg: Color::Rgb(0xbf, 0xbd, 0xb6),
        border_idle: Color::Rgb(0x56, 0x5b, 0x66),
        border_focus: Color::Rgb(0x39, 0xba, 0xe6),
        allow: Color::Rgb(0xc2, 0xd9, 0x4c),
        deny: Color::Rgb(0xf0, 0x71, 0x78),
        warn: Color::Rgb(0xff, 0xb4, 0x54),
        chart: Color::Rgb(0xd2, 0xa6, 0xff),
        accents: [
            Color::Rgb(0x39, 0xba, 0xe6),
            Color::Rgb(0xc2, 0xd9, 0x4c),
            Color::Rgb(0xd2, 0xa6, 0xff),
            Color::Rgb(0xff, 0xb4, 0x54),
            Color::Rgb(0x95, 0xe6, 0xcb),
        ],
    },
];

/// theme choice lives next to rules.toml but in its own file — it's a TUI
/// display preference, not part of the daemon's config, no reason to share
/// a lock with security-relevant writes
fn theme_path() -> std::path::PathBuf {
    config_path().with_file_name("theme")
}

fn load_theme_idx() -> usize {
    std::fs::read_to_string(theme_path())
        .ok()
        .and_then(|s| THEMES.iter().position(|t| t.name == s.trim()))
        .unwrap_or(0)
}

fn save_theme_idx(idx: usize) {
    if let Some(dir) = theme_path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(theme_path(), THEMES[idx].name);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Focus {
    Apps,
    Flow,
    Rules,
    /// listening ports — inside the log tab, not the grid: it answers the
    /// same "what has been going on" question the audit trail does, and
    /// pairing them frees the grid's third column for the live flow
    Conflicts,
    /// the full audit trail — its own tab, rendered over the whole grid area
    /// and jumpable to from anywhere via the global `A` key, same idea as
    /// `t` for theme
    AppLog,
}

/// the log tab: the audit trail and the listening ports, Tab switching
/// between them. Everything else is the bento grid.
fn in_log_tab(focus: Focus) -> bool {
    matches!(focus, Focus::AppLog | Focus::Conflicts)
}

// Grid tab order: system rules -> apps -> network flow, then back. Top apps
// and the blocking dashboard are informational (nothing to focus), and the
// audit tab is reached only via the global `A` key or a pane's `l` — a
// drill-down, not a pane you'd casually cycle through.
impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Rules => Focus::Apps,
            Focus::Apps => Focus::Flow,
            Focus::Flow => Focus::Rules,
            // inside the tab, Tab is a toggle between its two halves
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
        }
    }

    fn prev(self) -> Focus {
        match self {
            Focus::Rules => Focus::Flow,
            Focus::Apps => Focus::Rules,
            Focus::Flow => Focus::Apps,
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
        }
    }
}

enum Mode {
    Browse,
    Add(String),
    Preset(usize),
    /// keystrokes go to `App::apps_filter` instead of the Apps pane's own
    /// keys — the filter itself stays applied after leaving this mode
    Filter,
    /// the same, for the log tab's own filter (`App::log_filter`)
    LogFilter,
}

/// newest first — same reader as `guardit log-app`, just rendered live
fn read_app_log(limit: usize, filter: Option<&str>) -> Vec<FlowWire> {
    let mut entries = daemon::read_history(limit, filter);
    entries.reverse();
    entries
}

fn flush_app_log() -> std::io::Result<()> {
    std::fs::write(daemon::history_log_path(), "")
}

/// canned rule specs (same format as the freeform `a` add-flow) for users
/// who don't want to hand-write nft-ish specs — covers the common cases
const PRESETS: &[(&str, &str)] = &[
    ("Allow LAN (192.168.0.0/16)", "allow any 192.168.0.0/16 -"),
    ("Allow SSH (22)", "allow tcp any 22"),
    ("Allow DNS (53)", "allow any any 53"),
    ("Allow HTTP (80)", "allow tcp any 80"),
    ("Allow HTTPS (443)", "allow tcp any 443"),
    ("Block HTTP (80)", "deny tcp any 80"),
    ("Block HTTPS (443)", "deny tcp any 443"),
];

/// client side of the daemon's IPC socket (see src/daemon.rs) — non-blocking,
/// polled once per tick. `None` means the daemon isn't reachable (not
/// running, or we're not root); the Apps/Flow panes then just say so.
struct IpcClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    buf: Vec<u8>,
}

impl IpcClient {
    fn connect() -> Option<Self> {
        let stream = UnixStream::connect(ipc::socket_path()).ok()?;
        stream.set_nonblocking(true).ok()?;
        let writer = stream.try_clone().ok()?;
        Some(IpcClient {
            reader: BufReader::new(stream),
            writer,
            buf: Vec::new(),
        })
    }

    /// drains whatever full lines are currently available without blocking
    fn poll(&mut self) -> Vec<ServerMsg> {
        let mut chunk = [0u8; 4096];
        loop {
            match self.reader.read(&mut chunk) {
                Ok(n) if n > 0 => self.buf.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        let mut out = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            if let Ok(msg) = serde_json::from_slice::<ServerMsg>(&line[..line.len() - 1]) {
                out.push(msg);
            }
        }
        out
    }

    fn send(&mut self, msg: &ClientMsg) {
        let _ = ipc::send_msg(&mut self.writer, msg);
    }
}

/// one row of the Apps pane: either a persisted decision (`rule` set) or an
/// app that's only been *seen* asking (no rule yet — shows up as "new")
struct AppRow {
    exe: String,
    /// the whole-app default (port: None) — never a per-port override, so
    /// this row always reflects "what happens to a port with no specific
    /// rule of its own", not an arbitrary one of possibly several rules
    rule: Option<AppRule>,
    /// how many per-port overrides this app has beyond the default above
    port_overrides: usize,
}

const FLOW_CAP: usize = 200;
/// one sparkline bar per this much wall time. Matched to the daemon's own
/// stats cadence (daemon::LISTEN_SCAN_INTERVAL) — sampling faster would just
/// draw the same number spread across several bars
const BLOCKED_SAMPLE: std::time::Duration = std::time::Duration::from_secs(5);
const BLOCKED_HIST_CAP: usize = 120;

/// `flow` is global across all apps (kept after decision so the pane reads as
/// a history); the Apps pane's selection decides which slice Flow shows.
/// `msg` is for errors only — everything else the UI can say is already
/// visible live somewhere, so it never repeats transient "did X" notes.
struct App {
    cfg: Config,
    state: ListState,
    apps: Vec<AppRow>,
    apps_state: ListState,
    app_rules: Vec<AppRule>,
    flow: Vec<FlowWire>,
    flow_state: ListState,
    /// connection attempts per app since the audit log was last flushed —
    /// seeded from history.jsonl, then bumped live; what Top apps charts
    counts: HashMap<String, u64>,
    focus: Focus,
    ipc: Option<IpcClient>,
    mode: Mode,
    msg: String,
    net_prev: (u64, u64),
    net_prev_at: Instant,
    net_rate_kbps: (f64, f64),
    net_hist_down: VecDeque<u64>,
    net_hist_up: VecDeque<u64>,
    interfaces: Vec<String>,
    listening: Vec<ipc::ListenEntry>,
    conflicts_state: ListState,
    theme_idx: usize,
    app_log: Vec<FlowWire>,
    app_log_state: TableState,
    /// which pane to return to on q/L from AppLog — it's not a Tab stop, so
    /// "back" has to remember where you came from
    prev_focus: Focus,
    /// None = full unthrottled trail (global L); Some(exe) = just that app
    /// (l from Apps/Flow/Conflicts)
    app_log_filter: Option<String>,
    app_log_confirm_flush: bool,
    /// case-insensitive substring the Apps pane is narrowed to; empty = all.
    /// Applied in rebuild_apps, so every pane that keys off the Apps
    /// selection (Flow above all) follows it without knowing about it
    apps_filter: String,
    /// every row read from history.jsonl for the current `app_log_filter`;
    /// `app_log` is this narrowed by `log_filter`, and is what the tab
    /// renders and what its selection indexes into
    app_log_all: Vec<FlowWire>,
    /// port / ip / name the log tab is narrowed to; empty = all
    log_filter: String,
    blocklist: ipc::BlocklistStats,
    /// blocked lookups per sampling window, oldest first — sampled on our own
    /// clock rather than on the daemon's updates, so a window in which
    /// nothing was blocked is a zero rather than a gap
    blocked_hist: VecDeque<u64>,
    blocked_prev: u64,
    blocked_sampled_at: Instant,
}

/// total rx/tx bytes across every interface except loopback, from
/// /proc/net/dev — system-wide, not per-app (NFQUEUE only sees the first
/// packet of a *new* connection, never the bulk of established traffic, so
/// per-app throughput isn't available without a much bigger accounting layer)
fn read_net_bytes() -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    if let Ok(text) = std::fs::read_to_string("/proc/net/dev") {
        for line in text.lines().skip(2) {
            let Some((iface, rest)) = line.split_once(':') else {
                continue;
            };
            if iface.trim() == "lo" {
                continue;
            }
            let cols: Vec<&str> = rest.split_whitespace().collect();
            if cols.len() < 9 {
                continue;
            }
            rx += cols[0].parse::<u64>().unwrap_or(0);
            tx += cols[8].parse::<u64>().unwrap_or(0);
        }
    }
    (rx, tx)
}

/// every non-loopback interface currently in /proc/net/dev — the exact set
/// read_net_bytes() sums over, shown in the header so it's clear what
/// "down/up KB/s" actually covers
fn list_interfaces() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/proc/net/dev") else {
        return Vec::new();
    };
    text.lines()
        .skip(2)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(iface, _)| iface.trim().to_string())
        })
        .filter(|iface| iface != "lo")
        .collect()
}

fn basename(exe: &str) -> &str {
    Path::new(exe)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(exe)
}

/// Add-rule spec: "<allow|deny> <tcp|udp|any> <src|any> <port|->"
fn parse_spec(line: &str) -> Result<Rule, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 4 {
        return Err("format: <allow|deny> <tcp|udp|any> <src|any> <port|->".into());
    }
    let action = match parts[0] {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => return Err("action must be allow|deny".into()),
    };
    let proto = match parts[1] {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "any" => Proto::Any,
        _ => return Err("proto must be tcp|udp|any".into()),
    };
    let src = parts[2].to_string();
    config::validate_src(&src)?;
    let port = if parts[3] == "-" {
        None
    } else {
        Some(
            parts[3]
                .parse::<u16>()
                .map_err(|_| "bad port".to_string())?,
        )
    };
    Ok(Rule {
        id: 0,
        action,
        proto,
        src,
        port,
        enabled: true,
    })
}

fn new_app(cfg: Config) -> App {
    let mut app = App {
        app_rules: cfg.app_rule.clone(),
        cfg,
        state: ListState::default(),
        apps: Vec::new(),
        apps_state: ListState::default(),
        flow: Vec::new(),
        flow_state: ListState::default(),
        counts: daemon::count_history(),
        focus: Focus::Rules,
        ipc: IpcClient::connect(),
        mode: Mode::Browse,
        msg: String::new(),
        net_prev: read_net_bytes(),
        net_prev_at: Instant::now(),
        net_rate_kbps: (0.0, 0.0),
        net_hist_down: VecDeque::new(),
        net_hist_up: VecDeque::new(),
        interfaces: list_interfaces(),
        listening: Vec::new(),
        conflicts_state: ListState::default(),
        theme_idx: load_theme_idx(),
        app_log: Vec::new(),
        app_log_state: TableState::default(),
        prev_focus: Focus::Rules,
        app_log_filter: None,
        app_log_confirm_flush: false,
        apps_filter: String::new(),
        app_log_all: Vec::new(),
        log_filter: String::new(),
        blocklist: ipc::BlocklistStats::default(),
        blocked_hist: VecDeque::new(),
        blocked_prev: 0,
        blocked_sampled_at: Instant::now(),
    };
    if !app.cfg.rule.is_empty() {
        app.state.select(Some(0));
    }
    rebuild_apps(&mut app);
    app
}

pub fn run(cfg: Config) {
    enable_raw_mode().expect("raw mode");
    stdout().execute(EnterAlternateScreen).expect("alt screen");
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut app = new_app(cfg);

    loop {
        terminal.draw(|f| draw(f, &mut app)).expect("draw");

        // no key ready within the tick → refresh live views instead of blocking
        if !event::poll(std::time::Duration::from_millis(500)).unwrap_or(false) {
            if app.focus == Focus::AppLog {
                let keep = app.app_log_state.selected();
                app.app_log_all = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
                apply_log_filter(&mut app);
                // apply_log_filter resets to the top; a live refresh must not
                // yank the selection out from under someone scrolling
                if let Some(i) = keep
                    && i < app.app_log.len()
                {
                    app.app_log_state.select(Some(i));
                }
            }
            drain_ipc(&mut app);
            let now = Instant::now();
            let elapsed = now.duration_since(app.net_prev_at).as_secs_f64();
            if elapsed > 0.05 {
                let (rx, tx) = read_net_bytes();
                app.net_rate_kbps = (
                    rx.saturating_sub(app.net_prev.0) as f64 / 1024.0 / elapsed,
                    tx.saturating_sub(app.net_prev.1) as f64 / 1024.0 / elapsed,
                );
                app.net_prev = (rx, tx);
                app.net_prev_at = now;
                const NET_HIST_CAP: usize = 120;
                for (hist, rate) in [
                    (&mut app.net_hist_down, app.net_rate_kbps.0),
                    (&mut app.net_hist_up, app.net_rate_kbps.1),
                ] {
                    hist.push_back(rate as u64);
                    while hist.len() > NET_HIST_CAP {
                        hist.pop_front();
                    }
                }
            }
            // the daemon only pushes blocklist counters when they move, so
            // sampling on its messages would draw a quiet minute as no data
            // at all instead of as zeroes. One bar per window, on our clock.
            if now.duration_since(app.blocked_sampled_at) >= BLOCKED_SAMPLE {
                app.blocked_sampled_at = now;
                let total = app.blocklist.blocked;
                app.blocked_hist
                    .push_back(total.saturating_sub(app.blocked_prev));
                app.blocked_prev = total;
                while app.blocked_hist.len() > BLOCKED_HIST_CAP {
                    app.blocked_hist.pop_front();
                }
            }
            continue;
        }
        if let Event::Key(key) = event::read().expect("read event") {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            app.msg.clear();
            if (key.code == KeyCode::Tab || key.code == KeyCode::BackTab)
                && !matches!(
                    app.mode,
                    Mode::Add(_) | Mode::Preset(_) | Mode::Filter | Mode::LogFilter
                )
            {
                app.focus = if key.code == KeyCode::BackTab {
                    app.focus.prev()
                } else {
                    app.focus.next()
                };
                if app.apps_state.selected().is_none() && !app.apps.is_empty() {
                    app.apps_state.select(Some(0));
                    reset_flow_selection(&mut app);
                }
                continue;
            }
            if key.code == KeyCode::Char('t')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter | Mode::LogFilter)
            {
                app.theme_idx = (app.theme_idx + 1) % THEMES.len();
                save_theme_idx(app.theme_idx);
                continue;
            }
            // jumpable to from anywhere, same idea as `t` — the audit tab is
            // its own tab, not nested under any pane's local keys
            if key.code == KeyCode::Char('A')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter | Mode::LogFilter)
            {
                if in_log_tab(app.focus) {
                    close_app_log(&mut app);
                } else {
                    open_app_log(&mut app, None);
                }
                continue;
            }
            match app.focus {
                Focus::Rules => match &mut app.mode {
                    Mode::Browse => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('j') | KeyCode::Down => select_next(&mut app),
                        KeyCode::Char('k') | KeyCode::Up => select_prev(&mut app),
                        KeyCode::Char(' ') => toggle_selected(&mut app),
                        KeyCode::Char('d') => delete_selected(&mut app),
                        KeyCode::Char('a') => app.mode = Mode::Add(String::new()),
                        KeyCode::Char('p') => app.mode = Mode::Preset(0),
                        _ => {}
                    },
                    Mode::Preset(sel) => match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => app.mode = Mode::Browse,
                        KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1) % PRESETS.len(),
                        KeyCode::Char('k') | KeyCode::Up => {
                            *sel = (*sel + PRESETS.len() - 1) % PRESETS.len()
                        }
                        KeyCode::Enter => {
                            let (_, spec) = PRESETS[*sel];
                            let mut r = parse_spec(spec).expect("built-in preset spec must parse");
                            r.id = app.cfg.next_id();
                            app.cfg.rule.push(r);
                            save_rules(&mut app);
                            app.mode = Mode::Browse;
                        }
                        _ => {}
                    },
                    // only ever set from the Apps pane / the log tab, and Tab
                    // can't leave either — but if one got here, Browse is the
                    // safe read
                    Mode::Filter | Mode::LogFilter => app.mode = Mode::Browse,
                    Mode::Add(buf) => match key.code {
                        KeyCode::Esc => app.mode = Mode::Browse,
                        KeyCode::Enter => {
                            match parse_spec(buf) {
                                Ok(mut r) => {
                                    r.id = app.cfg.next_id();
                                    app.cfg.rule.push(r);
                                    save_rules(&mut app);
                                }
                                Err(e) => app.msg = format!("error: {e}"),
                            }
                            app.mode = Mode::Browse;
                        }
                        KeyCode::Backspace => {
                            buf.pop();
                        }
                        KeyCode::Char(c) => buf.push(c),
                        _ => {}
                    },
                },
                // every keystroke narrows the list live, so you see what
                // you're typing towards instead of committing blind
                Focus::Apps if matches!(app.mode, Mode::Filter) => {
                    match key.code {
                        KeyCode::Enter => app.mode = Mode::Browse,
                        KeyCode::Esc => {
                            app.apps_filter.clear();
                            app.mode = Mode::Browse;
                        }
                        KeyCode::Backspace => {
                            app.apps_filter.pop();
                        }
                        KeyCode::Char(c) => app.apps_filter.push(c),
                        _ => continue,
                    }
                    rebuild_apps(&mut app);
                    reset_flow_selection(&mut app);
                }
                Focus::Apps => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('/') => app.mode = Mode::Filter,
                    // a filter left on is easy to forget about — Esc drops it
                    // from anywhere in the pane, not only while typing
                    KeyCode::Esc if !app.apps_filter.is_empty() => {
                        app.apps_filter.clear();
                        rebuild_apps(&mut app);
                        reset_flow_selection(&mut app);
                    }
                    KeyCode::Char('j') | KeyCode::Down => apps_select(&mut app, false),
                    KeyCode::Char('k') | KeyCode::Up => apps_select(&mut app, true),
                    KeyCode::Char('y') => apps_set_verdict(&mut app, Action::Allow),
                    KeyCode::Char('n') => apps_set_verdict(&mut app, Action::Deny),
                    KeyCode::Char(' ') => apps_toggle_selected(&mut app),
                    KeyCode::Char('d') => apps_delete_selected(&mut app),
                    // jump to this app's connection history — Flow is already
                    // filtered by whichever app is selected here
                    KeyCode::Enter => {
                        app.focus = Focus::Flow;
                        reset_flow_selection(&mut app);
                    }
                    KeyCode::Char('l') => {
                        if let Some(exe) = app
                            .apps_state
                            .selected()
                            .and_then(|i| app.apps.get(i))
                            .map(|r| r.exe.clone())
                        {
                            open_app_log(&mut app, Some(exe));
                        }
                    }
                    _ => {}
                },
                Focus::Flow => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('j') | KeyCode::Down => flow_select(&mut app, false),
                    KeyCode::Char('k') | KeyCode::Up => flow_select(&mut app, true),
                    KeyCode::Char('y') => flow_decide(&mut app, Action::Allow),
                    KeyCode::Char('n') => flow_decide(&mut app, Action::Deny),
                    // uppercase = wider scope: the peer's name instead of the port
                    KeyCode::Char('Y') => flow_decide_host(&mut app, Action::Allow),
                    KeyCode::Char('N') => flow_decide_host(&mut app, Action::Deny),
                    KeyCode::Char('l') => {
                        if let Some(exe) = app
                            .apps_state
                            .selected()
                            .and_then(|i| app.apps.get(i))
                            .map(|r| r.exe.clone())
                        {
                            open_app_log(&mut app, Some(exe));
                        }
                    }
                    _ => {}
                },
                Focus::Conflicts => match key.code {
                    KeyCode::Char('q') => close_app_log(&mut app),
                    KeyCode::Char('j') | KeyCode::Down => conflicts_select(&mut app, false),
                    KeyCode::Char('k') | KeyCode::Up => conflicts_select(&mut app, true),
                    KeyCode::Char('y') => conflicts_decide(&mut app, Action::Allow),
                    KeyCode::Char('n') => conflicts_decide(&mut app, Action::Deny),
                    KeyCode::Char('l') => {
                        if let Some(exe) = app
                            .conflicts_state
                            .selected()
                            .and_then(|i| app.listening.get(i))
                            .map(|e| e.exe.clone())
                        {
                            open_app_log(&mut app, Some(exe));
                        }
                    }
                    _ => {}
                },
                // q/L never quit the whole app from here — they take you back
                // to whichever pane you jumped in from, same as closing a drill-down
                Focus::AppLog if app.app_log_confirm_flush => match key.code {
                    KeyCode::Char('y') => {
                        if let Err(e) = flush_app_log() {
                            app.msg = format!("flush failed: {e}");
                        }
                        app.app_log_confirm_flush = false;
                        app.counts.clear();
                        app.app_log_all =
                            read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
                        apply_log_filter(&mut app);
                        app.app_log_state.select(None);
                    }
                    KeyCode::Char('n') | KeyCode::Esc => app.app_log_confirm_flush = false,
                    _ => {}
                },
                Focus::AppLog if matches!(app.mode, Mode::LogFilter) => {
                    match key.code {
                        KeyCode::Enter => app.mode = Mode::Browse,
                        KeyCode::Esc => {
                            app.log_filter.clear();
                            app.mode = Mode::Browse;
                        }
                        KeyCode::Backspace => {
                            app.log_filter.pop();
                        }
                        KeyCode::Char(c) => app.log_filter.push(c),
                        _ => continue,
                    }
                    apply_log_filter(&mut app);
                }
                Focus::AppLog => match key.code {
                    KeyCode::Char('q') => close_app_log(&mut app),
                    KeyCode::Char('/') => app.mode = Mode::LogFilter,
                    KeyCode::Esc if !app.log_filter.is_empty() => {
                        app.log_filter.clear();
                        apply_log_filter(&mut app);
                    }
                    KeyCode::Char('f') => app.app_log_confirm_flush = true,
                    KeyCode::Char('j') | KeyCode::Down => app.app_log_state.select(step(
                        app.app_log_state.selected(),
                        app.app_log.len(),
                        false,
                    )),
                    KeyCode::Char('k') | KeyCode::Up => app.app_log_state.select(step(
                        app.app_log_state.selected(),
                        app.app_log.len(),
                        true,
                    )),
                    _ => {}
                },
            }
        }
    }

    disable_raw_mode().expect("disable raw mode");
    stdout()
        .execute(LeaveAlternateScreen)
        .expect("leave alt screen");
}

fn drain_ipc(app: &mut App) {
    let Some(ipc) = &mut app.ipc else { return };
    let msgs = ipc.poll();
    if msgs.is_empty() {
        return;
    }
    for msg in msgs {
        match msg {
            ServerMsg::Snapshot {
                app_rules,
                flow,
                listening,
                blocklist,
            } => {
                app.app_rules = app_rules;
                app.flow = flow;
                app.listening = listening;
                app.blocklist = blocklist;
                sort_listening(&mut app.listening);
            }
            ServerMsg::Blocklist(stats) => app.blocklist = stats,
            ServerMsg::FlowNew(w) => {
                *app.counts.entry(w.exe.clone()).or_default() += 1;
                app.flow.push(w);
            }
            ServerMsg::FlowResolved { req_id, status } => {
                if let Some(entry) = app.flow.iter_mut().find(|e| e.req_id == Some(req_id)) {
                    entry.status = status;
                }
            }
            ServerMsg::AppRules(rules) => app.app_rules = rules,
            ServerMsg::Listening(entries) => {
                app.listening = entries;
                sort_listening(&mut app.listening);
            }
        }
    }
    if app.flow.len() > FLOW_CAP {
        let excess = app.flow.len() - FLOW_CAP;
        app.flow.drain(0..excess);
    }
    rebuild_apps(app);
    reset_flow_selection(app);
}

/// rebuilds the Apps list from scratch: every app with a persisted rule,
/// plus every app seen in the flow log that doesn't have one yet ("new").
/// Tries to keep the same app selected across rebuilds by exe path.
fn rebuild_apps(app: &mut App) {
    let selected_exe = app
        .apps_state
        .selected()
        .and_then(|i| app.apps.get(i))
        .map(|r| r.exe.clone());

    let mut seen = HashSet::new();
    let mut rows: Vec<AppRow> = Vec::new();
    // whole-app defaults first so each app's row shows its default, never an
    // arbitrary per-port override; then apps that only have overrides
    let rules = &app.app_rules;
    for r in rules
        .iter()
        .filter(|r| r.port.is_none())
        .chain(rules.iter())
    {
        if seen.insert(r.exe.clone()) {
            let port_overrides = rules
                .iter()
                .filter(|o| o.exe == r.exe && o.port.is_some())
                .count();
            rows.push(AppRow {
                exe: r.exe.clone(),
                rule: r.port.is_none().then(|| r.clone()),
                port_overrides,
            });
        }
    }
    for e in &app.flow {
        if seen.insert(e.exe.clone()) {
            rows.push(AppRow {
                exe: e.exe.clone(),
                rule: None,
                port_overrides: 0,
            });
        }
    }
    rows.sort_by(|a, b| a.exe.cmp(&b.exe));
    if !app.apps_filter.is_empty() {
        let needle = app.apps_filter.to_lowercase();
        rows.retain(|r| r.exe.to_lowercase().contains(&needle));
    }
    app.apps = rows;

    let restored = selected_exe.and_then(|exe| app.apps.iter().position(|r| r.exe == exe));
    match restored {
        Some(i) => app.apps_state.select(Some(i)),
        None if !app.apps.is_empty() => app.apps_state.select(Some(0)),
        None => app.apps_state.select(None),
    }
}

/// indices into `app.flow` for the currently selected app, newest first —
/// what the Flow pane actually renders and what its selection indexes into
fn current_flow_indices(app: &App) -> Vec<usize> {
    let Some(exe) = app
        .apps_state
        .selected()
        .and_then(|i| app.apps.get(i))
        .map(|r| r.exe.as_str())
    else {
        return Vec::new();
    };
    let mut idxs: Vec<usize> = app
        .flow
        .iter()
        .enumerate()
        .filter(|(_, e)| e.exe == exe)
        .map(|(i, _)| i)
        .collect();
    idxs.reverse();
    idxs
}

fn reset_flow_selection(app: &mut App) {
    let idxs = current_flow_indices(app);
    app.flow_state
        .select(if idxs.is_empty() { None } else { Some(0) });
}

/// writes the IP/port rules under the shared config lock (see Config::update,
/// safe against a concurrent daemon write to app_rule), then applies
/// immediately — there's no separate "apply" step, every change takes
/// effect the moment you make it
fn save_rules(app: &mut App) {
    let rule = app.cfg.rule.clone();
    app.cfg = Config::update(|fresh| fresh.rule = rule);
    if let Err(e) = ruleset::apply(&app.cfg) {
        app.msg = format!("apply failed: {e}");
    }
}

/// wrap-around cursor move shared by every list/table in the UI
fn step(sel: Option<usize>, len: usize, back: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let delta = if back { len - 1 } else { 1 };
    Some(sel.map(|i| (i + delta) % len).unwrap_or(0))
}

fn select_next(app: &mut App) {
    app.state
        .select(step(app.state.selected(), app.cfg.rule.len(), false));
}

fn select_prev(app: &mut App) {
    app.state
        .select(step(app.state.selected(), app.cfg.rule.len(), true));
}

fn toggle_selected(app: &mut App) {
    if let Some(r) = app.state.selected().and_then(|i| app.cfg.rule.get_mut(i)) {
        r.enabled = !r.enabled;
        save_rules(app);
    }
}

fn delete_selected(app: &mut App) {
    if let Some(i) = app.state.selected()
        && i < app.cfg.rule.len()
    {
        app.cfg.rule.remove(i);
        save_rules(app);
        if app.cfg.rule.is_empty() {
            app.state.select(None);
        } else if i >= app.cfg.rule.len() {
            app.state.select(Some(app.cfg.rule.len() - 1));
        }
    }
}

const APP_LOG_LIMIT: usize = 300;

fn open_app_log(app: &mut App, filter: Option<String>) {
    if !in_log_tab(app.focus) {
        app.prev_focus = app.focus;
    }
    app.app_log_filter = filter;
    app.app_log_confirm_flush = false;
    app.focus = Focus::AppLog;
    app.app_log_all = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
    apply_log_filter(app);
}

/// Narrows the tab to one port, address or name.
///
/// A digits-only needle is matched against the port as a whole number, so
/// `/443` is port 443 and not "every port and address containing 443";
/// anything else is a substring of the peer address, the resolved name or
/// the app path, which is how you'd type an ip prefix or a domain.
fn log_row_matches(e: &FlowWire, needle: &str) -> bool {
    if needle.chars().all(|c| c.is_ascii_digit()) {
        return e.port.is_some_and(|p| p.to_string() == needle);
    }
    let needle = needle.to_lowercase();
    e.peer_ip.to_lowercase().contains(&needle)
        || e.peer_name
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains(&needle))
        || e.exe.to_lowercase().contains(&needle)
}

fn apply_log_filter(app: &mut App) {
    app.app_log = if app.log_filter.is_empty() {
        app.app_log_all.clone()
    } else {
        app.app_log_all
            .iter()
            .filter(|e| log_row_matches(e, &app.log_filter))
            .cloned()
            .collect()
    };
    app.app_log_state.select(if app.app_log.is_empty() {
        None
    } else {
        Some(0)
    });
}

fn close_app_log(app: &mut App) {
    app.focus = app.prev_focus;
    app.app_log_filter = None;
    app.log_filter.clear();
    app.app_log_confirm_flush = false;
}

fn apps_select(app: &mut App, back: bool) {
    app.apps_state
        .select(step(app.apps_state.selected(), app.apps.len(), back));
    reset_flow_selection(app);
}

/// a persisted allow/deny applies to every Flow row it covers, not just
/// going forward: rows already shown flip to match, and any genuinely
/// PENDING request (the daemon is holding that packet open) gets resolved
/// now instead of sitting until its own timeout. The caller's `matches_row`
/// decides the scope — whole app (Apps pane) or one (app, port) pair (Flow
/// and Listening panes), never one silently widening into the other.
fn cascade_flow_rows(app: &mut App, action: Action, matches_row: impl Fn(&FlowWire) -> bool) {
    let new_status = FlowStatus::from(action);
    let mut pending_req_ids = Vec::new();
    for e in app.flow.iter_mut().filter(|e| matches_row(e)) {
        if matches!(e.status, FlowStatus::Pending)
            && let Some(req_id) = e.req_id
        {
            pending_req_ids.push(req_id);
        }
        e.status = new_status;
    }
    if let Some(ipc) = &mut app.ipc {
        for req_id in pending_req_ids {
            ipc.send(&ClientMsg::Decide {
                req_id,
                verdict: action,
            });
        }
    }
}

/// the daemon's history records what actually happened *at the time* — it
/// never gets rewritten after the fact. So a row logged as DROP before you
/// set an allow rule would stay a stale DROP forever if we just displayed
/// the stored status. Instead, for anything not currently pending, this
/// recomputes what would happen *right now* under the current rules
/// (port-specific override first, else the app's whole-app default) and
/// only falls back to the stored status if nothing matches at all — this
/// is what makes the Flow pane self-correct after a reconnect instead of
/// showing decisions you already made as reverted. The row's own peer name
/// is what host rules are matched against, so a host rule shows up here on
/// exactly the rows it will actually apply to.
fn effective_status(e: &FlowWire, app_rules: &[AppRule]) -> FlowStatus {
    if matches!(e.status, FlowStatus::Pending) {
        return FlowStatus::Pending;
    }
    match_rule(
        app_rules,
        &e.exe,
        e.port,
        Some(e.direction),
        e.peer_name.as_deref(),
    )
        .map(|r| FlowStatus::from(r.action))
        .unwrap_or(e.status)
}

/// force this app to allow/deny everything, whether or not it already had a
/// rule — works on a brand-new "asking" app too, so you never *have* to go
/// through the flow pane to make a call
fn apps_set_verdict(app: &mut App, action: Action) {
    let Some(exe) = app
        .apps_state
        .selected()
        .and_then(|i| app.apps.get(i))
        .map(|r| r.exe.clone())
    else {
        return;
    };
    let Some(ipc) = &mut app.ipc else { return };
    ipc.send(&ClientMsg::SetAppRule {
        exe: exe.clone(),
        port: None,
        direction: None,
        action,
        expires: None,
        host: None,
    });
    cascade_flow_rows(app, action, |e| e.exe == exe);
}

fn apps_toggle_selected(app: &mut App) {
    let Some(id) = app
        .apps_state
        .selected()
        .and_then(|i| app.apps.get(i))
        .and_then(|r| r.rule.as_ref())
        .map(|r| r.id)
    else {
        app.msg = "no rule yet — decide its request in the flow pane first".into();
        return;
    };
    let Some(ipc) = &mut app.ipc else { return };
    ipc.send(&ClientMsg::ToggleAppRule { id });
}

/// forgets an app entirely: drops its rule (if any — future connections go
/// back through the ask flow, they never silently bypass since the fail-
/// closed default in ruleset.rs still applies) and clears its local flow
/// history so it disappears from Apps/Flow until it actually asks again
fn apps_delete_selected(app: &mut App) {
    let Some(row) = app.apps_state.selected().and_then(|i| app.apps.get(i)) else {
        return;
    };
    let exe = row.exe.clone();
    let Some(ipc) = &mut app.ipc else { return };
    // removes every rule for this app — whole-app default and all per-port
    // overrides — not just the one shown on this row
    ipc.send(&ClientMsg::RmAppRule { exe: exe.clone() });

    app.flow.retain(|e| e.exe != exe);
    rebuild_apps(app);
    reset_flow_selection(app);
}

fn flow_select(app: &mut App, back: bool) {
    let len = current_flow_indices(app).len();
    app.flow_state
        .select(step(app.flow_state.selected(), len, back));
}

/// on a still-pending request this verdicts the actual held packet (the
/// daemon persists it as a per-port rule); on an already-resolved history
/// entry there's no packet left to verdict, so it just (re)sets that port's
/// rule — this is how you flip an earlier deny back to allow, or vice versa
fn flow_decide(app: &mut App, verdict: Action) {
    let idxs = current_flow_indices(app);
    let Some(sel) = app.flow_state.selected() else {
        return;
    };
    let Some(&real_idx) = idxs.get(sel) else {
        return;
    };
    let Some(entry) = app.flow.get(real_idx) else {
        return;
    };
    let exe = entry.exe.clone();
    let port = entry.port;
    let direction = entry.direction;
    let was_pending = matches!(entry.status, FlowStatus::Pending);
    let req_id = entry.req_id;
    let Some(ipc) = &mut app.ipc else { return };

    if was_pending {
        let Some(req_id) = req_id else { return };
        ipc.send(&ClientMsg::Decide { req_id, verdict });
    } else {
        ipc.send(&ClientMsg::SetAppRule {
            exe: exe.clone(),
            port,
            direction: Some(direction),
            action: verdict,
            expires: None,
            host: None,
        });
    }
    // the rule covers this app's OTHER rows on the SAME port and direction
    // too (per-port control, never the whole app — that's Apps' job)
    cascade_flow_rows(app, verdict, |e| {
        e.exe == exe && e.port == port && e.direction == direction
    });
}

/// `Y`/`N` in the Flow pane: rule the *destination* rather than the port —
/// every connection this app makes to the name the selected row resolved
/// to, on any port, in either direction. The exact name is used, not a
/// guessed `*.` wildcard: widening "block tracker.ads.net" into "block
/// everything under ads.net" is a call only the user can make, and
/// `guardit app deny <exe> --host '*.ads.net'` is how they make it.
fn flow_decide_host(app: &mut App, verdict: Action) {
    let idxs = current_flow_indices(app);
    let entry = app
        .flow_state
        .selected()
        .and_then(|sel| idxs.get(sel).copied())
        .and_then(|i| app.flow.get(i));
    let Some(entry) = entry else { return };
    let exe = entry.exe.clone();
    let Some(host) = entry.peer_name.clone() else {
        app.msg = "no resolved name for this peer — the DNS tap never saw its lookup".into();
        return;
    };
    let Some(ipc) = &mut app.ipc else { return };
    ipc.send(&ClientMsg::SetAppRule {
        exe: exe.clone(),
        port: None,
        direction: None,
        action: verdict,
        expires: None,
        host: Some(host.clone()),
    });
    // a host rule beats port and direction (config::match_rule), so it takes
    // over every row of this app that reached the same name, whatever port
    cascade_flow_rows(app, verdict, |e| {
        e.exe == exe && e.peer_name.as_deref() == Some(host.as_str())
    });
}

/// stable, deterministic order shared by draw_conflicts and the
/// select/decide functions below, which index into `app.listening` directly
fn sort_listening(entries: &mut [ipc::ListenEntry]) {
    entries.sort_by(|a, b| {
        (a.proto.as_str(), a.port, a.addr.as_str()).cmp(&(
            b.proto.as_str(),
            b.port,
            b.addr.as_str(),
        ))
    });
}

fn conflicts_select(app: &mut App, back: bool) {
    app.conflicts_state.select(step(
        app.conflicts_state.selected(),
        app.listening.len(),
        back,
    ));
}

/// per-port, same as the Flow pane — a listening-port entry is one specific
/// port, so deciding it must not touch the app's whole-app default or its
/// other ports (that's Apps pane's job)
fn conflicts_decide(app: &mut App, action: Action) {
    let Some(entry) = app
        .conflicts_state
        .selected()
        .and_then(|i| app.listening.get(i))
    else {
        return;
    };
    let exe = entry.exe.clone();
    let port = Some(entry.port);
    let Some(ipc) = &mut app.ipc else { return };
    // a listening socket is only ever reached inbound
    ipc.send(&ClientMsg::SetAppRule {
        exe: exe.clone(),
        port,
        direction: Some(Direction::In),
        action,
        expires: None,
        host: None,
    });
    cascade_flow_rows(app, action, |e| {
        e.exe == exe && e.port == port && e.direction == Direction::In
    });
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let theme = THEMES[app.theme_idx];
    // paint the whole frame first so the gaps between panes pick up the
    // theme's background too, not just the widgets themselves
    f.render_widget(Paragraph::new("").style(theme.base()), area);

    let outer = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, app, outer[0]);
    if in_log_tab(app.focus) {
        // its own tab over the whole grid area: the audit trail and the
        // listening ports, which answer the same "what has been going on"
        // question and are both wider than a grid cell
        let cols =
            Layout::horizontal([Constraint::Percentage(64), Constraint::Percentage(36)])
                .split(outer[1]);
        draw_app_log(f, app, cols[0]);
        draw_conflicts(f, app, cols[1]);
    } else {
        // bento grid: all panes always visible, Tab/Shift+Tab just moves the
        // highlighted border — nothing goes full-screen/modal otherwise. Fill
        // (not Percentage) so the halves are exactly equal — no rounding
        // drift between panes, which is what breaks top/bottom alignment
        // across columns.
        // The blocklists get the right-hand column outright, top to bottom:
        // it is the one subject that is purely read, and it has the most to
        // say per row. What is left is split into a top band — the rules the
        // kernel holds, and what the machine has been doing — over the pane
        // you actually work in, which spans that whole width because a flow
        // row is a whole record and every column of it is worth reading.
        let [work, blocking] =
            Layout::horizontal([Constraint::Percentage(74), Constraint::Percentage(26)])
                .areas(outer[1]);
        let [top, bottom] =
            Layout::vertical([Constraint::Percentage(52), Constraint::Percentage(48)])
                .areas(work);
        let [rules, top_apps] =
            Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
                .areas(top);
        draw_rules(f, app, rules);
        draw_top_apps(f, app, top_apps);
        // the divider reproduces the seam above it — the two adjacent border
        // columns where System rules ends and Top apps begins — so the two
        // halves sit under the panes they belong with: the app list under
        // the rules, its flow under what the machine has been doing
        draw_app_control(f, app, bottom, rules.right().saturating_sub(1));
        draw_blocking(f, app, blocking);
    }

    draw_footer(f, app, outer[2]);
}

/// per-pane identity color, in the same order as Theme.accents
fn focus_accent(focus: Focus, theme: Theme) -> Color {
    match focus {
        Focus::Rules => theme.accents[0],
        Focus::Apps => theme.accents[1],
        Focus::Conflicts => theme.accents[2],
        Focus::Flow => theme.accents[4],
        Focus::AppLog => theme.chart,
    }
}

/// static, starship-style status line: a colored "where you are" segment
/// plus the keys that apply right now. Never repeats transient "did X"
/// state — only an error (`app.msg`) gets appended, until the next key.
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let base = theme.base();

    if matches!(app.mode, Mode::Filter | Mode::LogFilter) {
        let (label, buf) = if matches!(app.mode, Mode::Filter) {
            (" FILTER APPS ", &app.apps_filter)
        } else {
            (" FILTER LOG — port, ip or name ", &app.log_filter)
        };
        let spans = vec![
            Span::styled(
                label,
                Style::new()
                    .bg(theme.accents[1])
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Enter keep · Esc clear  ", base),
            Span::styled(format!("> {buf}"), base.add_modifier(Modifier::BOLD)),
        ];
        f.render_widget(Paragraph::new(Line::from(spans)).style(base), area);
        return;
    }

    if let Mode::Add(buf) = &app.mode {
        let spans = vec![
            Span::styled(
                " ADD RULE ",
                Style::new()
                    .bg(theme.accents[0])
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" <allow|deny> <tcp|udp|any> <src|any> <port|->  ", base),
            Span::styled(format!("> {buf}"), base.add_modifier(Modifier::BOLD)),
        ];
        f.render_widget(Paragraph::new(Line::from(spans)).style(base), area);
        return;
    }

    let focus_label = match app.focus {
        Focus::Rules => "RULES",
        Focus::Apps => "APPS",
        Focus::Conflicts => "LISTEN",
        Focus::Flow => "FLOW",
        Focus::AppLog => "LOG",
    };
    let focus_color = focus_accent(app.focus, theme);
    let mut keys: Vec<(&str, &str)> = match (app.focus, &app.mode) {
        (Focus::Apps, _) => vec![
            ("Tab", "pane"),
            ("j/k", "select"),
            ("Enter", "flow"),
            ("l", "audit"),
            ("y/n", "allow/deny app"),
            ("space", "toggle"),
            ("d", "remove"),
            ("/", "filter"),
        ],
        (Focus::Flow, _) => vec![
            ("Tab", "pane"),
            ("j/k", "select"),
            ("l", "audit"),
            ("y/n", "allow/deny port"),
            ("Y/N", "allow/deny host"),
        ],
        (Focus::Conflicts, _) => vec![
            ("Tab", "log"),
            ("j/k", "select"),
            ("l", "this app"),
            ("y/n", "allow/deny port"),
        ],
        (Focus::AppLog, _) if app.app_log_confirm_flush => {
            vec![("y", "confirm flush"), ("n", "cancel")]
        }
        (Focus::AppLog, _) => vec![
            ("Tab", "ports"),
            ("j/k", "move"),
            ("/", "filter"),
            ("f", "flush"),
        ],
        (Focus::Rules, Mode::Preset(_)) => {
            vec![("j/k", "move"), ("Enter", "add"), ("Esc", "cancel")]
        }
        (Focus::Rules, _) => vec![
            ("Tab", "pane"),
            ("j/k", "move"),
            ("space", "toggle"),
            ("d", "delete"),
            ("a", "add"),
            ("p", "presets"),
        ],
    };
    let in_tab = in_log_tab(app.focus);
    if !in_tab {
        keys.push(("A", "audit"));
    }
    keys.push(("t", "theme"));
    if !(in_tab && app.app_log_confirm_flush) {
        keys.push(("q", if in_tab { "back" } else { "quit" }));
    }

    let mut spans = vec![Span::styled(
        format!(" {focus_label} "),
        Style::new()
            .bg(focus_color)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    )];
    for (key, desc) in keys {
        spans.push(Span::styled("  ", base));
        spans.push(Span::styled(
            key,
            base.fg(focus_color).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(" ", base));
        spans.push(Span::styled(desc, base));
    }
    if !app.msg.is_empty() {
        spans.push(Span::styled(
            format!("   {}", app.msg),
            base.fg(theme.deny).add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(base), area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let daemon = if app.ipc.is_some() {
        "connected"
    } else {
        "not reachable — per-app control off (sudo guardit daemon)"
    };
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(4)]).split(area);
    let ifaces = if app.interfaces.is_empty() {
        "none detected".to_string()
    } else {
        app.interfaces.join(", ")
    };
    let theme = THEMES[app.theme_idx];
    let status = format!(
        "guardit  |  if: {ifaces}  |  daemon: {daemon}  |  theme: {} (t)",
        theme.name
    );
    f.render_widget(
        Paragraph::new(status).style(theme.base().add_modifier(Modifier::BOLD)),
        rows[0],
    );

    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let (down, up) = app.net_rate_kbps;
    draw_throughput_spark(f, cols[0], "\u{2193} down", down, &app.net_hist_down, theme);
    draw_throughput_spark(f, cols[1], "\u{2191} up", up, &app.net_hist_up, theme);
}

fn draw_throughput_spark(
    f: &mut Frame,
    area: Rect,
    label: &str,
    current: f64,
    history: &VecDeque<u64>,
    theme: Theme,
) {
    let data: Vec<u64> = history.iter().copied().collect();
    let sparkline = Sparkline::default()
        .style(Style::new().fg(theme.chart).bg(theme.bg))
        .data(&data)
        .block(
            theme
                .pane(format!("{label}  {current:.1} KB/s"), false)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(sparkline, area);
}

/// full-screen — its own tab, not squeezed into the bento grid; a detail
/// drill-down view genuinely needs the room these 7 columns take
fn draw_app_log(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let now = now_ts();
    let rows: Vec<Row> = app
        .app_log
        .iter()
        .map(|e| {
            let ago = ago(now.saturating_sub(e.ts));
            let (status, color) = match e.status {
                FlowStatus::Allowed => ("allow", theme.allow),
                FlowStatus::Denied => ("deny", theme.deny),
                FlowStatus::Pending => ("pending", theme.warn),
            };
            Row::new(vec![
                Cell::from(ago),
                Cell::from(e.direction.as_str()),
                Cell::from(basename(&e.exe).to_string()),
                Cell::from(e.proto.clone()),
                Cell::from(e.port.map(|p| p.to_string()).unwrap_or_default()),
                Cell::from(e.peer()),
                Cell::from(status),
            ])
            .style(Style::new().fg(color))
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(24),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(18),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["AGO", "DIR", "EXE", "PROTO", "PORT", "PEER", "STATUS"])
            .style(Style::new().fg(theme.fg).add_modifier(Modifier::BOLD)),
    )
    .style(theme.base())
    .row_highlight_style(Style::new().bg(theme.border_idle))
    .block(theme.pane(
        {
            let scope = match &app.app_log_filter {
                Some(exe) => basename(exe).to_string(),
                None => "full audit trail".to_string(),
            };
            let needle = if app.log_filter.is_empty() {
                String::new()
            } else {
                format!(" /{}", app.log_filter)
            };
            format!("audit — {scope}{needle} ({} entries)", app.app_log.len())
        },
        app.focus == Focus::AppLog,
    ));
    f.render_stateful_widget(table, area, &mut app.app_log_state);

    if app.app_log_confirm_flush {
        draw_confirm_flush(f, app, area);
    }
}

/// small centered dialog over the app log — y/n, nothing else responds while it's up
fn draw_confirm_flush(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let [popup] = Layout::horizontal([Constraint::Length(44)])
        .flex(Flex::Center)
        .areas(area);
    let [popup] = Layout::vertical([Constraint::Length(3)])
        .flex(Flex::Center)
        .areas(popup);
    let text = Paragraph::new("flush the whole log? this can't be undone  y/n")
        .alignment(Alignment::Center)
        .style(
            Style::new()
                .bg(theme.deny)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::new().bg(theme.deny).fg(Color::Black))
                .border_type(BorderType::Thick),
        );
    f.render_widget(ratatui::widgets::Clear, popup);
    f.render_widget(text, popup);
}

fn draw_rules(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let focused = app.focus == Focus::Rules;
    match &mut app.mode {
        Mode::Preset(sel) => {
            let items: Vec<ListItem> = PRESETS
                .iter()
                .enumerate()
                .map(|(i, (label, spec))| {
                    let text = format!("{label}   [{spec}]");
                    let style = if i == *sel {
                        Style::new().fg(Color::Black).bg(theme.chart)
                    } else {
                        Style::new().fg(theme.fg)
                    };
                    ListItem::new(text).style(style)
                })
                .collect();
            let list = List::new(items)
                .style(theme.base())
                .block(theme.pane("pick a preset".into(), focused));
            f.render_widget(list, area);
        }
        _ => {
            let items: Vec<ListItem> = app
                .cfg
                .rule
                .iter()
                .map(|r| {
                    let color = if !r.enabled {
                        theme.border_idle
                    } else if r.action == Action::Allow {
                        theme.allow
                    } else {
                        theme.deny
                    };
                    // two lines, not one: the source is the identifying half
                    // of a rule and this pane is the narrow column, so a
                    // single line would truncate exactly the part you read.
                    // Height is what the column has to spare
                    ListItem::new(vec![
                        Line::from(format!(
                            "#{:<3} {:<6} {}{}",
                            r.id,
                            format!("{:?}", r.action).to_uppercase(),
                            format!("{:?}", r.proto).to_lowercase(),
                            if r.enabled { "" } else { "  (off)" },
                        )),
                        Line::from(format!(
                            "  {}{}",
                            r.src,
                            r.port.map(|p| format!(":{p}")).unwrap_or_default(),
                        )),
                    ])
                    .style(Style::new().fg(color))
                })
                .collect();
            let list = List::new(items)
                .style(theme.base())
                .highlight_style(Style::new().bg(theme.border_idle))
                .block(theme.pane("system rules".into(), focused));
            f.render_stateful_widget(list, area, &mut app.state);
        }
    }
}

fn draw_apps(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let width = area.width;
    let items: Vec<ListItem> = app
        .apps
        .iter()
        .map(|row| {
            // allow/deny and enabled/disabled are two separate axes — space
            // toggles enabled, y/n sets allow/deny, and neither should ever
            // hide the other: a disabled rule still shows what it *would*
            // do, just dimmed with "(off)" appended, instead of a generic
            // "(disabled)" that threw the allow/deny info away
            let (dot, base_color, mut status) = match &row.rule {
                Some(r) if r.action == Action::Allow => ("●", theme.allow, "(allow)".to_string()),
                Some(_) => ("●", theme.deny, "(deny)".to_string()),
                None => ("●", theme.warn, "(new)".to_string()),
            };
            let disabled = matches!(&row.rule, Some(r) if !r.enabled);
            let color = if disabled {
                theme.border_idle
            } else {
                base_color
            };
            if disabled {
                status.push_str(" (off)");
            }
            if let Some(t) = row.rule.as_ref().and_then(|r| r.expires) {
                status.push_str(&format!(" ⏱{}", ago(t.saturating_sub(now_ts()))));
            }
            // exe identity is just a path (see config::AppRule docs) — an
            // app that got reinstalled/updated to a different binary path
            // (common for Flatpak, AppImage, some auto-updaters) leaves a
            // rule pointing at nothing; flag it instead of pretending it's
            // still meaningful
            // "flatpak:…" / "snap:…" identities aren't paths (daemon::app_identity)
            let missing = row.exe.starts_with('/') && !Path::new(&row.exe).exists();
            if missing {
                status.push_str(" [gone]");
            } else if row.rule.as_ref().is_some_and(|r| r.stale()) {
                // binary changed since the rule was made — the daemon will
                // ask again on its next connection (config::AppRule::stale)
                status.push_str(" [changed]");
            }
            // this default doesn't tell the whole story if some of the app's
            // ports have their own override — say so instead of looking wrong
            if row.port_overrides > 0 {
                status.push_str(&format!(" +{}p", row.port_overrides));
            }
            let style = if missing {
                Style::new().fg(color).add_modifier(Modifier::CROSSED_OUT)
            } else {
                Style::new().fg(color)
            };
            // a name longer than the column gets truncated (not just padded) —
            // otherwise one long app name pushes its own status out of line
            // with every other row's, defeating the whole point of padding.
            // The column shrinks with the pane so the status, which is the
            // part you are actually reading, never falls off the edge
            let name = basename(&row.exe);
            let col = (width as usize).saturating_sub(10).clamp(6, 18);
            let name_col = if name.chars().count() > col {
                format!("{}…", name.chars().take(col - 1).collect::<String>())
            } else {
                format!("{name:<col$}")
            };
            ListItem::new(format!("{dot} {name_col} {status}")).style(style)
        })
        .collect();
    let heading = if app.apps_filter.is_empty() {
        format!("apps ({})", app.apps.len())
    } else {
        format!("apps — /{} ({} shown)", app.apps_filter, app.apps.len())
    };
    let [head, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(heading).style(half_heading(theme, app.focus == Focus::Apps)),
        head,
    );
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(Style::new().bg(theme.border_idle));
    f.render_stateful_widget(list, body, &mut app.apps_state);
}

/// the two halves of the app-control pane label themselves, since they share
/// one border: the focused one is bold in its own accent, the other is quiet
fn half_heading(theme: Theme, focused: bool) -> Style {
    if focused {
        theme
            .base()
            .fg(theme.border_focus)
            .add_modifier(Modifier::BOLD)
    } else {
        theme.base().fg(theme.border_idle)
    }
}

/// Application blocking: the app list and that app's live flow, one pane
/// split by a vertical rule.
///
/// They are one subject — you pick an app on the left and rule on what it is
/// doing on the right — and the flow pane is meaningless without knowing
/// which app it is showing, so a shared border says that better than two
/// separate ones did. Both halves stay in the Tab ring; the border lights up
/// for either.
///
/// `divider_x` is the absolute column the rule starts at, so it can be lined
/// up with a pane boundary elsewhere on the screen rather than falling
/// wherever a percentage of this pane happens to land. The rule is two
/// columns wide because the seam it continues is: two panes side by side
/// meet as two adjacent border columns, and a single line under them would
/// sit half a pane off. Clamped to leave a usable column on each side.
fn draw_app_control(f: &mut Frame, app: &mut App, area: Rect, divider_x: u16) {
    let theme = THEMES[app.theme_idx];
    let focused = matches!(app.focus, Focus::Apps | Focus::Flow);
    let block = theme.pane("application blocking".into(), focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 6 || inner.height == 0 {
        return;
    }
    // the divider is a column of its own so neither list ever draws over it
    const RULE_W: u16 = 2;
    let divider_x = divider_x.clamp(inner.x + 1, inner.right().saturating_sub(RULE_W + 1));
    let [left, rule, right] = Layout::horizontal([
        Constraint::Length(divider_x - inner.x),
        Constraint::Length(RULE_W),
        Constraint::Min(0),
    ])
    .areas(inner);
    draw_apps(f, app, left);
    f.render_widget(
        Block::new()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::new().fg(theme.border_idle))
            .style(theme.base()),
        rule,
    );
    draw_flow(f, app, right);
}

/// top apps by how many flow entries they've generated this session —
/// a quick "who's the most active/chatty" glance, not a rule-editing view
/// A total in at most five columns, so it always fits over its own bar
/// however narrow the bar is: 12345 -> "12k", 5_400_000 -> "5.4M".
///
/// The ranges are cut just below each rounding boundary rather than at it,
/// so 999_999 reads "1.0M" and never "1000k".
fn compact(n: u64) -> String {
    const UNITS: [&str; 7] = ["", "k", "M", "G", "T", "P", "E"];
    if n < 10_000 {
        return n.to_string();
    }
    let mut v = n as f64;
    let mut unit = 0;
    // step up *before* the value would round to four digits, so 999_999
    // reads "1.0M" and never "1000k"
    while v >= 999.95 && unit + 1 < UNITS.len() {
        v /= 1000.0;
        unit += 1;
    }
    let suffix = UNITS[unit];
    if v < 10.0 {
        format!("{v:.1}{suffix}")
    } else {
        format!("{v:.0}{suffix}")
    }
}

fn draw_top_apps(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let mut top: Vec<(&str, u64)> = app.counts.iter().map(|(e, &c)| (e.as_str(), c)).collect();
    top.sort_by_key(|&(exe, c)| (Reverse(c), exe));

    // the block is rendered separately from the chart so a row of totals can
    // sit between the two: BarChart draws its own value text *inside* the
    // bar, which is exactly what we don't want (see the bar_width comment)
    let block = theme.pane("top apps — connection attempts, all time".into(), false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [totals_area, chart_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);

    // every app, always — bar width adapts to how many there are instead of
    // truncating the list, so it never silently hides an app
    let n = top.len().max(1) as u16;
    let bar_gap: u16 = 1;
    let bar_width = ((inner.width.saturating_sub(n.saturating_sub(1) * bar_gap)) / n).clamp(3, 9);

    // the totals line is laid out on exactly the chart's own geometry —
    // bar_width wide per app, bar_gap between — so each number lands over
    // the bar it belongs to instead of drifting off by a column
    let totals: String = top
        .iter()
        .map(|(_, count)| {
            let text = compact(*count);
            let w = bar_width as usize;
            if text.chars().count() >= w {
                text
            } else {
                format!("{text:^w$}")
            }
        })
        .collect::<Vec<_>>()
        .join(&" ".repeat(bar_gap as usize));
    f.render_widget(
        Paragraph::new(Line::from(totals)).style(theme.base().fg(theme.chart)),
        totals_area,
    );

    // no in-bar digit: a number glyph drawn inside a solid block bar breaks
    // the bar's straight top edge (worst offender: "7", its shape reads as
    // a notch/hump). The count now lives above the bar, so the label under
    // it is just the name
    let bars: Vec<Bar> = top
        .iter()
        .map(|(exe, count)| {
            Bar::default()
                .value(*count)
                .label(Line::from(basename(exe).to_string()))
                .text_value(String::new())
                .style(Style::new().fg(theme.chart))
        })
        .collect();

    let chart = BarChart::default()
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(bar_gap)
        .label_style(Style::new().fg(theme.fg))
        .style(theme.base());
    f.render_widget(chart, chart_area);
}

/// 1234567 -> "1 234 567" — a raw run of digits is the one thing on this
/// dashboard you actually have to read a number off, so it gets separators
fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// A one-row stacked bar: blocked on the left in the deny colour, allowed on
/// the right in the allow colour, sized to `area.width`.
///
/// A proportion in a column this narrow is easier to read across than around
/// — the bar carries the split, and the figures under it carry the numbers.
/// Each side is given at least one cell whenever it is non-zero, so a rate
/// too small to round up to a cell still shows as present rather than as
/// nothing at all.
fn stacked_bar(width: u16, blocked: u64, allowed: u64, theme: Theme) -> Line<'static> {
    let width = width as usize;
    let total = blocked + allowed;
    if width == 0 {
        return Line::from("");
    }
    if total == 0 {
        return Line::from(Span::styled(
            "░".repeat(width),
            Style::new().fg(theme.border_idle),
        ));
    }
    let mut n = (blocked as f64 / total as f64 * width as f64).round() as usize;
    n = n.clamp(usize::from(blocked > 0), width - usize::from(allowed > 0));
    Line::from(vec![
        Span::styled("█".repeat(n), Style::new().fg(theme.deny)),
        Span::styled("█".repeat(width - n), Style::new().fg(theme.allow)),
    ])
}

/// The ads / tracking column: everything the blocklists are doing.
///
/// Splits `n` rows off the top of `rest`, leaving the remainder behind —
/// None when there aren't that many, which is how a pane drops an element
/// whole instead of drawing it clipped.
fn take_rows(rest: &mut Rect, n: u16) -> Option<Rect> {
    if rest.height < n || n == 0 {
        return None;
    }
    let [got, left] = Layout::vertical([Constraint::Length(n), Constraint::Min(0)]).areas(*rest);
    *rest = left;
    Some(got)
}

/// Three views of the same thing, stacked down the column. A bar for the
/// split of DNS lookups blocked vs allowed — proportion, read across. A
/// sparkline of blocks per five-second window — trend, which the split
/// cannot show. Then every figure under its own label, and the names most
/// recently blocked, which is where a false positive announces itself the
/// moment a page breaks.
fn draw_blocking(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let b = &app.blocklist;
    let block = theme.pane(
        if b.enabled {
            "ads & tracking".to_string()
        } else {
            "ads & tracking — off".to_string()
        },
        false,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    if !b.enabled {
        let dim = Style::new().fg(theme.border_idle);
        let hint = vec![
            Line::from(""),
            Line::from(Span::styled(
                "blocking is off",
                Style::new().fg(theme.warn).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("sudo guardit blocklist on"),
            Line::from("sudo guardit blocklist update"),
            Line::from(""),
            Line::from(Span::styled("ads, trackers and telemetry", dim)),
            Line::from(Span::styled("are refused at the DNS", dim)),
            Line::from(Span::styled("answer, before anything", dim)),
            Line::from(Span::styled("connects", dim)),
        ];
        f.render_widget(Paragraph::new(hint).style(theme.base()), inner);
        return;
    }

    let allowed = b.queries.saturating_sub(b.blocked);
    let rate = if b.queries == 0 {
        0.0
    } else {
        b.blocked as f64 / b.queries as f64 * 100.0
    };

    let dim = Style::new().fg(theme.border_idle);

    // Rows are handed out in order of what you would miss most if it were
    // gone, and each element is skipped whole rather than drawn clipped:
    // the split first, then the figures, then the trend, then the names.
    // A short pane loses the tail; it never loses the top.
    let mut rest = inner;

    if let Some(area) = take_rows(&mut rest, 2) {
        let [head, bar] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("blocked ", dim),
                Span::styled(
                    format!("{rate:.1}%"),
                    Style::new().fg(theme.deny).add_modifier(Modifier::BOLD),
                ),
            ]))
            .style(theme.base()),
            head,
        );
        f.render_widget(
            Paragraph::new(stacked_bar(bar.width, b.blocked, allowed, theme))
                .style(theme.base()),
            bar,
        );
    }

    // trend: one bar per sampling window, which the split above cannot show
    if let Some(area) = take_rows(&mut rest, 3) {
        let [label, spark] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        f.render_widget(
            Paragraph::new(Span::styled("blocks per 5s", dim)).style(theme.base()),
            label,
        );
        // newest on the right, only as many windows as there are columns
        let n = spark.width as usize;
        let data: Vec<u64> = app
            .blocked_hist
            .iter()
            .skip(app.blocked_hist.len().saturating_sub(n))
            .copied()
            .collect();
        f.render_widget(
            Sparkline::default()
                .data(&data)
                .style(Style::new().fg(theme.deny).bg(theme.bg)),
            spark,
        );
    }

    let figure = |dot_color: Color, label: &str, value: String| {
        [
            Line::from(vec![
                Span::styled("● ", Style::new().fg(dot_color)),
                Span::styled(label.to_string(), dim),
            ]),
            Line::from(Span::styled(
                format!("  {value}"),
                Style::new().fg(dot_color).add_modifier(Modifier::BOLD),
            )),
        ]
    };
    let mut lines: Vec<Line> = Vec::new();
    lines.extend(figure(theme.fg, "lookups", group(b.queries)));
    lines.extend(figure(theme.deny, "blocked", group(b.blocked)));
    lines.extend(figure(theme.allow, "allowed", group(allowed)));
    // the three counters get a line each for their number, as the headline
    // figures; what the lists themselves are doing is state, not a quantity
    // you read off, so it pairs up onto two lines
    lines.push(Line::from(vec![
        Span::styled("lists ", dim),
        Span::styled(b.sources.len().to_string(), Style::new().fg(theme.fg)),
        Span::styled(" · domains ", dim),
        Span::styled(group(b.domains as u64), Style::new().fg(theme.fg)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("updated ", dim),
        Span::styled(
            match b.updated_at {
                // no " ago" — this line pairs two facts in a narrow column,
                // and the word is the first thing that pushes it off the edge
                Some(t) => ago(now_ts().saturating_sub(t)),
                None => "never".into(),
            },
            Style::new().fg(if b.updated_at.is_some() {
                theme.fg
            } else {
                theme.warn
            }),
        ),
        Span::styled(" · dns ", dim),
        Span::styled(
            if b.encrypted_dns_blocked {
                "refused"
            } else {
                "bypassable"
            },
            Style::new().fg(if b.encrypted_dns_blocked {
                theme.allow
            } else {
                theme.warn
            }),
        ),
    ]));
    let figures_h = (lines.len() as u16).min(rest.height);
    if let Some(area) = take_rows(&mut rest, figures_h) {
        f.render_widget(Paragraph::new(lines).style(theme.base()), area);
    }

    let recent_area = rest;
    if recent_area.height < 2 {
        return;
    }
    let mut recent = vec![Line::from(Span::styled("recently blocked", dim))];
    if b.recent.is_empty() {
        recent.push(Line::from(Span::styled("nothing yet", dim)));
    } else {
        // newest first, and only as many as there are rows for
        let rows = recent_area.height.saturating_sub(1) as usize;
        for (ts, name) in b.recent.iter().rev().take(rows) {
            let age = ago(now_ts().saturating_sub(*ts));
            let width = recent_area.width as usize;
            let room = width.saturating_sub(age.chars().count() + 2);
            let name = if name.chars().count() > room && room > 1 {
                format!("{}…", name.chars().take(room - 1).collect::<String>())
            } else {
                name.clone()
            };
            recent.push(Line::from(vec![
                Span::styled(name, Style::new().fg(theme.deny)),
                Span::styled(format!(" {age}"), dim),
            ]));
        }
    }
    f.render_widget(Paragraph::new(recent).style(theme.base()), recent_area);
}

fn draw_flow(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let heading = match app.apps_state.selected().and_then(|i| app.apps.get(i)) {
        Some(row) => format!("flow — {}", basename(&row.exe)),
        None => "flow — select an app".to_string(),
    };
    let idxs = current_flow_indices(app);
    let items: Vec<ListItem> = idxs
        .iter()
        .filter_map(|&i| app.flow.get(i))
        .map(|e| {
            let status = effective_status(e, &app.app_rules);
            let (tag, color) = match status {
                FlowStatus::Pending => ("[ASK] ", theme.warn),
                FlowStatus::Allowed => ("[ UP ]", theme.allow),
                FlowStatus::Denied => ("[DROP]", theme.deny),
            };
            let text = format!(
                "{tag}  {:<4}/{:<4}  port {:<6}  {}",
                e.proto,
                e.direction.as_str(),
                e.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                e.peer(),
            );
            let mut style = Style::new().fg(color);
            if matches!(status, FlowStatus::Pending) {
                style = style.add_modifier(Modifier::BOLD);
            }
            ListItem::new(text).style(style)
        })
        .collect();
    let [head, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(heading).style(half_heading(theme, app.focus == Focus::Flow)),
        head,
    );
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(Style::new().bg(theme.border_idle));
    f.render_stateful_widget(list, body, &mut app.flow_state);
}

fn draw_conflicts(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    // real EADDRINUSE-style conflicts (see daemon::find_conflicts) — this
    // will almost always be empty, because the kernel already refuses the
    // losing bind() before it ever shows up here; that's the honest,
    // correct answer, not a bug in the detector
    let conflicts = daemon::find_conflicts(&app.listening);
    let conflicted: HashSet<&str> = conflicts
        .iter()
        .flat_map(|(a, b)| [a.exe.as_str(), b.exe.as_str()])
        .collect();

    let items: Vec<ListItem> = if app.listening.is_empty() {
        vec![ListItem::new(
            "no listening sockets seen yet (scanned every 5s)",
        )]
    } else {
        app.listening
            .iter()
            .map(|e| {
                let is_conflict = conflicted.contains(e.exe.as_str());
                let text = format!(
                    "{:<3} {:<15}:{:<5} {:<18}{}",
                    e.proto,
                    e.addr,
                    e.port,
                    basename(&e.exe),
                    if is_conflict { " [!]" } else { "" },
                );
                let style = if is_conflict {
                    Style::new().fg(theme.deny).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(theme.fg)
                };
                ListItem::new(text).style(style)
            })
            .collect()
    };
    let title = if conflicts.is_empty() {
        "listening ports".to_string()
    } else {
        format!("listening ports — {} REAL CONFLICT(S)", conflicts.len())
    };
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(Style::new().bg(theme.border_idle))
        .block(theme.pane(title, app.focus == Focus::Conflicts));
    f.render_stateful_widget(list, area, &mut app.conflicts_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn demo_flow(port: u16, ip: &str, name: Option<&str>, exe: &str) -> FlowWire {
        FlowWire {
            req_id: None,
            exe: exe.into(),
            direction: Direction::Out,
            proto: "tcp".into(),
            port: Some(port),
            peer_ip: ip.into(),
            peer_name: name.map(|n| n.into()),
            status: FlowStatus::Allowed,
            ts: 0,
        }
    }

    /// a populated App, for the render tests and for eyeballing a layout
    fn demo_app() -> App {
        let mut app = new_app(Config::default());
        app.blocklist = ipc::BlocklistStats {
            enabled: true,
            encrypted_dns_blocked: true,
            sources: vec!["hagezi:pro".into()],
            domains: 224_039,
            queries: 12_345,
            blocked: 2_345,
            recent: vec![
                (now_ts() - 400, "ads.doubleclick.net".into()),
                (now_ts() - 90, "telemetry.microsoft.com".into()),
                (now_ts() - 5, "graph.facebook.com".into()),
            ],
            updated_at: Some(now_ts() - 7200),
        };
        app.blocked_hist = (0..40).map(|i| (i * 7) % 13).collect();
        app.cfg.rule = vec![Rule {
            id: 1,
            action: Action::Allow,
            proto: Proto::Tcp,
            src: "192.168.1.0/24".into(),
            port: Some(22),
            enabled: true,
        }];
        for (exe, n) in [
            ("/usr/bin/firefox", 4210u64),
            ("/usr/bin/curl", 91),
            ("/usr/lib/thunderbird/thunderbird", 12),
        ] {
            app.counts.insert(exe.into(), n);
            app.flow
                .push(demo_flow(443, "140.82.121.4", Some("github.com"), exe));
            app.flow.push(demo_flow(80, "93.184.216.34", None, exe));
        }
        app.app_rules = vec![AppRule {
            id: 1,
            exe: "/usr/bin/firefox".into(),
            port: None,
            direction: None,
            action: Action::Allow,
            enabled: true,
            expires: None,
            fingerprint: None,
            host: None,
        }];
        rebuild_apps(&mut app);
        app.focus = Focus::Apps;
        app
    }

    #[test]
    fn a_numeric_log_filter_is_a_port_not_a_substring() {
        let e = demo_flow(443, "140.82.121.4", Some("github.com"), "/usr/bin/curl");
        assert!(log_row_matches(&e, "443"));
        assert!(!log_row_matches(&e, "44"), "not a prefix of the port");
        assert!(!log_row_matches(&e, "4"), "nor a digit inside the address");
        assert!(!log_row_matches(&e, "80"));
    }

    #[test]
    fn a_text_log_filter_matches_address_name_or_app() {
        let e = demo_flow(443, "140.82.121.4", Some("github.com"), "/usr/bin/curl");
        assert!(log_row_matches(&e, "140.82"));
        assert!(log_row_matches(&e, "github"));
        assert!(log_row_matches(&e, "GitHub.COM"), "case-insensitive");
        assert!(log_row_matches(&e, "curl"));
        assert!(!log_row_matches(&e, "gitlab"));
        // a row the tap never resolved still matches on its address
        let bare = demo_flow(443, "140.82.121.4", None, "/usr/bin/curl");
        assert!(log_row_matches(&bare, "140.82"));
        assert!(!log_row_matches(&bare, "github"));
    }

    #[test]
    fn totals_are_grouped_and_compacted() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1_234), "1 234");
        assert_eq!(group(1_234_567), "1 234 567");
        // the bar labels have four columns at most, whatever the count
        for n in [0, 9_999, 10_000, 999_999, 1_000_000, 9_999_999_999, u64::MAX] {
            assert!(compact(n).len() <= 5, "{n} -> {}", compact(n));
        }
        assert_eq!(compact(999), "999");
        assert_eq!(compact(12_345), "12k");
        assert_eq!(compact(999_999), "1.0M", "never rounds up into 1000k");
        assert_eq!(compact(5_400_000), "5.4M");
        assert_eq!(compact(9_999_999_999), "10.0G");
    }

    /// Draws every screen at a range of terminal sizes.
    ///
    /// The grid and the dashboard do their own Rect arithmetic — a ring that
    /// wants twice its height in columns, a totals row carved off a pane's
    /// inner area — and getting that wrong is a panic in ratatui, not a
    /// cosmetic problem. Small sizes are the point: that is where a
    /// saturating_sub that should have been one is found.
    #[test]
    fn every_screen_renders_at_any_terminal_size() {
        for (w, h) in [(200, 60), (120, 40), (80, 24), (60, 20), (40, 12), (20, 8)] {
            let mut app = demo_app();
            app.listening = vec![ipc::ListenEntry {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 22,
                exe: "/usr/bin/sshd".into(),
            }];
            app.counts.insert("/usr/bin/curl".into(), 1_234_567);
            rebuild_apps(&mut app);

            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for focus in [
                Focus::Rules,
                Focus::Apps,
                Focus::Flow,
                Focus::AppLog,
                Focus::Conflicts,
            ] {
                app.focus = focus;
                term.draw(|f| draw(f, &mut app))
                    .unwrap_or_else(|e| panic!("{focus:?} at {w}x{h}: {e}"));
            }
            // and the modal-ish states, which replace the footer
            app.focus = Focus::Apps;
            app.mode = Mode::Filter;
            app.apps_filter = "fire".into();
            term.draw(|f| draw(f, &mut app)).unwrap();
            app.focus = Focus::AppLog;
            app.mode = Mode::LogFilter;
            app.log_filter = "443".into();
            term.draw(|f| draw(f, &mut app)).unwrap();
            app.mode = Mode::Browse;
            app.app_log_confirm_flush = true;
            term.draw(|f| draw(f, &mut app)).unwrap();
        }
    }

    /// blocking off is a different pane entirely, and an empty ring is the
    /// one that divides by a zero total
    #[test]
    fn the_dashboard_renders_with_nothing_to_show() {
        let mut app = new_app(Config::default());
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        app.blocklist.enabled = true;
        term.draw(|f| draw(f, &mut app)).unwrap();
    }
}





