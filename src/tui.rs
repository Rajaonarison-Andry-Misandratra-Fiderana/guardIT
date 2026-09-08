use crate::config::{config_path, match_rule, Action, AppRule, Config, Proto, Rule};
use crate::ipc::{self, ClientMsg, FlowStatus, FlowWire, ServerMsg};
use crate::daemon;
use crate::ruleset;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, List, ListItem, ListState, Padding, Paragraph, Row, Sparkline, Table, TableState};
use ratatui::{Frame, Terminal};
use std::cmp::Reverse;
use std::collections::{HashSet, VecDeque};
use std::io::{stdout, BufReader, Read as _};
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
            (Style::new().fg(self.border_focus).add_modifier(Modifier::BOLD), BorderType::Thick)
        } else {
            (Style::new().fg(self.border_idle), BorderType::Plain)
        };
        Block::default().style(self.base()).borders(Borders::ALL).padding(Padding::horizontal(1)).border_style(border).border_type(kind).title(title).title_alignment(Alignment::Center)
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
        accents: [Color::Blue, Color::Green, Color::Magenta, Color::Yellow, Color::Cyan],
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
        accents: [Color::Rgb(139, 233, 253), Color::Rgb(80, 250, 123), Color::Rgb(255, 121, 198), Color::Rgb(241, 250, 140), Color::Rgb(189, 147, 249)],
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
        accents: [Color::Rgb(129, 161, 193), Color::Rgb(163, 190, 140), Color::Rgb(180, 142, 173), Color::Rgb(235, 203, 139), Color::Rgb(136, 192, 208)],
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
        accents: [Color::White, Color::White, Color::White, Color::White, Color::White],
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
    std::fs::read_to_string(theme_path()).ok().and_then(|s| THEMES.iter().position(|t| t.name == s.trim())).unwrap_or(0)
}

fn save_theme_idx(idx: usize) {
    if let Some(dir) = theme_path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(theme_path(), THEMES[idx].name);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Apps,
    Flow,
    Rules,
    Conflicts,
    /// the full audit trail — its own tab, rendered full-screen (not part of
    /// the bento grid, it needs the room) and jumpable to from anywhere via
    /// the global `L` key, same idea as `t` for theme
    AppLog,
}

// Tab order: system rules -> apps -> flow (live) -> listening ports, then
// back to rules. Top apps is informational only (nothing to focus), and
// AppLog is reached only via the global `L`/`l` keys — a drill-down, not a
// pane you'd casually cycle through.
impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Rules => Focus::Apps,
            Focus::Apps => Focus::Flow,
            Focus::Flow => Focus::Conflicts,
            Focus::Conflicts | Focus::AppLog => Focus::Rules,
        }
    }

    fn prev(self) -> Focus {
        match self {
            Focus::Rules | Focus::AppLog => Focus::Conflicts,
            Focus::Apps => Focus::Rules,
            Focus::Flow => Focus::Apps,
            Focus::Conflicts => Focus::Flow,
        }
    }
}

enum Mode {
    Browse,
    Add(String),
    Preset(usize),
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
        Some(IpcClient { reader: BufReader::new(stream), writer, buf: Vec::new() })
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
            let Some((iface, rest)) = line.split_once(':') else { continue };
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
    let Ok(text) = std::fs::read_to_string("/proc/net/dev") else { return Vec::new() };
    text.lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(iface, _)| iface.trim().to_string()))
        .filter(|iface| iface != "lo")
        .collect()
}

fn basename(exe: &str) -> &str {
    Path::new(exe).file_name().and_then(|s| s.to_str()).unwrap_or(exe)
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
    let port = if parts[3] == "-" {
        None
    } else {
        Some(parts[3].parse::<u16>().map_err(|_| "bad port".to_string())?)
    };
    Ok(Rule { id: 0, action, proto, src, port, enabled: true })
}

pub fn run(cfg: Config) {
    enable_raw_mode().expect("raw mode");
    stdout().execute(EnterAlternateScreen).expect("alt screen");
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).expect("terminal");

    let mut app = App {
        app_rules: cfg.app_rule.clone(),
        cfg,
        state: ListState::default(),
        apps: Vec::new(),
        apps_state: ListState::default(),
        flow: Vec::new(),
        flow_state: ListState::default(),
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
    };
    if !app.cfg.rule.is_empty() {
        app.state.select(Some(0));
    }
    rebuild_apps(&mut app);

    loop {
        terminal.draw(|f| draw(f, &mut app)).expect("draw");

        // no key ready within the tick → refresh live views instead of blocking
        if !event::poll(std::time::Duration::from_millis(500)).unwrap_or(false) {
            if app.focus == Focus::AppLog {
                app.app_log = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
                if app.app_log_state.selected().is_none() && !app.app_log.is_empty() {
                    app.app_log_state.select(Some(0));
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
                for (hist, rate) in [(&mut app.net_hist_down, app.net_rate_kbps.0), (&mut app.net_hist_up, app.net_rate_kbps.1)] {
                    hist.push_back(rate as u64);
                    while hist.len() > NET_HIST_CAP {
                        hist.pop_front();
                    }
                }
            }
            continue;
        }
        if let Event::Key(key) = event::read().expect("read event") {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            app.msg.clear();
            if (key.code == KeyCode::Tab || key.code == KeyCode::BackTab) && !matches!(app.mode, Mode::Add(_) | Mode::Preset(_)) {
                app.focus = if key.code == KeyCode::BackTab { app.focus.prev() } else { app.focus.next() };
                if app.apps_state.selected().is_none() && !app.apps.is_empty() {
                    app.apps_state.select(Some(0));
                    reset_flow_selection(&mut app);
                }
                continue;
            }
            if key.code == KeyCode::Char('t') && !matches!(app.mode, Mode::Add(_)) {
                app.theme_idx = (app.theme_idx + 1) % THEMES.len();
                save_theme_idx(app.theme_idx);
                continue;
            }
            // jumpable to from anywhere, same idea as `t` — the app log is
            // its own tab, not nested under any pane's local keys
            if key.code == KeyCode::Char('L') && !matches!(app.mode, Mode::Add(_)) {
                if app.focus == Focus::AppLog {
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
                        KeyCode::Char('k') | KeyCode::Up => *sel = (*sel + PRESETS.len() - 1) % PRESETS.len(),
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
                Focus::Apps => match key.code {
                    KeyCode::Char('q') => break,
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
                        if let Some(exe) = app.apps_state.selected().and_then(|i| app.apps.get(i)).map(|r| r.exe.clone()) {
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
                    KeyCode::Char('l') => {
                        if let Some(exe) = app.apps_state.selected().and_then(|i| app.apps.get(i)).map(|r| r.exe.clone()) {
                            open_app_log(&mut app, Some(exe));
                        }
                    }
                    _ => {}
                },
                Focus::Conflicts => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('j') | KeyCode::Down => conflicts_select(&mut app, false),
                    KeyCode::Char('k') | KeyCode::Up => conflicts_select(&mut app, true),
                    KeyCode::Char('y') => conflicts_decide(&mut app, Action::Allow),
                    KeyCode::Char('n') => conflicts_decide(&mut app, Action::Deny),
                    KeyCode::Char('l') => {
                        if let Some(exe) = app.conflicts_state.selected().and_then(|i| app.listening.get(i)).map(|e| e.exe.clone()) {
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
                        app.app_log = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
                        app.app_log_state.select(None);
                    }
                    KeyCode::Char('n') | KeyCode::Esc => app.app_log_confirm_flush = false,
                    _ => {}
                },
                Focus::AppLog => match key.code {
                    KeyCode::Char('q') => close_app_log(&mut app),
                    KeyCode::Char('f') => app.app_log_confirm_flush = true,
                    KeyCode::Char('j') | KeyCode::Down => app.app_log_state.select(step(app.app_log_state.selected(), app.app_log.len(), false)),
                    KeyCode::Char('k') | KeyCode::Up => app.app_log_state.select(step(app.app_log_state.selected(), app.app_log.len(), true)),
                    _ => {}
                },
            }
        }
    }

    disable_raw_mode().expect("disable raw mode");
    stdout().execute(LeaveAlternateScreen).expect("leave alt screen");
}

fn drain_ipc(app: &mut App) {
    let Some(ipc) = &mut app.ipc else { return };
    let msgs = ipc.poll();
    if msgs.is_empty() {
        return;
    }
    for msg in msgs {
        match msg {
            ServerMsg::Snapshot { app_rules, flow, listening } => {
                app.app_rules = app_rules;
                app.flow = flow;
                app.listening = listening;
                sort_listening(&mut app.listening);
            }
            ServerMsg::FlowNew(w) => app.flow.push(w),
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
    let selected_exe = app.apps_state.selected().and_then(|i| app.apps.get(i)).map(|r| r.exe.clone());

    let mut seen = HashSet::new();
    let mut rows: Vec<AppRow> = Vec::new();
    // whole-app defaults first so each app's row shows its default, never an
    // arbitrary per-port override; then apps that only have overrides
    let rules = &app.app_rules;
    for r in rules.iter().filter(|r| r.port.is_none()).chain(rules.iter()) {
        if seen.insert(r.exe.clone()) {
            let port_overrides = rules.iter().filter(|o| o.exe == r.exe && o.port.is_some()).count();
            rows.push(AppRow { exe: r.exe.clone(), rule: r.port.is_none().then(|| r.clone()), port_overrides });
        }
    }
    for e in &app.flow {
        if seen.insert(e.exe.clone()) {
            rows.push(AppRow { exe: e.exe.clone(), rule: None, port_overrides: 0 });
        }
    }
    rows.sort_by(|a, b| a.exe.cmp(&b.exe));
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
    let Some(exe) = app.apps_state.selected().and_then(|i| app.apps.get(i)).map(|r| r.exe.as_str()) else {
        return Vec::new();
    };
    let mut idxs: Vec<usize> = app.flow.iter().enumerate().filter(|(_, e)| e.exe == exe).map(|(i, _)| i).collect();
    idxs.reverse();
    idxs
}

fn reset_flow_selection(app: &mut App) {
    let idxs = current_flow_indices(app);
    app.flow_state.select(if idxs.is_empty() { None } else { Some(0) });
}

/// writes the IP/port rules under the shared config lock (see Config::update,
/// safe against a concurrent daemon write to app_rule), then applies
/// immediately — there's no separate "apply" step, every change takes
/// effect the moment you make it
fn save_rules(app: &mut App) {
    let rule = app.cfg.rule.clone();
    app.cfg = Config::update(|fresh| fresh.rule = rule);
    if !ruleset::is_root() {
        app.msg = "need root to apply (run guardit tui as sudo) — rule saved but not loaded".into();
        return;
    }
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
    app.state.select(step(app.state.selected(), app.cfg.rule.len(), false));
}

fn select_prev(app: &mut App) {
    app.state.select(step(app.state.selected(), app.cfg.rule.len(), true));
}

fn toggle_selected(app: &mut App) {
    if let Some(r) = app.state.selected().and_then(|i| app.cfg.rule.get_mut(i)) {
        r.enabled = !r.enabled;
        save_rules(app);
    }
}

fn delete_selected(app: &mut App) {
    if let Some(i) = app.state.selected()
        && i < app.cfg.rule.len() {
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
    if app.focus != Focus::AppLog {
        app.prev_focus = app.focus;
    }
    app.app_log_filter = filter;
    app.app_log_confirm_flush = false;
    app.focus = Focus::AppLog;
    app.app_log = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
    app.app_log_state.select(if app.app_log.is_empty() { None } else { Some(0) });
}

fn close_app_log(app: &mut App) {
    app.focus = app.prev_focus;
    app.app_log_filter = None;
    app.app_log_confirm_flush = false;
}

fn apps_select(app: &mut App, back: bool) {
    app.apps_state.select(step(app.apps_state.selected(), app.apps.len(), back));
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
            && let Some(req_id) = e.req_id {
                pending_req_ids.push(req_id);
            }
        e.status = new_status;
    }
    if let Some(ipc) = &mut app.ipc {
        for req_id in pending_req_ids {
            ipc.send(&ClientMsg::Decide { req_id, verdict: action });
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
/// showing decisions you already made as reverted.
fn effective_status(e: &FlowWire, app_rules: &[AppRule]) -> FlowStatus {
    if matches!(e.status, FlowStatus::Pending) {
        return FlowStatus::Pending;
    }
    match_rule(app_rules, &e.exe, e.port).map(FlowStatus::from).unwrap_or(e.status)
}

/// force this app to allow/deny everything, whether or not it already had a
/// rule — works on a brand-new "asking" app too, so you never *have* to go
/// through the flow pane to make a call
fn apps_set_verdict(app: &mut App, action: Action) {
    let Some(exe) = app.apps_state.selected().and_then(|i| app.apps.get(i)).map(|r| r.exe.clone()) else { return };
    let Some(ipc) = &mut app.ipc else { return };
    ipc.send(&ClientMsg::SetAppRule { exe: exe.clone(), port: None, action });
    cascade_flow_rows(app, action, |e| e.exe == exe);
}

fn apps_toggle_selected(app: &mut App) {
    let Some(id) = app.apps_state.selected().and_then(|i| app.apps.get(i)).and_then(|r| r.rule.as_ref()).map(|r| r.id) else {
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
    let Some(row) = app.apps_state.selected().and_then(|i| app.apps.get(i)) else { return };
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
    app.flow_state.select(step(app.flow_state.selected(), len, back));
}

/// on a still-pending request this verdicts the actual held packet (the
/// daemon persists it as a per-port rule); on an already-resolved history
/// entry there's no packet left to verdict, so it just (re)sets that port's
/// rule — this is how you flip an earlier deny back to allow, or vice versa
fn flow_decide(app: &mut App, verdict: Action) {
    let idxs = current_flow_indices(app);
    let Some(sel) = app.flow_state.selected() else { return };
    let Some(&real_idx) = idxs.get(sel) else { return };
    let Some(entry) = app.flow.get(real_idx) else { return };
    let exe = entry.exe.clone();
    let port = entry.port;
    let was_pending = matches!(entry.status, FlowStatus::Pending);
    let req_id = entry.req_id;
    let Some(ipc) = &mut app.ipc else { return };

    if was_pending {
        let Some(req_id) = req_id else { return };
        ipc.send(&ClientMsg::Decide { req_id, verdict });
    } else {
        ipc.send(&ClientMsg::SetAppRule { exe: exe.clone(), port, action: verdict });
    }
    // the rule covers this app's OTHER rows on the SAME port too (per-port
    // control, never the whole app — that's Apps' job)
    cascade_flow_rows(app, verdict, |e| e.exe == exe && e.port == port);
}

/// stable, deterministic order shared by draw_conflicts and the
/// select/decide functions below, which index into `app.listening` directly
fn sort_listening(entries: &mut [ipc::ListenEntry]) {
    entries.sort_by(|a, b| (a.proto.as_str(), a.port, a.addr.as_str()).cmp(&(b.proto.as_str(), b.port, b.addr.as_str())));
}

fn conflicts_select(app: &mut App, back: bool) {
    app.conflicts_state.select(step(app.conflicts_state.selected(), app.listening.len(), back));
}

/// per-port, same as the Flow pane — a listening-port entry is one specific
/// port, so deciding it must not touch the app's whole-app default or its
/// other ports (that's Apps pane's job)
fn conflicts_decide(app: &mut App, action: Action) {
    let Some(entry) = app.conflicts_state.selected().and_then(|i| app.listening.get(i)) else { return };
    let exe = entry.exe.clone();
    let port = Some(entry.port);
    let Some(ipc) = &mut app.ipc else { return };
    ipc.send(&ClientMsg::SetAppRule { exe: exe.clone(), port, action });
    cascade_flow_rows(app, action, |e| e.exe == exe && e.port == port);
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let theme = THEMES[app.theme_idx];
    // paint the whole frame first so the gaps between panes pick up the
    // theme's background too, not just the widgets themselves
    f.render_widget(Paragraph::new("").style(theme.base()), area);

    let outer = Layout::vertical([Constraint::Length(5), Constraint::Min(3), Constraint::Length(1)]).split(area);

    draw_header(f, app, outer[0]);
    if app.focus == Focus::AppLog {
        // its own tab, full-screen — not part of the bento grid below
        draw_app_log(f, app, outer[1]);
    } else {
        // bento grid: all panes always visible, Tab/Shift+Tab just moves the
        // highlighted border — nothing goes full-screen/modal otherwise. Fill
        // (not Percentage) so the halves are exactly equal — no rounding
        // drift between panes, which is what breaks top/bottom alignment
        // across columns.
        let main = Layout::horizontal([Constraint::Percentage(28), Constraint::Percentage(42), Constraint::Percentage(30)]).split(outer[1]);
        let left = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).split(main[0]);
        let mid = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).split(main[1]);
        draw_rules(f, app, left[0]);
        draw_apps(f, app, left[1]);
        draw_top_apps(f, app, mid[0]);
        draw_flow(f, app, mid[1]);
        draw_conflicts(f, app, main[2]);
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

    if let Mode::Add(buf) = &app.mode {
        let spans = vec![
            Span::styled(" ADD RULE ", Style::new().bg(theme.accents[0]).fg(Color::Black).add_modifier(Modifier::BOLD)),
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
        (Focus::Apps, _) => vec![("Tab", "pane"), ("j/k", "select"), ("Enter", "flow"), ("l", "log"), ("y/n", "allow/deny app"), ("space", "toggle"), ("d", "remove")],
        (Focus::Flow, _) => vec![("Tab", "pane"), ("j/k", "select"), ("l", "log"), ("y/n", "allow/deny port")],
        (Focus::Conflicts, _) => vec![("Tab", "pane"), ("j/k", "select"), ("l", "log"), ("y/n", "allow/deny port")],
        (Focus::AppLog, _) if app.app_log_confirm_flush => vec![("y", "confirm flush"), ("n", "cancel")],
        (Focus::AppLog, _) => vec![("j/k", "move"), ("f", "flush")],
        (Focus::Rules, Mode::Preset(_)) => vec![("j/k", "move"), ("Enter", "add"), ("Esc", "cancel")],
        (Focus::Rules, _) => vec![("Tab", "pane"), ("j/k", "move"), ("space", "toggle"), ("d", "delete"), ("a", "add"), ("p", "presets")],
    };
    let in_app_log = app.focus == Focus::AppLog;
    if !in_app_log {
        keys.push(("L", "app log"));
    }
    keys.push(("t", "theme"));
    if !(in_app_log && app.app_log_confirm_flush) {
        keys.push(("q", if in_app_log { "back" } else { "quit" }));
    }

    let mut spans = vec![Span::styled(format!(" {focus_label} "), Style::new().bg(focus_color).fg(Color::Black).add_modifier(Modifier::BOLD))];
    for (key, desc) in keys {
        spans.push(Span::styled("  ", base));
        spans.push(Span::styled(key, base.fg(focus_color).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(" ", base));
        spans.push(Span::styled(desc, base));
    }
    if !app.msg.is_empty() {
        spans.push(Span::styled(format!("   {}", app.msg), base.fg(theme.deny).add_modifier(Modifier::BOLD)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(base), area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let daemon = if app.ipc.is_some() { "connected" } else { "not reachable — per-app control off (sudo guardit daemon)" };
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(4)]).split(area);
    let ifaces = if app.interfaces.is_empty() { "none detected".to_string() } else { app.interfaces.join(", ") };
    let theme = THEMES[app.theme_idx];
    let status = format!("guardit  |  if: {ifaces}  |  daemon: {daemon}  |  theme: {} (t)", theme.name);
    f.render_widget(Paragraph::new(status).style(theme.base().add_modifier(Modifier::BOLD)), rows[0]);

    let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let (down, up) = app.net_rate_kbps;
    draw_throughput_spark(f, cols[0], "\u{2193} down", down, &app.net_hist_down, theme);
    draw_throughput_spark(f, cols[1], "\u{2191} up", up, &app.net_hist_up, theme);
}

fn draw_throughput_spark(f: &mut Frame, area: Rect, label: &str, current: f64, history: &VecDeque<u64>, theme: Theme) {
    let data: Vec<u64> = history.iter().copied().collect();
    let sparkline = Sparkline::default()
        .style(Style::new().fg(theme.chart).bg(theme.bg))
        .data(&data)
        .block(theme.pane(format!("{label}  {current:.1} KB/s"), false).border_type(BorderType::Rounded));
    f.render_widget(sparkline, area);
}

/// full-screen — its own tab, not squeezed into the bento grid; a detail
/// drill-down view genuinely needs the room these 7 columns take
fn draw_app_log(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let now = daemon::now_ts();
    let rows: Vec<Row> = app
        .app_log
        .iter()
        .map(|e| {
            let ago = daemon::ago(now.saturating_sub(e.ts));
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
                Cell::from(e.peer_ip.clone()),
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
    .header(Row::new(vec!["AGO", "DIR", "EXE", "PROTO", "PORT", "PEER", "STATUS"]).style(Style::new().fg(theme.fg).add_modifier(Modifier::BOLD)))
    .style(theme.base())
    .row_highlight_style(Style::new().bg(theme.border_idle))
    .block(theme.pane(
        match &app.app_log_filter {
            Some(exe) => format!("app log — {} ({} entries)", basename(exe), app.app_log.len()),
            None => format!("app log — full audit trail ({} entries)", app.app_log.len()),
        },
        true,
    ));
    f.render_stateful_widget(table, area, &mut app.app_log_state);

    if app.app_log_confirm_flush {
        draw_confirm_flush(f, app, area);
    }
}

/// small centered dialog over the app log — y/n, nothing else responds while it's up
fn draw_confirm_flush(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let [popup] = Layout::horizontal([Constraint::Length(44)]).flex(Flex::Center).areas(area);
    let [popup] = Layout::vertical([Constraint::Length(3)]).flex(Flex::Center).areas(popup);
    let text = Paragraph::new("flush the whole log? this can't be undone  y/n")
        .alignment(Alignment::Center)
        .style(Style::new().bg(theme.deny).fg(Color::Black).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).style(Style::new().bg(theme.deny).fg(Color::Black)).border_type(BorderType::Thick));
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
                    let style = if i == *sel { Style::new().fg(Color::Black).bg(theme.chart) } else { Style::new().fg(theme.fg) };
                    ListItem::new(text).style(style)
                })
                .collect();
            let list = List::new(items).style(theme.base()).block(theme.pane("pick a preset".into(), focused));
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
                    let text = format!(
                        "#{:<3} {:<6} [{}]  {}{}  {}",
                        r.id,
                        format!("{:?}", r.action).to_uppercase(),
                        format!("{:?}", r.proto).to_lowercase(),
                        r.src,
                        r.port.map(|p| format!(":{p}")).unwrap_or_default(),
                        if r.enabled { "" } else { "(off)" },
                    );
                    ListItem::new(text).style(Style::new().fg(color))
                })
                .collect();
            let list = List::new(items).style(theme.base()).highlight_style(Style::new().bg(theme.border_idle)).block(theme.pane("system rules".into(), focused));
            f.render_stateful_widget(list, area, &mut app.state);
        }
    }
}

fn draw_apps(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
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
            let color = if disabled { theme.border_idle } else { base_color };
            if disabled {
                status.push_str(" (off)");
            }
            // exe identity is just a path (see config::AppRule docs) — an
            // app that got reinstalled/updated to a different binary path
            // (common for Flatpak, AppImage, some auto-updaters) leaves a
            // rule pointing at nothing; flag it instead of pretending it's
            // still meaningful
            let missing = !Path::new(&row.exe).exists();
            if missing {
                status.push_str(" [gone]");
            }
            // this default doesn't tell the whole story if some of the app's
            // ports have their own override — say so instead of looking wrong
            if row.port_overrides > 0 {
                status.push_str(&format!(" +{}p", row.port_overrides));
            }
            let style = if missing { Style::new().fg(color).add_modifier(Modifier::CROSSED_OUT) } else { Style::new().fg(color) };
            // a name longer than the column gets truncated (not just padded) —
            // otherwise one long app name pushes its own status out of line
            // with every other row's, defeating the whole point of padding
            let name = basename(&row.exe);
            const NAME_COL: usize = 18;
            let name_col = if name.chars().count() > NAME_COL {
                format!("{}…", name.chars().take(NAME_COL - 1).collect::<String>())
            } else {
                format!("{name:<NAME_COL$}")
            };
            ListItem::new(format!("{dot} {name_col} {status}")).style(style)
        })
        .collect();
    let list = List::new(items).style(theme.base()).highlight_style(Style::new().bg(theme.border_idle)).block(theme.pane("application blocking".into(), app.focus == Focus::Apps));
    f.render_stateful_widget(list, area, &mut app.apps_state);
}

/// top apps by how many flow entries they've generated this session —
/// a quick "who's the most active/chatty" glance, not a rule-editing view
fn draw_top_apps(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let mut counts: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for e in &app.flow {
        *counts.entry(e.exe.as_str()).or_default() += 1;
    }
    let mut top: Vec<(&str, u64)> = counts.into_iter().collect();
    top.sort_by_key(|&(_, c)| Reverse(c));
    // every app, always — bar width adapts to how many there are instead of
    // truncating the list, so it never silently hides an app
    let n = top.len().max(1) as u16;
    let inner_width = area.width.saturating_sub(4); // borders + horizontal padding
    let bar_gap: u16 = 1;
    let bar_width = ((inner_width.saturating_sub(n.saturating_sub(1) * bar_gap)) / n).clamp(3, 9);
    // no in-bar digit: a number glyph drawn inside a solid block bar breaks
    // the bar's straight top edge (worst offender: "7", its shape reads as
    // a notch/hump), so the count only shows in the label under the bar
    let bars: Vec<Bar> = top
        .iter()
        .map(|(exe, count)| {
            Bar::default()
                .value(*count)
                .label(format!("{} ({count})", basename(exe)).into())
                .text_value(String::new())
                .style(Style::new().fg(theme.chart))
        })
        .collect();

    let chart = BarChart::default()
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(bar_gap)
        .label_style(Style::new().fg(theme.fg))
        .style(Style::new().bg(theme.bg))
        .block(theme.pane("top apps — connection attempts".into(), false));
    f.render_widget(chart, area);
}

fn draw_flow(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let title = match app.apps_state.selected().and_then(|i| app.apps.get(i)) {
        Some(row) => format!("network flow — {}", basename(&row.exe)),
        None => "network flow — select an app on the left".to_string(),
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
                e.peer_ip,
            );
            let mut style = Style::new().fg(color);
            if matches!(status, FlowStatus::Pending) {
                style = style.add_modifier(Modifier::BOLD);
            }
            ListItem::new(text).style(style)
        })
        .collect();
    let list = List::new(items).style(theme.base()).highlight_style(Style::new().bg(theme.border_idle)).block(theme.pane(title, app.focus == Focus::Flow));
    f.render_stateful_widget(list, area, &mut app.flow_state);
}

fn draw_conflicts(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    // real EADDRINUSE-style conflicts (see daemon::find_conflicts) — this
    // will almost always be empty, because the kernel already refuses the
    // losing bind() before it ever shows up here; that's the honest,
    // correct answer, not a bug in the detector
    let conflicts = daemon::find_conflicts(&app.listening);
    let conflicted: HashSet<&str> = conflicts.iter().flat_map(|(a, b)| [a.exe.as_str(), b.exe.as_str()]).collect();

    let items: Vec<ListItem> = if app.listening.is_empty() {
        vec![ListItem::new("no listening sockets seen yet (scanned every 5s)")]
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
                let style = if is_conflict { Style::new().fg(theme.deny).add_modifier(Modifier::BOLD) } else { Style::new().fg(theme.fg) };
                ListItem::new(text).style(style)
            })
            .collect()
    };
    let title = if conflicts.is_empty() {
        "listening ports".to_string()
    } else {
        format!("listening ports — {} REAL CONFLICT(S)", conflicts.len())
    };
    let list = List::new(items).style(theme.base()).highlight_style(Style::new().bg(theme.border_idle)).block(theme.pane(title, app.focus == Focus::Conflicts));
    f.render_stateful_widget(list, area, &mut app.conflicts_state);
}
