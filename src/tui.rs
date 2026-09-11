use crate::blocklist;
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
    Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, List, ListItem, ListState,
    Padding, Paragraph, Row, Sparkline, Table, TableState,
};
use ratatui::{Frame, Terminal};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufReader, Read as _, stdout};
use std::sync::mpsc;
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
    /// what the blocklists block — its own tab on `B`, not a pane in the
    /// grid: it is set up now and then, and the grid is for the thing you
    /// operate every day
    Blocking,
    /// listening ports — inside the log tab, not the grid: it answers the
    /// same "what has been going on" question the audit trail does, and
    /// pairing them frees the grid's third column for the live flow
    Conflicts,
    /// the full audit trail — its own tab, rendered over the whole grid area
    /// and jumpable to from anywhere via the global `A` key, same idea as
    /// `t` for theme
    AppLog,
    /// the names most recently blocked — the other half of the blocking
    /// tab, `h`/`l` away from the categories, where a false positive shows
    /// up and gets allowed
    BlockedNames,
}

/// the log tab: the audit trail and the listening ports, Tab switching
/// between them. Everything else is the bento grid.
fn in_log_tab(focus: Focus) -> bool {
    matches!(focus, Focus::AppLog | Focus::Conflicts)
}

/// Anything drawn over the whole grid rather than inside it.
fn in_tab(focus: Focus) -> bool {
    in_log_tab(focus) || in_blocking_tab(focus)
}

/// the blocking tab: the category switches and the names recently blocked
fn in_blocking_tab(focus: Focus) -> bool {
    matches!(focus, Focus::Blocking | Focus::BlockedNames)
}

// Two rings over the same panes.
//
// Tab walks the panes as a user thinks of them: system rules, application
// blocking, ads & tracking. Application blocking is one stop even though it
// holds two lists, because it is one pane with one border.
//
// h/l walks every stop, the halves of application blocking included, in the
// order they sit on screen — so `l` out of the app list lands on its flow,
// and `l` again leaves the pane. Top apps is informational (nothing to
// focus), and the audit tab is reached only via the global `A` key or a
// pane's `a` — a drill-down, not a pane you'd casually cycle through.
impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Rules => Focus::Apps,
            Focus::Apps | Focus::Flow => Focus::Rules,
            // inside a tab, Tab toggles its two halves
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
            Focus::Blocking => Focus::BlockedNames,
            Focus::BlockedNames => Focus::Blocking,
        }
    }

    fn prev(self) -> Focus {
        match self {
            Focus::Rules => Focus::Apps,
            Focus::Apps => Focus::Rules,
            Focus::Flow => Focus::Apps,
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
            Focus::Blocking => Focus::BlockedNames,
            Focus::BlockedNames => Focus::Blocking,
        }
    }

    /// `l`: the next stop to the right, counting the two halves of
    /// application blocking separately
    fn right(self) -> Focus {
        match self {
            Focus::Rules => Focus::Apps,
            Focus::Apps => Focus::Flow,
            Focus::Flow => Focus::Rules,
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
            Focus::Blocking => Focus::BlockedNames,
            Focus::BlockedNames => Focus::Blocking,
        }
    }

    /// `h`: the same, the other way
    fn left(self) -> Focus {
        match self {
            Focus::Rules => Focus::Flow,
            Focus::Apps => Focus::Rules,
            Focus::Flow => Focus::Apps,
            Focus::AppLog => Focus::Conflicts,
            Focus::Conflicts => Focus::AppLog,
            Focus::Blocking => Focus::BlockedNames,
            Focus::BlockedNames => Focus::Blocking,
        }
    }
}

enum Mode {
    Browse,
    Add(String),
    /// the preset picker: a selection into `matching_presets(filter)`, and
    /// the filter itself. Typing narrows the catalogue and the arrows move
    /// through what is left — with thirty-odd entries, "type three letters"
    /// is the navigation, and j/k would cost the letters j and k to type
    Preset {
        sel: usize,
        filter: String,
    },
    /// keystrokes go to the focused pane's filter instead of its own keys.
    /// Which filter that is follows the focus (`filter_buf`); the filter
    /// itself stays applied after leaving this mode
    Filter,
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

/// One entry of the preset catalogue: a named policy, one or more rules.
///
/// Multi-rule on purpose. "Allow web serving" is two ports, "allow the LAN"
/// is three ranges, and a preset that made you pick them off a list one at a
/// time would be a list of specs with extra steps.
struct Preset {
    /// what the picker filters and groups on, so a catalogue this size stays
    /// something you can find your way around by typing three letters
    group: &'static str,
    name: &'static str,
    /// what it actually does to your traffic, including the part you would
    /// not have guessed. An `allow` here is a kernel-level accept: it means
    /// the daemon never sees that traffic, so per-app rules stop applying to
    /// it. That is the whole point when you want the asking to stop, and a
    /// nasty surprise when you did not — so every such preset says so.
    note: &'static str,
    specs: &'static [&'static str],
}

const fn p(
    group: &'static str,
    name: &'static str,
    note: &'static str,
    specs: &'static [&'static str],
) -> Preset {
    Preset {
        group,
        name,
        note,
        specs,
    }
}

/// The catalogue, in the same spec format as the freeform `a` add-flow.
///
/// Grouped by what you are trying to do rather than by protocol: `off` when
/// guardit is in the way, `lan` for your own network, `in` for what this
/// machine offers, `out` for what it may reach, `harden` for the ports worth
/// shutting on principle, and `bundle` for whole postures in one keystroke.
const PRESETS: &[Preset] = &[
    // ---- off: the escape hatches ----
    p(
        "off",
        "Allow everything (pause filtering)",
        "one unqualified accept above both queues — no per-app matching, no prompts, no blocking",
        &["allow any any -"],
    ),
    p(
        "off",
        "Pause outbound filtering only",
        "stops the asking about outgoing connections; inbound stays fully filtered",
        &["allow any any - out"],
    ),
    // ---- lan: your own network ----
    p(
        "lan",
        "Allow my LAN (all private ranges)",
        "192.168/16, 10/8 and 172.16/12, both ways — printers, NAS, phones, other machines you own",
        &[
            "allow any 192.168.0.0/16 -",
            "allow any 10.0.0.0/8 -",
            "allow any 172.16.0.0/12 -",
        ],
    ),
    p(
        "lan",
        "Allow my LAN (192.168.0.0/16)",
        "the home-router range only",
        &["allow any 192.168.0.0/16 -"],
    ),
    p(
        "lan",
        "Allow my LAN (10.0.0.0/8)",
        "the corporate/VPN range only",
        &["allow any 10.0.0.0/8 -"],
    ),
    p(
        "lan",
        "Allow link-local (169.254.0.0/16)",
        "self-assigned addresses: a directly cabled machine, a camera, a printer with no DHCP",
        &["allow any 169.254.0.0/16 -"],
    ),
    p(
        "lan",
        "Allow local service discovery",
        "mDNS/Bonjour and SSDP — how printers, casts and NAS boxes announce themselves",
        &["allow udp any 5353", "allow udp any 1900"],
    ),
    p(
        "lan",
        "Block everything outside my LAN",
        "adds nothing: inbound already defaults to drop. Here to say so out loud",
        &["deny any any - in"],
    ),
    // ---- in: what this machine offers ----
    p(
        "in",
        "Allow SSH in (22)",
        "from anywhere. Pair it with fail2ban or keys-only if this machine faces the internet",
        &["allow tcp any 22 in"],
    ),
    p(
        "in",
        "Allow SSH in from my LAN only (22)",
        "the same, but nothing off your own network can reach it",
        &[
            "allow tcp 192.168.0.0/16 22 in",
            "allow tcp 10.0.0.0/8 22 in",
        ],
    ),
    p(
        "in",
        "Allow web serving in (80, 443)",
        "this machine answering HTTP and HTTPS from anywhere",
        &["allow tcp any 80 in", "allow tcp any 443 in"],
    ),
    p(
        "in",
        "Allow a dev server from my LAN (3000, 5173, 8000, 8080)",
        "the usual node/vite/python/tomcat ports, reachable from your own network only",
        &[
            "allow tcp 192.168.0.0/16 3000 in",
            "allow tcp 192.168.0.0/16 5173 in",
            "allow tcp 192.168.0.0/16 8000 in",
            "allow tcp 192.168.0.0/16 8080 in",
        ],
    ),
    p(
        "in",
        "Allow file sharing from my LAN (SMB 139, 445)",
        "Windows/Samba shares — from your own network only, which is the only place SMB belongs",
        &[
            "allow tcp 192.168.0.0/16 445 in",
            "allow tcp 192.168.0.0/16 139 in",
        ],
    ),
    p(
        "in",
        "Allow printing in (631)",
        "CUPS/IPP, so other machines can print to this one",
        &["allow tcp any 631 in"],
    ),
    p(
        "in",
        "Allow remote desktop from my LAN (VNC 5900, RDP 3389)",
        "screen sharing from your own network. Never open these to the internet",
        &[
            "allow tcp 192.168.0.0/16 5900 in",
            "allow tcp 192.168.0.0/16 3389 in",
        ],
    ),
    p(
        "in",
        "Allow Syncthing in (22000)",
        "peer-to-peer sync, which needs to be reachable to work at all",
        &["allow tcp any 22000 in", "allow udp any 22000 in"],
    ),
    p(
        "in",
        "Allow BitTorrent in (6881)",
        "incoming peers. Expect a lot of them",
        &["allow tcp any 6881 in", "allow udp any 6881 in"],
    ),
    p(
        "in",
        "Allow WireGuard in (51820)",
        "so a VPN client elsewhere can reach this machine",
        &["allow udp any 51820 in"],
    ),
    // ---- out: what this machine may reach ----
    p(
        "out",
        "Stop asking about DNS and NTP (53, 123)",
        "the two every program needs. Kernel-level accept, so per-app rules no longer apply to them",
        &["allow any any 53 out", "allow udp any 123 out"],
    ),
    p(
        "out",
        "Stop asking about the web (80, 443)",
        "quietest single change there is — and it takes per-app control off ALL web traffic",
        &["allow tcp any 80 out", "allow tcp any 443 out"],
    ),
    p(
        "out",
        "Stop asking about mail (465, 587, 993, 995)",
        "submission and IMAP/POP over TLS; per-app control stops applying to them",
        &[
            "allow tcp any 465 out",
            "allow tcp any 587 out",
            "allow tcp any 993 out",
            "allow tcp any 995 out",
        ],
    ),
    p(
        "out",
        "Stop asking about SSH and git (22, 9418)",
        "for a machine you push from all day",
        &["allow tcp any 22 out", "allow tcp any 9418 out"],
    ),
    p(
        "out",
        "Block plain HTTP out (80)",
        "HTTPS only. Breaks captive portals and a few updaters, and says so loudly when it does",
        &["deny tcp any 80 out"],
    ),
    p(
        "out",
        "Block SMTP out (25)",
        "port 25 from a machine like this one is a spam bot; real mail submits on 465 or 587",
        &["deny tcp any 25 out"],
    ),
    // ---- harden: shut on principle ----
    p(
        "harden",
        "Block remote-control ports out (telnet, SMB, RDP, VNC)",
        "23, 139, 445, 3389, 5900 outbound — plaintext or LAN-only protocols with no business leaving",
        &[
            "deny tcp any 23 out",
            "deny tcp any 139 out",
            "deny tcp any 445 out",
            "deny tcp any 3389 out",
            "deny tcp any 5900 out",
        ],
    ),
    p(
        "harden",
        "Block known implant ports out (4444, 5555, 6667)",
        "metasploit's default, adb over the network, and IRC — a shortlist, not a shield",
        &[
            "deny tcp any 4444 out",
            "deny tcp any 5555 out",
            "deny tcp any 6667 out",
        ],
    ),
    p(
        "harden",
        "Block encrypted DNS out (853)",
        "DoT/DoQ, so name lookups stay where the blocklists can see them. The blocklist setting covers DoH too",
        &["deny tcp any 853 out", "deny udp any 853 out"],
    ),
    p(
        "harden",
        "Block NetBIOS and mDNS leaving the LAN (137, 138, 5353)",
        "chatty discovery protocols that leak machine and user names",
        &[
            "deny udp any 137 out",
            "deny udp any 138 out",
            "deny udp any 5353 out",
        ],
    ),
    // ---- bundle: a whole posture in one keystroke ----
    p(
        "bundle",
        "Laptop on untrusted wifi",
        "nothing in, the essentials out, no LAN trust: DNS/NTP/web out, everything inbound dropped",
        &[
            "deny any any - in",
            "allow any any 53 out",
            "allow udp any 123 out",
            "allow tcp any 80 out",
            "allow tcp any 443 out",
        ],
    ),
    p(
        "bundle",
        "Web server",
        "80, 443 and SSH in; DNS, NTP and web out for updates. Per-app control stays on everything else",
        &[
            "allow tcp any 80 in",
            "allow tcp any 443 in",
            "allow tcp any 22 in",
            "allow any any 53 out",
            "allow udp any 123 out",
            "allow tcp any 80 out",
            "allow tcp any 443 out",
        ],
    ),
    p(
        "bundle",
        "Home desktop",
        "the whole LAN trusted both ways, DNS/NTP/web out, and the remote-control ports shut outbound",
        &[
            "allow any 192.168.0.0/16 -",
            "allow any 10.0.0.0/8 -",
            "allow any any 53 out",
            "allow udp any 123 out",
            "allow tcp any 80 out",
            "allow tcp any 443 out",
            "deny tcp any 23 out",
            "deny tcp any 445 out",
            "deny tcp any 3389 out",
        ],
    ),
    p(
        "bundle",
        "Paranoid",
        "no LAN trust, no kernel-level allows at all — every single connection goes to the daemon and its rules",
        &[
            "deny any any - in",
            "deny tcp any 23 out",
            "deny tcp any 25 out",
            "deny tcp any 139 out",
            "deny tcp any 445 out",
            "deny tcp any 3389 out",
            "deny tcp any 5900 out",
            "deny tcp any 853 out",
            "deny udp any 853 out",
        ],
    ),
];

/// the presets whose group or name contains `filter`, case-insensitively —
/// the whole navigation model for a catalogue this long is "type three
/// letters", so the match has to cover the group tag as well as the words
fn matching_presets(filter: &str) -> Vec<&'static Preset> {
    let f = filter.trim().to_ascii_lowercase();
    PRESETS
        .iter()
        .filter(|p| {
            f.is_empty()
                || p.group.contains(&f)
                || p.name.to_ascii_lowercase().contains(&f)
                || p.note.to_ascii_lowercase().contains(&f)
        })
        .collect()
}

/// Adds a preset's rules, skipping any this config already has.
///
/// Without the skip, picking the same preset twice — or two presets that
/// overlap, which the bundles deliberately do — leaves duplicate rules that
/// each have to be deleted by hand. Returns how many were actually added.
fn apply_preset(app: &mut App, preset: &Preset) -> usize {
    let mut added = 0;
    for spec in preset.specs {
        let mut r = parse_spec(spec).expect("built-in preset spec must parse");
        let dup = app.cfg.rule.iter().any(|e| {
            e.action == r.action
                && e.proto == r.proto
                && e.src == r.src
                && e.port == r.port
                && e.direction == r.direction
        });
        if dup {
            continue;
        }
        r.id = app.cfg.next_id();
        app.cfg.rule.push(r);
        added += 1;
    }
    if added > 0 {
        save_rules(app);
    }
    added
}

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

/// How much of each app's history the flow pane holds.
///
/// Per app, not overall: a global cap means one chatty program evicts every
/// other app's history, so selecting a quiet one shows an empty pane even
/// though its whole trail is on disk.
const FLOW_PER_APP: usize = 300;

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
    /// apps whose earlier flow has already been read back off disk — once
    /// each, since the disk copy does not change behind us
    flow_hydrated: HashSet<String>,
    /// None = full unthrottled trail (global A); Some(exe) = just that app
    /// (a from Apps/Flow/Conflicts)
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
    /// every listening socket the daemon reported; `listening` is this
    /// narrowed by `listening_filter`, and is what the pane renders and what
    /// its selection indexes into
    listening_all: Vec<ipc::ListenEntry>,
    /// port / address / owner the listening pane is narrowed to; empty = all
    listening_filter: String,
    blocklist: ipc::BlocklistStats,
    /// which row of the category list is selected
    blocking_state: ListState,
    /// which recently blocked name is selected, counted newest first as the
    /// list is drawn; kept on its name as new ones arrive (set_blocklist_stats)
    blocked_state: ListState,
    /// the one slow thing that may be running: a list download, or a
    /// ruleset reload. Both are seconds-to-minutes and both used to happen
    /// inside the draw loop, where they read as a freeze
    busy: Option<Busy>,
    /// rules.toml's mtime when `cfg` was last read from it, so a hand edit
    /// shows up here as it does in the daemon (reload_cfg_if_edited)
    cfg_mtime: Option<std::time::SystemTime>,
}

/// A job running off the draw loop. It reports one line back and hangs up;
/// until then the footer carries a segment saying what is going on.
struct Busy {
    label: &'static str,
    started: Instant,
    rx: mpsc::Receiver<String>,
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

/// Add-rule spec: "<allow|deny> <tcp|udp|any> <peer|any> <port|-> [in|out]"
///
/// The trailing direction is optional and omitting it means both, so every
/// spec that parsed before this field existed still parses and still means
/// the same thing.
const SPEC_FORMAT: &str = "format: <allow|deny> <tcp|udp|any> <peer|any> <port|-> [in|out]";

fn parse_spec(line: &str) -> Result<Rule, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if !(4..=5).contains(&parts.len()) {
        return Err(SPEC_FORMAT.into());
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
    let direction = match parts.get(4) {
        None => None,
        Some(&"in") => Some(Direction::In),
        Some(&"out") => Some(Direction::Out),
        Some(_) => return Err("direction must be in|out, or left off for both".into()),
    };
    Ok(Rule {
        id: 0,
        action,
        proto,
        src,
        port,
        direction,
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
        flow_hydrated: HashSet::new(),
        app_log_filter: None,
        app_log_confirm_flush: false,
        apps_filter: String::new(),
        app_log_all: Vec::new(),
        log_filter: String::new(),
        listening_all: Vec::new(),
        listening_filter: String::new(),
        blocklist: ipc::BlocklistStats::default(),
        blocking_state: ListState::default().with_selected(Some(0)),
        blocked_state: ListState::default().with_selected(Some(0)),
        busy: None,
        cfg_mtime: config_mtime(),
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
            drain_busy(&mut app);
            reload_cfg_if_edited(&mut app);
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
            continue;
        }
        if let Event::Key(key) = event::read().expect("read event") {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            app.msg.clear();
            // h/l move like j/k do, one axis over: between panes, and
            // between the two halves of application blocking
            let move_focus = match key.code {
                KeyCode::Tab => Some(Focus::next as fn(Focus) -> Focus),
                KeyCode::BackTab => Some(Focus::prev as fn(Focus) -> Focus),
                KeyCode::Char('l') | KeyCode::Right => Some(Focus::right as fn(Focus) -> Focus),
                KeyCode::Char('h') | KeyCode::Left => Some(Focus::left as fn(Focus) -> Focus),
                _ => None,
            };
            if let Some(step) = move_focus
                && !matches!(
                    app.mode,
                    Mode::Add(_) | Mode::Preset { .. } | Mode::Filter
                )
                // a confirmation is answered before anything else moves
                && !app.app_log_confirm_flush
            {
                app.focus = step(app.focus);
                if app.apps_state.selected().is_none() && !app.apps.is_empty() {
                    app.apps_state.select(Some(0));
                    reset_flow_selection(&mut app);
                }
                continue;
            }
            if key.code == KeyCode::Char('t')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter)
            {
                app.theme_idx = (app.theme_idx + 1) % THEMES.len();
                save_theme_idx(app.theme_idx);
                continue;
            }
            if key.code == KeyCode::Char('B')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter)
            {
                if in_blocking_tab(app.focus) {
                    leave_tab(&mut app);
                } else {
                    enter_tab(&mut app, Focus::Blocking);
                }
                continue;
            }
            // auto mode is a property of the whole daemon, not of any pane,
            // so it toggles from anywhere. Only on and off: which fallback
            // it uses is a decision to make once in the config, not one to
            // cycle past by accident on the way to turning it off
            if key.code == KeyCode::Char('m')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter)
            {
                let enabled = !app.cfg.auto.enabled;
                app.cfg = Config::update(|c| c.auto.enabled = enabled);
                continue;
            }
            // jumpable to from anywhere, same idea as `t` — the audit tab is
            // its own tab, not nested under any pane's local keys
            if key.code == KeyCode::Char('A')
                && !matches!(app.mode, Mode::Add(_) | Mode::Filter)
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
                        KeyCode::Char('p') => {
                            app.mode = Mode::Preset {
                                sel: 0,
                                filter: String::new(),
                            }
                        }
                        _ => {}
                    },
                    Mode::Preset { sel, filter } => {
                        let len = matching_presets(filter).len();
                        match key.code {
                            KeyCode::Esc => app.mode = Mode::Browse,
                            KeyCode::Down => *sel = if len == 0 { 0 } else { (*sel + 1) % len },
                            KeyCode::Up => {
                                *sel = if len == 0 { 0 } else { (*sel + len - 1) % len }
                            }
                            KeyCode::Backspace => {
                                filter.pop();
                                *sel = 0;
                            }
                            // every other printable key narrows the list, so
                            // there is no second mode to enter first
                            KeyCode::Char(c) => {
                                filter.push(c);
                                *sel = 0;
                            }
                            KeyCode::Enter => {
                                if let Some(preset) = matching_presets(filter).get(*sel).copied() {
                                    apply_preset(&mut app, preset);
                                }
                                app.mode = Mode::Browse;
                            }
                            _ => {}
                        }
                    }
                    // only ever set from the Apps pane / the log tab, and Tab
                    // can't leave either — but if one got here, Browse is the
                    // safe read
                    Mode::Filter => app.mode = Mode::Browse,
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
                // you're typing towards instead of committing blind. One
                // branch for every pane that has a filter — which one is
                // being typed into follows the focus
                _ if matches!(app.mode, Mode::Filter) => {
                    let Some(buf) = filter_buf(&mut app) else {
                        app.mode = Mode::Browse;
                        continue;
                    };
                    match key.code {
                        KeyCode::Enter => app.mode = Mode::Browse,
                        KeyCode::Esc => {
                            buf.clear();
                            app.mode = Mode::Browse;
                        }
                        KeyCode::Backspace => {
                            buf.pop();
                        }
                        KeyCode::Char(c) => buf.push(c),
                        _ => continue,
                    }
                    apply_filter(&mut app);
                }
                Focus::Apps => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('/') => app.mode = Mode::Filter,
                    // a filter left on is easy to forget about — Esc drops it
                    // from anywhere in the pane, not only while typing
                    KeyCode::Esc if !app.apps_filter.is_empty() => {
                        app.apps_filter.clear();
                        apply_filter(&mut app);
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
                    KeyCode::Char('a') => {
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
                Focus::BlockedNames => match key.code {
                    KeyCode::Char('q') => leave_tab(&mut app),
                    KeyCode::Char('j') | KeyCode::Down => app.blocked_state.select(step(
                        app.blocked_state.selected(),
                        app.blocklist.recent.len(),
                        false,
                    )),
                    KeyCode::Char('k') | KeyCode::Up => app.blocked_state.select(step(
                        app.blocked_state.selected(),
                        app.blocklist.recent.len(),
                        true,
                    )),
                    KeyCode::Char('y') => allow_blocked_name(&mut app),
                    _ => {}
                },
                Focus::Blocking => match key.code {
                    KeyCode::Char('q') => leave_tab(&mut app),
                    KeyCode::Char('j') | KeyCode::Down => app.blocking_state.select(step(
                        app.blocking_state.selected(),
                        blocklist::CATEGORIES.len(),
                        false,
                    )),
                    KeyCode::Char('k') | KeyCode::Up => app.blocking_state.select(step(
                        app.blocking_state.selected(),
                        blocklist::CATEGORIES.len(),
                        true,
                    )),
                    KeyCode::Char(' ') => toggle_category(&mut app),
                    KeyCode::Char('s') => cycle_source(&mut app),
                    KeyCode::Char('u') => update_blocklists(&mut app),
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
                    KeyCode::Char('a') => {
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
                    KeyCode::Char('/') => app.mode = Mode::Filter,
                    KeyCode::Esc if !app.listening_filter.is_empty() => {
                        app.listening_filter.clear();
                        apply_filter(&mut app);
                    }
                    KeyCode::Char('j') | KeyCode::Down => conflicts_select(&mut app, false),
                    KeyCode::Char('k') | KeyCode::Up => conflicts_select(&mut app, true),
                    KeyCode::Char('y') => conflicts_decide(&mut app, Action::Allow),
                    KeyCode::Char('n') => conflicts_decide(&mut app, Action::Deny),
                    KeyCode::Char('a') => {
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
                Focus::AppLog => match key.code {
                    KeyCode::Char('q') => close_app_log(&mut app),
                    KeyCode::Char('/') => app.mode = Mode::Filter,
                    KeyCode::Esc if !app.log_filter.is_empty() => {
                        app.log_filter.clear();
                        apply_filter(&mut app);
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
                app.listening_all = listening;
                app.blocklist = blocklist;
                apply_listening_filter(app);
            }
            ServerMsg::Blocklist(stats) => set_blocklist_stats(app, stats),
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
                app.listening_all = entries;
                apply_listening_filter(app);
            }
        }
    }
    trim_flow(app);
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
    // apps with no rule at all first — they're the ones waiting on a
    // decision — and alphabetical within each half, so a row only ever moves
    // when its own state changes
    rows.sort_by_key(|r| (r.rule.is_some() || r.port_overrides > 0, r.exe.clone()));
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

/// Keeps the newest `FLOW_PER_APP` rows of every app, rather than the newest
/// N rows overall — otherwise one busy program's traffic evicts the history
/// of every app you might actually want to look at.
fn trim_flow(app: &mut App) {
    if app.flow.len() <= FLOW_PER_APP {
        return;
    }
    let mut kept: HashMap<&str, usize> = HashMap::new();
    let mut keep = vec![false; app.flow.len()];
    for (i, e) in app.flow.iter().enumerate().rev() {
        let n = kept.entry(e.exe.as_str()).or_default();
        if *n < FLOW_PER_APP {
            *n += 1;
            keep[i] = true;
        }
    }
    let mut it = keep.into_iter();
    app.flow.retain(|_| it.next().unwrap_or(false));
}

/// Reads an app's earlier flow back off disk, the first time you look at it.
///
/// The daemon hands a new client a capped slice of recent history across all
/// apps, so a program that was busy yesterday and quiet today arrives with
/// an empty pane — while its whole trail is sitting in history.jsonl, which
/// is where the audit tab reads it from. Same file, filtered to the app,
/// merged in front of what is already held.
///
/// Cut by time rather than deduplicated: everything in memory is newer than
/// everything being added, so taking only entries older than the oldest one
/// held cannot double up a row.
fn hydrate_flow(app: &mut App, exe: &str) {
    if !app.flow_hydrated.insert(exe.to_string()) {
        return;
    }
    let oldest = app
        .flow
        .iter()
        .filter(|e| e.exe == exe)
        .map(|e| e.ts)
        .min()
        .unwrap_or(u64::MAX);
    let mut older: Vec<FlowWire> = read_app_log(FLOW_PER_APP, Some(exe))
        .into_iter()
        .filter(|e| e.ts < oldest)
        .collect();
    if older.is_empty() {
        return;
    }
    older.append(&mut app.flow);
    app.flow = older;
}

fn reset_flow_selection(app: &mut App) {
    if let Some(exe) = app
        .apps_state
        .selected()
        .and_then(|i| app.apps.get(i))
        .map(|r| r.exe.clone())
    {
        hydrate_flow(app, &exe);
    }
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
    let cfg = Config::load();
    apply_ruleset(app, cfg);
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

/// Opens a tab, remembering where you were — and only ever a place in the
/// grid, never another tab.
///
/// `prev_focus` holding a tab is a trap with no way out: leaving that tab
/// puts you back in a tab, whose own way out is the same field, now pointing
/// at itself. That is reachable by opening one tab from another, which the
/// two keys that open them both allow.
fn enter_tab(app: &mut App, tab: Focus) {
    if !in_tab(app.focus) {
        app.prev_focus = app.focus;
    }
    app.focus = tab;
}

/// Back to the grid, from any tab. Clamped rather than trusted: a
/// `prev_focus` that ever held a tab would strand you, and landing on the
/// apps pane is a poor outcome next to no way back at all.
fn leave_tab(app: &mut App) {
    app.focus = if in_tab(app.prev_focus) {
        Focus::Apps
    } else {
        app.prev_focus
    };
}

fn open_app_log(app: &mut App, filter: Option<String>) {
    enter_tab(app, Focus::AppLog);
    app.app_log_filter = filter;
    app.app_log_confirm_flush = false;
    app.app_log_all = read_app_log(APP_LOG_LIMIT, app.app_log_filter.as_deref());
    apply_log_filter(app);
    apply_listening_filter(app);
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

/// Which text field the keystrokes of `Mode::Filter` land in — the pane
/// with the focus owns the filter, so there is one mode rather than one per
/// pane. `None` for panes that have no filter, which cannot enter the mode.
fn filter_buf(app: &mut App) -> Option<&mut String> {
    match app.focus {
        Focus::Apps => Some(&mut app.apps_filter),
        Focus::AppLog => Some(&mut app.log_filter),
        Focus::Conflicts => Some(&mut app.listening_filter),
        _ => None,
    }
}

/// re-narrows whatever the focused pane shows, after its filter changed
fn apply_filter(app: &mut App) {
    match app.focus {
        Focus::Apps => {
            rebuild_apps(app);
            reset_flow_selection(app);
        }
        Focus::AppLog => apply_log_filter(app),
        Focus::Conflicts => apply_listening_filter(app),
        _ => {}
    }
}

/// Narrows the listening pane to one port, address or owner, on the same
/// terms as the audit trail's filter: a digits-only needle is the port as a
/// whole number, anything else a substring of the bound address or the exe.
///
/// The tab's own scope comes first: opened for one app with `a`, both halves
/// are about that app, so the ports shown are its ports.
fn apply_listening_filter(app: &mut App) {
    app.listening = app
        .listening_all
        .iter()
        .filter(|e| app.app_log_filter.as_deref().is_none_or(|exe| e.exe == exe))
        .filter(|e| {
            let needle = &app.listening_filter;
            if needle.is_empty() {
                return true;
            }
            if needle.chars().all(|c| c.is_ascii_digit()) {
                return e.port.to_string() == *needle;
            }
            let needle = needle.to_lowercase();
            e.addr.to_lowercase().contains(&needle) || e.exe.to_lowercase().contains(&needle)
        })
        .cloned()
        .collect();
    sort_listening(&mut app.listening);
    app.conflicts_state.select(if app.listening.is_empty() {
        None
    } else {
        Some(0)
    });
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
    leave_tab(app);
    app.app_log_filter = None;
    app.log_filter.clear();
    app.listening_filter.clear();
    apply_listening_filter(app);
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
    // A policy refusal is not something the rules can be re-read to reach:
    // the blocklist and require_resolved decide on evidence of their own, and
    // a whole-app allow does not override either. Recomputing from the rules
    // alone painted those rows green while the daemon went on dropping them.
    if e.denied_by.is_some() {
        return FlowStatus::Denied;
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
    // forgetting the app forgets what we read for it too, so selecting it
    // again reads its trail back rather than showing nothing
    app.flow_hydrated.remove(&exe);
    rebuild_apps(app);
    reset_flow_selection(app);
}

fn flow_select(app: &mut App, back: bool) {
    let len = current_flow_indices(app).len();
    app.flow_state
        .select(step(app.flow_state.selected(), len, back));
}

/// Rules the row you are looking at, and only that.
///
/// A flow row is an app reaching one peer on one port, so the rule is about
/// that pair: `deny` on `curl -> port 53 -> ads.example.com` must stop curl
/// reaching *that name*, not stop curl doing DNS. Where the peer has no
/// resolved name there is nothing else to key on and it falls back to the
/// port alone, which is all a nameless row actually says.
///
/// `Y`/`N` widen it to the host on any port; the Apps pane widens it to the
/// whole app. Three deliberate scopes, narrowest under the plain keys.
///
/// On a still-pending request this verdicts the held packet and the daemon
/// records the same rule; on a resolved row there is no packet left, so it
/// just (re)sets the rule — which is how you flip an earlier deny to allow.
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
    let host = entry.peer_name.clone();
    let was_pending = matches!(entry.status, FlowStatus::Pending);
    let req_id = entry.req_id;
    let Some(ipc) = &mut app.ipc else { return };

    if was_pending {
        // the daemon records the same scope from the packet it is holding,
        // which is where the peer name for it comes from
        let Some(req_id) = req_id else { return };
        ipc.send(&ClientMsg::Decide { req_id, verdict });
    } else {
        ipc.send(&ClientMsg::SetAppRule {
            exe: exe.clone(),
            port,
            direction: Some(direction),
            action: verdict,
            expires: None,
            host: host.clone(),
        });
    }
    // the same rows the rule will match: this app, this port and direction,
    // and — when the row named a peer — that peer
    cascade_flow_rows(app, verdict, |e| {
        e.exe == exe
            && e.port == port
            && e.direction == direction
            && (host.is_none() || e.peer_name == host)
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
    if in_blocking_tab(app.focus) {
        draw_blocking(f, app, outer[1]);
    } else if in_log_tab(app.focus) {
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
        // Three panes, all about the same thing: the rules the kernel
        // holds, what the machine has been doing, and the pane you decide
        // in. The blocklists are a tab (`B`), not a column — they are set up
        // now and then, and a third of the screen given to something you
        // read makes the tool look like what it isn't.
        let [top, bottom] =
            Layout::vertical([Constraint::Percentage(46), Constraint::Percentage(54)])
                .areas(outer[1]);
        let [rules, top_apps] =
            Layout::horizontal([Constraint::Percentage(28), Constraint::Percentage(72)])
                .areas(top);
        draw_rules(f, app, rules);
        draw_top_apps(f, app, top_apps);
        // the divider reproduces the seam above it — the two adjacent border
        // columns where System rules ends and Top apps begins — so the two
        // halves sit under the panes they belong with: the app list under
        // the rules, its flow under what the machine has been doing
        draw_app_control(f, app, bottom, rules.right().saturating_sub(1));
    }

    // over the grid rather than inside the rules pane: the catalogue is
    // thirty-odd two-line entries and that pane is a quarter of one row.
    // Nothing else in this UI is modal, and this is the exception that earns
    // it — you are picking one thing and then going back
    if matches!(app.mode, Mode::Preset { .. }) {
        draw_presets(f, app, centered(outer[1], 92, 94));
    }

    draw_footer(f, app, outer[2]);
    lift_invisible_text(f, theme);
}

/// Text drawn in the colour it sits on, made readable again. A selected
/// row's background is `border_idle`, which is also the colour of every
/// dimmed span — a disabled rule, a category's lists, a flow row's reason —
/// so the quiet half of a row vanished exactly when it was selected. One
/// pass over the frame rather than a fix in every list: a list added later
/// is covered too, and the rest of the row keeps its colours.
fn lift_invisible_text(f: &mut Frame, theme: Theme) {
    for cell in f.buffer_mut().content.iter_mut() {
        if cell.bg == theme.border_idle && cell.fg == theme.border_idle {
            cell.set_fg(theme.fg);
        }
    }
}

/// per-pane identity color, in the same order as Theme.accents
fn focus_accent(focus: Focus, theme: Theme) -> Color {
    match focus {
        Focus::Rules => theme.accents[0],
        Focus::Apps => theme.accents[1],
        Focus::Conflicts => theme.accents[2],
        Focus::Flow => theme.accents[4],
        Focus::Blocking | Focus::BlockedNames => theme.accents[3],
        Focus::AppLog => theme.chart,
    }
}

/// static, starship-style status line: a colored "where you are" segment
/// plus the keys that apply right now. Never repeats transient "did X"
/// state — only an error (`app.msg`) gets appended, until the next key.
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let base = theme.base();

    // a job running off the draw loop gets the far right of the status line,
    // as its own segment: same shape as the focus segment on the left, in
    // the warn colour because it is a state that will pass. Reserved before
    // anything else is laid out, so a long key list is what gets cut, not
    // the only thing on screen saying the app is busy
    let area = match &app.busy {
        Some(busy) => {
            // 10 frames at ~100ms, from the job's own clock — without it a
            // minute-long download is indistinguishable from a freeze
            const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let frame = SPINNER[(busy.started.elapsed().as_millis() / 100) as usize % SPINNER.len()];
            let text = format!(" {frame} {}… ", busy.label);
            let w = (text.chars().count() as u16).min(area.width);
            let [keys, seg] =
                Layout::horizontal([Constraint::Min(0), Constraint::Length(w)]).areas(area);
            f.render_widget(
                Paragraph::new(text).style(
                    Style::new()
                        .bg(theme.warn)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                ),
                seg,
            );
            keys
        }
        None => area,
    };

    if matches!(app.mode, Mode::Filter) {
        let (label, buf) = match app.focus {
            Focus::AppLog => (" FILTER AUDIT — port, ip or name ", &app.log_filter),
            Focus::Conflicts => (" FILTER PORTS — port, address or app ", &app.listening_filter),
            _ => (" FILTER APPS ", &app.apps_filter),
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
        Focus::Blocking | Focus::BlockedNames => "BLOCK",
        Focus::AppLog => "AUDIT",
    };
    let focus_color = focus_accent(app.focus, theme);
    let mut keys: Vec<(&str, &str)> = match (app.focus, &app.mode) {
        (Focus::Apps, _) => vec![
            ("h/l", "pane"),
            ("j/k", "select"),
            ("a", "audit app"),
            ("y/n", "allow/deny app"),
            ("space", "toggle"),
            ("d", "remove"),
            ("/", "filter"),
        ],
        (Focus::Flow, _) => vec![
            ("h/l", "pane"),
            ("j/k", "select"),
            ("a", "audit app"),
            ("y/n", "allow/deny row"),
            ("Y/N", "allow/deny host"),
        ],
        (Focus::Blocking, _) => vec![
            ("h/l", "names"),
            ("j/k", "category"),
            ("space", "block/unblock"),
            ("s", "switch list"),
            ("u", "update lists"),
        ],
        (Focus::BlockedNames, _) => vec![
            ("h/l", "categories"),
            ("j/k", "name"),
            ("y", "never block it"),
        ],
        (Focus::Conflicts, _) => vec![
            ("h/l", "audit"),
            ("j/k", "select"),
            ("a", "audit app"),
            ("y/n", "allow/deny port"),
            ("/", "filter"),
        ],
        (Focus::AppLog, _) if app.app_log_confirm_flush => {
            vec![("y", "confirm flush"), ("n", "cancel")]
        }
        (Focus::AppLog, _) => vec![
            ("h/l", "ports"),
            ("j/k", "move"),
            ("/", "filter"),
            ("f", "flush"),
        ],
        (Focus::Rules, Mode::Preset { .. }) => vec![
            ("type", "filter"),
            ("↑/↓", "move"),
            ("Enter", "add"),
            ("Esc", "cancel"),
        ],
        (Focus::Rules, _) => vec![
            ("h/l", "pane"),
            ("j/k", "move"),
            ("space", "toggle"),
            ("d", "delete"),
            ("a", "add"),
            ("p", "presets"),
        ],
    };
    let tab = in_tab(app.focus);
    if !tab {
        keys.push(("A", "audit"));
        keys.push(("B", "blocking"));
    }
    keys.push(("t", "theme"));
    if !(tab && app.app_log_confirm_flush) {
        keys.push(("q", if tab { "back" } else { "quit" }));
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
    // the blocklists' one headline, so leaving them in a tab does not mean
    // losing sight of whether they are on
    let blocking = if !app.blocklist.enabled {
        "off (B)".to_string()
    } else if app.blocklist.queries == 0 {
        "on (B)".to_string()
    } else {
        format!(
            "{:.1}% of lookups (B)",
            app.blocklist.blocked as f64 / app.blocklist.queries as f64 * 100.0
        )
    };
    // what the daemon does with a connection no rule covers — the single
    // most consequential setting there is, and the one you most need to see
    // before wondering why nothing is asking you anything
    let auto = match app.cfg.auto.active() {
        Some(f) => format!("on/{} (m)", f.as_str()),
        None => "off (m)".to_string(),
    };
    let status = format!(
        "guardit  |  if: {ifaces}  |  daemon: {daemon}  |  auto: {auto}  |  blocking: {blocking}  |  theme: {} (t)",
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
            // the audit tab is where you go to ask why, so the reason rides
            // in the verdict's own column rather than costing an eighth one
            let status = match e.why.as_deref().or(e.denied_by.map(|b| b.as_str())) {
                Some(why) => format!("{status} · {why}"),
                None => status.to_string(),
            };
            Row::new(vec![
                Cell::from(ago),
                Cell::from(e.direction.as_str()),
                Cell::from(basename(&e.exe).to_string()),
                Cell::from(e.proto.clone()),
                Cell::from(e.port.map(|p| p.to_string()).unwrap_or_default()),
                Cell::from(e.peer()),
                Cell::from(status.clone()),
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
            // wide enough for the verdict and the reason auto mode gives for
            // it — the last column, and this tab is full-screen
            Constraint::Length(28),
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

/// a rect `pct_w` x `pct_h` percent of `area`, centered — the one modal in
/// this UI (the preset catalogue) and nothing else needs it yet
fn centered(area: Rect, pct_w: u16, pct_h: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Percentage(pct_h)])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::horizontal([Constraint::Percentage(pct_w)])
        .flex(Flex::Center)
        .areas(row);
    cell
}

/// The preset catalogue, as a modal over the grid.
fn draw_presets(f: &mut Frame, app: &App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let Mode::Preset { sel, filter } = &app.mode else {
        return;
    };
    f.render_widget(Clear, area);
    let hits = matching_presets(filter);
    let dim = Style::new().fg(theme.border_idle);
    let items: Vec<ListItem> = hits
        .iter()
        .map(|p| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!("{:<8}", format!("[{}]", p.group)), dim),
                    Span::styled(p.name, Style::new().fg(theme.fg)),
                    Span::styled(
                        match p.specs.len() {
                            1 => String::new(),
                            n => format!("  ({n} rules)"),
                        },
                        dim,
                    ),
                ]),
                // the note is the half that decides whether you want this
                // preset, so it is always on screen — dimmed, never hidden
                // behind a second keystroke
                Line::styled(format!("        {}", p.note), dim),
            ])
        })
        .collect();
    let title = if filter.is_empty() {
        format!("presets — {} of them, type to filter", PRESETS.len())
    } else if hits.is_empty() {
        format!("presets — nothing matches {filter:?}")
    } else {
        format!("presets — {filter:?}: {} of {}", hits.len(), PRESETS.len())
    };
    let mut state = ListState::default().with_selected(Some(*sel));
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(Style::new().bg(theme.border_idle).add_modifier(Modifier::BOLD))
        // a background alone is easy to lose in a light theme, and this is
        // the one list where picking the wrong row writes rules
        .highlight_symbol("\u{203a} ")
        .block(theme.pane(title, true));
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_rules(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let focused = app.focus == Focus::Rules;
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
            // two lines, not one: the source is the identifying half of a
            // rule and this pane is the narrow column, so a single line
            // would truncate exactly the part you read. Height is what the
            // column has to spare
            ListItem::new(vec![
                Line::from(format!(
                    "#{:<3} {:<6} {}{}",
                    r.id,
                    format!("{:?}", r.action).to_uppercase(),
                    format!("{:?}", r.proto).to_lowercase(),
                    if r.enabled { "" } else { "  (off)" },
                )),
                Line::from(format!(
                    "  {}{}{}",
                    r.src,
                    r.port.map(|p| format!(":{p}")).unwrap_or_default(),
                    // only when it is *not* both: a direction on every row
                    // would be noise on the common case
                    r.direction
                        .map(|d| format!("  {}", d.as_str()))
                        .unwrap_or_default(),
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
            // An app with per-port or per-host rules of its own has no single
            // verdict to report, so it says so rather than showing one of its
            // rules and a count of the others. The dot keeps the whole-app
            // default's colour, so what it falls back to is still visible.
            let (dot, base_color, mut status) = match (&row.rule, row.port_overrides > 0) {
                (Some(r), true) => (
                    "●",
                    if r.action == Action::Allow {
                        theme.allow
                    } else {
                        theme.deny
                    },
                    "(custom)".to_string(),
                ),
                (None, true) => ("●", theme.warn, "(custom)".to_string()),
                (Some(r), false) if r.action == Action::Allow => {
                    ("●", theme.allow, "(allow)".to_string())
                }
                (Some(_), false) => ("●", theme.deny, "(deny)".to_string()),
                (None, false) => ("●", theme.warn, "(new)".to_string()),
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
/// Blocks or unblocks the selected category.
///
/// Written straight to rules.toml rather than sent over IPC: nothing in the
/// kernel ruleset changes, and the daemon re-reads the file within seconds
/// and reloads the lists itself. The TUI's own copy is refreshed from what
/// `Config::update` returns, so a concurrent write by the daemon can't be
/// clobbered.
fn toggle_category(app: &mut App) {
    let Some(cat) = app
        .blocking_state
        .selected()
        .and_then(|i| blocklist::CATEGORIES.get(i))
    else {
        return;
    };
    let key = cat.key.to_string();
    let was_enabled = app.cfg.blocklist.enabled;
    app.cfg = Config::update(|cfg| {
        if let Some(i) = cfg.blocklist.categories.iter().position(|k| *k == key) {
            cfg.blocklist.categories.remove(i);
        } else {
            cfg.blocklist.categories.push(key.clone());
            // turning a category on with blocking off would look like
            // nothing happened at all
            cfg.blocklist.enabled = true;
        }
    });
    // the encrypted-dns half of blocking lives in the kernel ruleset, so
    // switching blocking on here has to reload it — the daemon's own
    // re-read only covers the lists
    if !was_enabled && app.cfg.blocklist.enabled {
        let cfg = Config::load();
        apply_ruleset(app, cfg);
    }
    if let Some(ipc) = &mut app.ipc {
        ipc.send(&ClientMsg::Reload);
    }
    if !app.cfg.blocklist.categories.iter().any(|k| *k == cat.key) {
        app.msg = format!("no longer blocking {}", cat.key);
        return;
    }
    // a category whose lists are not on disk yet blocks nothing, so ticking
    // it has to fetch them — otherwise the box is ticked, the numbers do not
    // move, and nothing is actually blocked until someone presses u
    app.msg = if fetch_missing(app) {
        format!("blocking {} — downloading its lists", cat.key)
    } else {
        format!("blocking {}", cat.key)
    };
}

/// Switches the selected category to its next list (blocklist::
/// source_choices), wrapping round to the catalogue's choice.
///
/// The same write as editing its line under `[blocklist.category_sources]`
/// by hand, and like `toggle_category` it goes to rules.toml rather than
/// over IPC. A set of lists put together by hand is not one of the choices,
/// so `s` steps off it to the default rather than guessing where it sits.
fn cycle_source(app: &mut App) {
    let Some(cat) = app
        .blocking_state
        .selected()
        .and_then(|i| blocklist::CATEGORIES.get(i))
    else {
        return;
    };
    let choices = blocklist::source_choices(cat);
    let now = blocklist::category_sources(&app.cfg.blocklist, cat.key);
    let next = choices
        .iter()
        .position(|c| *c == now)
        .map_or(0, |i| (i + 1) % choices.len());
    let pick = choices[next].clone();
    let key = cat.key.to_string();
    app.cfg = Config::update(|cfg| {
        cfg.blocklist.category_sources.insert(key, pick.clone());
    });
    if let Some(ipc) = &mut app.ipc {
        ipc.send(&ClientMsg::Reload);
    }
    app.msg = format!("{} now uses {}", cat.key, pick.join(", "));
    if fetch_missing(app) {
        app.msg.push_str(" — downloading");
    }
}

/// Downloads the enabled lists when any of them is not on disk yet: a list
/// that is not there blocks nothing, so whatever switched it on has to
/// fetch it. True when that started a download.
fn fetch_missing(app: &mut App) -> bool {
    let missing = app.cfg.blocklist.enabled
        && blocklist::effective_sources(&app.cfg.blocklist)
            .iter()
            .any(|k| blocklist::cached_at(k).is_none());
    if missing {
        update_blocklists(app);
    }
    missing
}

fn config_mtime() -> Option<std::time::SystemTime> {
    std::fs::metadata(config_path())
        .and_then(|m| m.modified())
        .ok()
}

/// Picks up a hand edit of rules.toml — a category's lists, a rule, auto
/// mode — so the screen says what the file says, as the daemon does. A list
/// the edit switched on is fetched, same as ticking it here would. A file
/// that no longer parses keeps what is on screen and says why, once.
fn reload_cfg_if_edited(app: &mut App) {
    let mtime = config_mtime();
    if mtime == app.cfg_mtime {
        return;
    }
    app.cfg_mtime = mtime;
    match Config::try_load() {
        Ok(cfg) => {
            let blocklist_changed = cfg.blocklist != app.cfg.blocklist;
            app.cfg = cfg;
            if blocklist_changed {
                fetch_missing(app);
            }
        }
        Err(e) => app.msg = e,
    }
}

/// Runs `job` on a thread, with `label` in the footer until it finishes.
///
/// One at a time: both jobs here rewrite the same state, and a UI that can
/// only show one of them running should only be able to start one.
fn start_busy(app: &mut App, label: &'static str, job: impl FnOnce() -> String + Send + 'static) {
    if app.busy.is_some() {
        app.msg = "still working — one thing at a time".into();
        return;
    }
    let (tx, rx) = mpsc::channel();
    app.busy = Some(Busy {
        label,
        started: Instant::now(),
        rx,
    });
    std::thread::spawn(move || {
        let _ = tx.send(job());
    });
}

/// Downloads the enabled lists, off the draw loop.
///
/// A category can bring in half a dozen lists and one of them is 39 MB, so
/// doing this inline would freeze the UI for a minute with nothing on
/// screen to say why.
fn update_blocklists(app: &mut App) {
    let cfg = app.cfg.blocklist.clone();
    if blocklist::effective_sources(&cfg).is_empty() {
        app.msg = "nothing to download — space to block a category".into();
        return;
    }
    start_busy(app, "updating domains", move || {
        let results = blocklist::update_all(&cfg);
        let failed: Vec<&str> = results
            .iter()
            .filter(|(_, r)| r.is_err())
            .map(|(k, _)| k.as_str())
            .collect();
        if failed.is_empty() {
            format!("downloaded {} list(s)", results.len())
        } else {
            format!(
                "{} of {} lists failed: {}",
                failed.len(),
                results.len(),
                failed.join(", ")
            )
        }
    });
}

/// Loads the ruleset into the kernel, off the draw loop.
///
/// Usually fast, but it is an `nft -f` of the whole table and the
/// encrypted-dns sets alone carry ~1500 addresses, so it is not always
/// instant — and the config on disk is already the source of truth by the
/// time this runs, so nothing depends on it having finished.
fn apply_ruleset(app: &mut App, cfg: Config) {
    start_busy(app, "applying ruleset", move || match ruleset::apply(&cfg) {
        Ok(()) => String::new(),
        Err(e) => format!("apply failed: {e}"),
    });
}

/// picks up a finished job and tells the daemon to re-read what changed —
/// which is what makes the domain count on screen move
fn drain_busy(app: &mut App) {
    let Some(busy) = &app.busy else { return };
    match busy.rx.try_recv() {
        Ok(msg) => {
            if !msg.is_empty() {
                app.msg = msg;
            }
            app.busy = None;
            if let Some(ipc) = &mut app.ipc {
                ipc.send(&ClientMsg::Reload);
            }
        }
        Err(mpsc::TryRecvError::Disconnected) => app.busy = None,
        Err(mpsc::TryRecvError::Empty) => {}
    }
}

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

/// The category switches: one row per thing you can block, ticked when it
/// is on. Several at once is the normal case, so these are checkboxes and
/// not a menu — `space` toggles the selected one.
fn draw_categories(f: &mut Frame, app: &mut App, area: Rect, focused: bool) {
    let theme = THEMES[app.theme_idx];
    let dim = Style::new().fg(theme.border_idle);
    let cfg = &app.cfg.blocklist;
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("block ", half_heading(theme, focused)),
            // app.msg is wiped by the next keypress, so the one long-running
            // thing this pane does says so here instead
            Span::styled(format!("({} on)", cfg.categories.len()), dim),
        ]))
        .style(theme.base()),
        head,
    );
    let key_width = blocklist::CATEGORIES
        .iter()
        .map(|c| c.key.len())
        .max()
        .unwrap_or(0);
    // what is left of the row after "[x] ", the name, and two spaces
    let room = (body.width as usize).saturating_sub(4 + key_width + 2);
    let items: Vec<ListItem> = blocklist::CATEGORIES
        .iter()
        .map(|c| {
            let ticked = cfg.categories.iter().any(|k| k == c.key);
            let (mark, color) = if ticked {
                ("[x]", theme.deny)
            } else {
                ("[ ]", theme.border_idle)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{mark} {:<key_width$}  ", c.key),
                    Style::new().fg(color),
                ),
                Span::styled(
                    lists_label(&blocklist::category_sources(cfg, c.key), room),
                    dim,
                ),
            ]))
        })
        .collect();
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(if focused {
            Style::new().bg(theme.border_idle)
        } else {
            Style::new()
        });
    f.render_stateful_widget(list, body, &mut app.blocking_state);
}

/// A category's lists in `room` columns: all of them when they fit, else
/// the first and how many more — cut off mid-name, a list key reads as a
/// different list.
fn lists_label(keys: &[String], room: usize) -> String {
    let all = keys.join(", ");
    let label = match keys {
        [] => "no list".into(),
        [first, rest @ ..] if !rest.is_empty() && all.chars().count() > room => {
            format!("{first} +{}", rest.len())
        }
        _ => all,
    };
    if label.chars().count() <= room {
        return label;
    }
    let mut cut: String = label.chars().take(room.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// The blocking tab: what is blocked, how well it is going, and the
/// switches for changing it.
///
/// Its own tab rather than a column in the grid. Blocking is set up now and
/// then and read occasionally; the grid is for the thing you operate, and
/// giving a third of it to something you only read made the tool look like
/// an ad blocker that happened to have a firewall in it.
///
/// Three columns at tab width, stacked in the order they matter when there
/// is not room for three: the figures, the switches, then what was blocked.
fn draw_blocking(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let b = app.blocklist.clone();
    let block = theme.pane(
        if b.enabled {
            "ads & tracking".to_string()
        } else {
            "ads & tracking — off".to_string()
        },
        true,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let dim = Style::new().fg(theme.border_idle);
    // wide enough for three columns, or stacked; either way the switches are
    // never the thing that gets dropped, since they are why you came here
    let columns = if inner.width >= 90 { 3 } else { 1 };
    let (stats_area, cats_area, recent_area) = if columns == 3 {
        let [a, b, c] = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        // columns that touch read as one run-on line
        .spacing(3)
        .areas(inner);
        (a, b, Some(c))
    } else {
        let [a, b] =
            Layout::vertical([Constraint::Length(11), Constraint::Min(0)]).areas(inner);
        (a, b, None)
    };

    if !b.enabled {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "blocking is off",
                    Style::new().fg(theme.warn).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled("tick a category with space —", dim)),
                Line::from(Span::styled("names on its lists are then", dim)),
                Line::from(Span::styled("refused at the DNS answer,", dim)),
                Line::from(Span::styled("before anything connects", dim)),
            ])
            .style(theme.base()),
            stats_area,
        );
        draw_halves(f, app, cats_area, recent_area);
        return;
    }

    let allowed = b.queries.saturating_sub(b.blocked);
    let rate = if b.queries == 0 {
        0.0
    } else {
        b.blocked as f64 / b.queries as f64 * 100.0
    };

    let mut rest = stats_area;
    if let Some(area) = take_rows(&mut rest, 2) {
        let [head, bar] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
        // each end of the bar gets its own share, labelled at its own end —
        // so the line reads as the bar underneath it does
        let blocked = format!("{rate:.1}%");
        let allowed_pct = format!("{:.1}%", 100.0 - rate);
        let gap = (head.width as usize).saturating_sub(
            "blocked ".len() + blocked.len() + "allowed ".len() + allowed_pct.len(),
        );
        let mut spans = vec![
            Span::styled("blocked ", dim),
            Span::styled(
                blocked,
                Style::new().fg(theme.deny).add_modifier(Modifier::BOLD),
            ),
        ];
        if gap > 0 {
            spans.push(Span::styled(" ".repeat(gap), theme.base()));
            spans.push(Span::styled("allowed ", dim));
            spans.push(Span::styled(
                allowed_pct,
                Style::new().fg(theme.allow).add_modifier(Modifier::BOLD),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)).style(theme.base()), head);
        f.render_widget(
            Paragraph::new(stacked_bar(bar.width, b.blocked, allowed, theme)).style(theme.base()),
            bar,
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
    if let Some((exe, n)) = b.by_app.first() {
        lines.push(Line::from(vec![
            Span::styled("worst   ", dim),
            Span::styled(basename(exe).to_string(), Style::new().fg(theme.deny)),
            Span::styled(format!(" {}", group(*n)), dim),
        ]));
    }
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

    draw_halves(f, app, cats_area, recent_area);
}

/// The blocking tab's two halves: side by side when the layout has a
/// column for the names, else whichever one has the focus — stacked, the
/// figures take the top and one list gets all the room below them.
fn draw_halves(f: &mut Frame, app: &mut App, cats_area: Rect, recent_area: Option<Rect>) {
    let names = app.focus == Focus::BlockedNames;
    match recent_area {
        Some(recent_area) => {
            draw_categories(f, app, cats_area, !names);
            draw_blocked_names(f, app, recent_area, names);
        }
        None if names => draw_blocked_names(f, app, cats_area, true),
        None => draw_categories(f, app, cats_area, true),
    }
}

/// The names most recently refused, newest first. A false positive shows up
/// here the moment a page breaks, so it is a list to move through and `y` a
/// name on, not only a readout.
fn draw_blocked_names(f: &mut Frame, app: &mut App, area: Rect, focused: bool) {
    let theme = THEMES[app.theme_idx];
    let dim = Style::new().fg(theme.border_idle);
    if area.height < 2 {
        return;
    }
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "recently blocked",
            half_heading(theme, focused),
        )))
        .style(theme.base()),
        head,
    );
    if app.blocklist.recent.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("nothing yet", dim))).style(theme.base()),
            body,
        );
        return;
    }
    let width = body.width as usize;
    let items: Vec<ListItem> = app
        .blocklist
        .recent
        .iter()
        .rev()
        .map(|entry| {
            // who asked, when we know it — more use than how long ago
            let tail = match &entry.exe {
                Some(exe) => basename(exe).to_string(),
                None => ago(now_ts().saturating_sub(entry.ts)),
            };
            let room = width.saturating_sub(tail.chars().count() + 2);
            let name = if entry.name.chars().count() > room && room > 1 {
                format!("{}…", entry.name.chars().take(room - 1).collect::<String>())
            } else {
                entry.name.clone()
            };
            ListItem::new(Line::from(vec![
                Span::styled(name, Style::new().fg(theme.deny)),
                Span::styled(format!(" {tail}"), dim),
            ]))
        })
        .collect();
    let list = List::new(items)
        .style(theme.base())
        .highlight_style(if focused {
            Style::new().bg(theme.border_idle)
        } else {
            Style::new()
        });
    f.render_stateful_widget(list, body, &mut app.blocked_state);
}

/// New figures from the daemon. The recent names are drawn newest first, so
/// every new block pushes the rest down a row; the selection follows the
/// name it was on, or `y` could allow a name nobody looked at.
fn set_blocklist_stats(app: &mut App, stats: ipc::BlocklistStats) {
    let picked = app
        .blocked_state
        .selected()
        .and_then(|i| app.blocklist.recent.iter().rev().nth(i))
        .map(|e| (e.ts, e.name.clone()));
    app.blocklist = stats;
    if let Some((ts, name)) = picked
        && let Some(i) = app
            .blocklist
            .recent
            .iter()
            .rev()
            .position(|e| e.ts == ts && e.name == name)
    {
        app.blocked_state.select(Some(i));
    }
}

/// `y` on a recently blocked name: never block it again, nor anything under
/// it — the allowlist entry `guardit blocklist allow` writes, and like the
/// category switches it goes to rules.toml for the daemon to pick up.
fn allow_blocked_name(app: &mut App) {
    let Some(entry) = app
        .blocked_state
        .selected()
        .and_then(|i| app.blocklist.recent.iter().rev().nth(i))
    else {
        return;
    };
    let name = entry.name.trim_end_matches('.').to_ascii_lowercase();
    if let Err(e) = config::validate_host(&name) {
        app.msg = e;
        return;
    }
    if app.cfg.blocklist.allow.contains(&name) {
        app.msg = format!("{name} is already allowed");
        return;
    }
    app.cfg = Config::update(|cfg| {
        if !cfg.blocklist.allow.contains(&name) {
            cfg.blocklist.allow.push(name.clone());
        }
    });
    if let Some(ipc) = &mut app.ipc {
        ipc.send(&ClientMsg::Reload);
    }
    app.msg = format!("{name} will never be blocked, nor anything under it");
}

fn draw_flow(f: &mut Frame, app: &mut App, area: Rect) {
    let theme = THEMES[app.theme_idx];
    let heading = match app.apps_state.selected().and_then(|i| app.apps.get(i)) {
        Some(row) => basename(&row.exe).to_string(),
        None => "select an app".to_string(),
    };
    let idxs = current_flow_indices(app);
    let width = area.width.saturating_sub(2) as usize;
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
            // the reason gets its columns reserved before the peer is laid
            // out: a truncated "· unres" reads as a bug, and the peer is the
            // field with room to give
            let reason = match (e.why.as_deref(), e.denied_by) {
                // auto mode's own words — "smb", "volatile path" — say more
                // than the name of the mechanism that produced them, and are
                // the only thing on the row that explains an *allow*
                (Some(why), _) => format!("  · {why}"),
                (None, Some(by)) => format!("  · {}", by.as_str()),
                (None, None) => String::new(),
            };
            let head = format!(
                "{tag}  {:<4}/{:<4}  port {:<6}  ",
                e.proto,
                e.direction.as_str(),
                e.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            );
            let room = width
                .saturating_sub(head.chars().count() + reason.chars().count());
            let peer = e.peer();
            let peer = if peer.chars().count() > room && room > 1 {
                format!("{}…", peer.chars().take(room - 1).collect::<String>())
            } else {
                peer
            };
            let text = format!("{head}{peer}");
            let mut style = Style::new().fg(color);
            if matches!(status, FlowStatus::Pending) {
                style = style.add_modifier(Modifier::BOLD);
            }
            // a red row is a question — your rule, or a list? — and only the
            // row itself can answer it
            if reason.is_empty() {
                ListItem::new(text).style(style)
            } else {
                ListItem::new(Line::from(vec![
                    Span::styled(text, style),
                    Span::styled(reason, Style::new().fg(theme.border_idle)),
                ]))
            }
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
    let title = if !conflicts.is_empty() {
        format!("listening ports — {} REAL CONFLICT(S)", conflicts.len())
    } else {
        let scope = match &app.app_log_filter {
            Some(exe) => format!(" — {}", basename(exe)),
            None => String::new(),
        };
        let needle = if app.listening_filter.is_empty() {
            String::new()
        } else {
            format!(" /{}", app.listening_filter)
        };
        format!(
            "listening ports{scope}{needle} ({})",
            app.listening.len()
        )
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

    /// the picker feeds these straight into `parse_spec(..).expect(..)`, so a
    /// typo anywhere in the catalogue is a panic in front of the user rather
    /// than an error message. Nothing else checks them.
    #[test]
    fn every_built_in_preset_parses() {
        for p in PRESETS {
            assert!(!p.specs.is_empty(), "preset {:?} does nothing", p.name);
            for spec in p.specs {
                assert!(
                    parse_spec(spec).is_ok(),
                    "preset {:?} spec {spec:?}: {:?}",
                    p.name,
                    parse_spec(spec).unwrap_err()
                );
            }
        }
    }

    /// the off switch has to be an *unqualified* accept — any proto, any
    /// source, any port. A preset that quietly narrowed to tcp/443 would
    /// still read "Allow everything" in the list while leaving udp filtered.
    #[test]
    fn the_first_preset_allows_literally_everything() {
        let p = &PRESETS[0];
        assert_eq!(p.specs.len(), 1, "{}", p.name);
        let r = parse_spec(p.specs[0]).expect("parses");
        assert_eq!(r.action, Action::Allow, "{}", p.name);
        assert_eq!(r.proto, Proto::Any, "{}", p.name);
        assert_eq!(r.src, "any", "{}", p.name);
        assert_eq!(r.port, None, "{}", p.name);
        assert_eq!(r.direction, None, "{}", p.name);
    }

    /// the catalogue is only navigable by typing, so a group tag that is not
    /// one of the documented handful is a preset nobody will find
    #[test]
    fn every_preset_is_findable_by_its_own_group_and_name() {
        for p in PRESETS {
            assert!(
                ["off", "lan", "in", "out", "harden", "bundle"].contains(&p.group),
                "unknown group {:?} on {:?}",
                p.group,
                p.name
            );
            assert!(
                matching_presets(p.group).iter().any(|m| m.name == p.name),
                "{:?} is not reachable by typing its group",
                p.name
            );
            let word = p.name.split_whitespace().next().unwrap();
            assert!(
                matching_presets(word).iter().any(|m| m.name == p.name),
                "{:?} is not reachable by typing {word:?}",
                p.name
            );
        }
    }

    #[test]
    fn filtering_is_case_insensitive_and_matches_the_note_too() {
        assert!(!matching_presets("SSH").is_empty());
        assert!(!matching_presets("ssh").is_empty());
        assert!(!matching_presets("spam").is_empty(), "a word only the notes use");
        assert!(matching_presets("zzzz").is_empty());
        assert_eq!(matching_presets("").len(), PRESETS.len(), "no filter, no narrowing");
    }

    /// picking a bundle twice, or two bundles that overlap, must not leave a
    /// pile of identical rules to delete by hand
    #[test]
    fn a_preset_adds_only_the_rules_that_are_not_already_there() {
        let mut app = new_app(Config::default());
        let bundle = PRESETS
            .iter()
            .find(|p| p.specs.len() > 2)
            .expect("the catalogue has multi-rule presets");
        // apply_preset saves to /etc, which a test must not do — so exercise
        // the deduplication through the same comparison it uses
        for spec in bundle.specs {
            let mut r = parse_spec(spec).unwrap();
            r.id = app.cfg.next_id();
            app.cfg.rule.push(r);
        }
        let before = app.cfg.rule.len();
        assert_eq!(before, bundle.specs.len());
        let dups = bundle
            .specs
            .iter()
            .map(|s| parse_spec(s).unwrap())
            .filter(|r| {
                app.cfg.rule.iter().any(|e| {
                    e.action == r.action
                        && e.proto == r.proto
                        && e.src == r.src
                        && e.port == r.port
                        && e.direction == r.direction
                })
            })
            .count();
        assert_eq!(dups, bundle.specs.len(), "every rule reads as already present");
    }

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
            denied_by: None,
            why: None,
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
                ipc::Blocked {
                    ts: now_ts() - 400,
                    name: "ads.doubleclick.net".into(),
                    exe: Some("/usr/bin/firefox".into()),
                },
                ipc::Blocked {
                    ts: now_ts() - 90,
                    name: "telemetry.microsoft.com".into(),
                    exe: None,
                },
                ipc::Blocked {
                    ts: now_ts() - 5,
                    name: "graph.facebook.com".into(),
                    exe: Some("/usr/bin/firefox".into()),
                },
            ],
            by_app: vec![("/usr/bin/firefox".into(), 2_301)],
            updated_at: Some(now_ts() - 7200),
        };
            app.cfg.rule = vec![Rule {
            id: 1,
            action: Action::Allow,
            proto: Proto::Tcp,
            src: "192.168.1.0/24".into(),
            direction: None,
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

    /// The sequence that used to strand you: open the blocking tab, open the
    /// audit tab from inside it, then come back. `prev_focus` had been set
    /// to the blocking tab on the way through, so leaving audit landed there
    /// and leaving *that* went to itself — `q` and `B` both did nothing.
    #[test]
    fn no_route_through_the_tabs_leaves_you_without_a_way_back() {
        let mut app = new_app(Config::default());
        app.focus = Focus::Flow;

        enter_tab(&mut app, Focus::Blocking);
        enter_tab(&mut app, Focus::AppLog);
        leave_tab(&mut app);
        assert!(!in_tab(app.focus), "stranded in a tab: {:?}", app.focus);
        assert_eq!(app.focus, Focus::Flow, "and back where you started");

        // every order of the two tabs, in and out, ends in the grid
        for first in [Focus::Blocking, Focus::AppLog] {
            for second in [Focus::Blocking, Focus::AppLog, Focus::Conflicts] {
                app.focus = Focus::Rules;
                enter_tab(&mut app, first);
                enter_tab(&mut app, second);
                leave_tab(&mut app);
                assert!(!in_tab(app.focus), "{first:?} then {second:?}");
                leave_tab(&mut app);
                assert!(!in_tab(app.focus), "{first:?} then {second:?}, twice out");
            }
        }

        // and a prev_focus that somehow holds a tab still lets you out
        app.focus = Focus::Blocking;
        app.prev_focus = Focus::AppLog;
        leave_tab(&mut app);
        assert!(!in_tab(app.focus));
    }

    #[test]
    fn lists_that_do_not_fit_shorten_to_the_first_and_a_count() {
        let keys: Vec<String> = vec!["a:one".into(), "b:two".into(), "c:three".into()];
        assert_eq!(lists_label(&keys, 80), "a:one, b:two, c:three");
        assert_eq!(lists_label(&keys, 10), "a:one +2");
        // and cut, visibly, when even that does not fit
        assert_eq!(lists_label(&keys, 5), "a:on…");
        assert_eq!(lists_label(&keys[..1], 4), "a:o…");
        assert_eq!(lists_label(&[], 10), "no list");
    }

    #[test]
    fn a_new_block_does_not_move_the_selection_off_its_name() {
        let mut app = demo_app();
        app.blocked_state.select(Some(1));
        let picked = app
            .blocklist
            .recent
            .iter()
            .rev()
            .nth(1)
            .unwrap()
            .name
            .clone();
        let mut stats = app.blocklist.clone();
        stats.recent.push(ipc::Blocked {
            ts: now_ts(),
            name: "new.example.com".into(),
            exe: None,
        });
        set_blocklist_stats(&mut app, stats);
        let i = app.blocked_state.selected().unwrap();
        assert_eq!(i, 2, "one row further down, where its name went");
        assert_eq!(
            app.blocklist.recent.iter().rev().nth(i).unwrap().name,
            picked
        );
    }

    #[test]
    fn selected_rows_stay_readable_in_every_theme() {
        for (theme_idx, theme) in THEMES.iter().enumerate() {
            let mut app = demo_app();
            app.theme_idx = theme_idx;
            // the dimmed rows: a disabled rule, a category's lists
            if let Some(r) = app.cfg.rule.first_mut() {
                r.enabled = false;
            }
            app.state.select(Some(0));
            let mut term = Terminal::new(TestBackend::new(130, 40)).unwrap();
            for focus in [
                Focus::Rules,
                Focus::Apps,
                Focus::Flow,
                Focus::Blocking,
                Focus::BlockedNames,
                Focus::AppLog,
                Focus::Conflicts,
            ] {
                app.focus = focus;
                term.draw(|f| draw(f, &mut app)).unwrap();
                for cell in &term.backend().buffer().content {
                    assert!(
                        cell.symbol() == " "
                            || cell.bg != theme.border_idle
                            || cell.fg != theme.border_idle,
                        "{} in {focus:?}: {:?} drawn on its own colour",
                        theme.name,
                        cell.symbol()
                    );
                }
            }
        }
    }

    #[test]
    fn a_policy_refusal_is_never_recomputed_back_to_allowed() {
        let allow_whole_app = AppRule {
            id: 1,
            exe: "/usr/bin/firefox".into(),
            port: None,
            direction: None,
            action: Action::Allow,
            enabled: true,
            expires: None,
            fingerprint: None,
            host: None,
        };
        let rules = vec![allow_whole_app];

        let mut row = demo_flow(443, "1.2.3.4", Some("ads.example.com"), "/usr/bin/firefox");
        row.status = FlowStatus::Denied;

        // this is what the pane used to do: read the rules, find the allow,
        // and paint the row green while the daemon went on dropping it
        assert_eq!(
            effective_status(&row, &rules),
            FlowStatus::Allowed,
            "no reason recorded, so the rules decide — as they should"
        );

        row.denied_by = Some(ipc::DeniedBy::Blocklist);
        assert_eq!(effective_status(&row, &rules), FlowStatus::Denied);
        row.denied_by = Some(ipc::DeniedBy::Unresolved);
        assert_eq!(effective_status(&row, &rules), FlowStatus::Denied);

        // a still-pending row is still pending, whatever else is true
        row.status = FlowStatus::Pending;
        assert_eq!(effective_status(&row, &rules), FlowStatus::Pending);
    }

    #[test]
    fn trimming_the_flow_keeps_each_apps_own_history() {
        let mut app = new_app(Config::default());
        // one chatty app and one quiet one, interleaved oldest-first
        for i in 0..(FLOW_PER_APP * 2) {
            let mut e = demo_flow(443, "1.1.1.1", None, "/usr/bin/chatty");
            e.ts = i as u64;
            app.flow.push(e);
            if i == 0 {
                let mut q = demo_flow(443, "2.2.2.2", None, "/usr/bin/quiet");
                q.ts = 0;
                app.flow.push(q);
            }
        }
        trim_flow(&mut app);
        assert_eq!(
            app.flow.iter().filter(|e| e.exe.ends_with("quiet")).count(),
            1,
            "a global cap would have evicted the quiet app entirely"
        );
        assert_eq!(
            app.flow.iter().filter(|e| e.exe.ends_with("chatty")).count(),
            FLOW_PER_APP
        );
        // and it kept the newest of the chatty ones, not the oldest
        let newest = app.flow.iter().map(|e| e.ts).max().unwrap();
        assert_eq!(newest, (FLOW_PER_APP * 2 - 1) as u64);
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
    /// eyeball the catalogue: `cargo test presets_look_right -- --ignored --nocapture`
    #[test]
    #[ignore = "prints the preset modal for a human to look at"]
    fn presets_look_right() {
        let mut app = demo_app();
        app.focus = Focus::Rules;
        app.mode = Mode::Preset {
            sel: 2,
            filter: String::new(),
        };
        let mut term = Terminal::new(TestBackend::new(120, 44)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        println!("{}", term.backend());
    }

    #[test]
    fn every_screen_renders_at_any_terminal_size() {
        for (w, h) in [(200, 60), (120, 40), (80, 24), (60, 20), (40, 12), (20, 8)] {
            let mut app = demo_app();
            app.listening_all = vec![ipc::ListenEntry {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 22,
                exe: "/usr/bin/sshd".into(),
            }];
            apply_listening_filter(&mut app);
            app.counts.insert("/usr/bin/curl".into(), 1_234_567);
            rebuild_apps(&mut app);

            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for focus in [
                Focus::Rules,
                Focus::Apps,
                Focus::Flow,
                Focus::Blocking,
                Focus::BlockedNames,
                Focus::AppLog,
                Focus::Conflicts,
            ] {
                app.focus = focus;
                term.draw(|f| draw(f, &mut app))
                    .unwrap_or_else(|e| panic!("{focus:?} at {w}x{h}: {e}"));
            }
            // the preset catalogue draws over the grid, at whatever size the
            // grid happens to be — including sizes where its own modal rect
            // rounds down to nothing
            app.focus = Focus::Rules;
            for filter in ["", "ssh", "zzzz"] {
                app.mode = Mode::Preset {
                    sel: 0,
                    filter: filter.into(),
                };
                term.draw(|f| draw(f, &mut app))
                    .unwrap_or_else(|e| panic!("presets {filter:?} at {w}x{h}: {e}"));
            }
            // a selection past the end of a narrowed list must not panic
            app.mode = Mode::Preset {
                sel: PRESETS.len() + 5,
                filter: "ssh".into(),
            };
            term.draw(|f| draw(f, &mut app)).unwrap();
            app.mode = Mode::Browse;

            // and the modal-ish states, which replace the footer
            app.focus = Focus::Apps;
            app.mode = Mode::Filter;
            app.apps_filter = "fire".into();
            term.draw(|f| draw(f, &mut app)).unwrap();
            app.focus = Focus::AppLog;
            app.mode = Mode::Filter;
            app.log_filter = "443".into();
            term.draw(|f| draw(f, &mut app)).unwrap();
            app.focus = Focus::Conflicts;
            app.listening_filter = "22".into();
            apply_listening_filter(&mut app);
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













