mod config;
mod daemon;
mod ipc;
mod ruleset;
mod tui;

use clap::{Parser, Subcommand, ValueEnum};
use config::{Action as RuleAction, Config, Direction, Proto, Rule, now_ts};
use ipc::{ClientMsg, FlowStatus, ServerMsg};

#[derive(Parser)]
#[command(name = "guardit", about = "ultra simple nftables-backed firewall")]
struct Cli {
    /// no subcommand → opens the TUI (same as `guardit tui`)
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(ValueEnum, Clone, Copy)]
enum ProtoArg {
    Tcp,
    Udp,
    Any,
}

#[derive(clap::Args)]
struct RuleArgs {
    #[arg(long, default_value = "any")]
    proto: ProtoArg,
    #[arg(long, default_value = "any")]
    src: String,
    #[arg(long)]
    port: Option<u16>,
}

#[derive(ValueEnum, Clone, Copy)]
enum DirArg {
    In,
    Out,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum VerdictArg {
    Allow,
    Deny,
}

impl From<VerdictArg> for RuleAction {
    fn from(v: VerdictArg) -> Self {
        match v {
            VerdictArg::Allow => RuleAction::Allow,
            VerdictArg::Deny => RuleAction::Deny,
        }
    }
}

#[derive(clap::Args)]
struct AppRuleArgs {
    /// full path of the executable, as shown by `guardit app list`
    exe: String,
    /// one port only (the destination port: remote for outbound, local for inbound);
    /// omit for the whole app
    #[arg(long)]
    port: Option<u16>,
    /// one direction only; omit for both
    #[arg(long)]
    dir: Option<DirArg>,
    /// expire after this long, e.g. 30s, 10m, 1h30m, 2d
    #[arg(long = "for", value_parser = parse_duration)]
    expires_in: Option<u64>,
}

#[derive(Subcommand)]
enum AppCmd {
    /// list per-app rules
    List,
    /// allow an app (whole app, or one port / direction)
    Allow(AppRuleArgs),
    /// deny an app (whole app, or one port / direction)
    Deny(AppRuleArgs),
    /// forget an app: removes its whole-app rule and every per-port override
    Rm { exe: String },
}

#[derive(Subcommand)]
enum Cmd {
    /// per-application rules (what the daemon enforces)
    #[command(subcommand)]
    App(AppCmd),
    /// connections the daemon is holding right now, waiting for a decision
    Pending,
    /// decide a pending connection by its id (see `pending`); remembered as a rule
    Answer { req_id: u32, verdict: VerdictArg },
    /// allow traffic matching a source/port
    Allow(RuleArgs),
    /// block traffic matching a source/port (kernel already denies by default — use this to
    /// carve out an explicit block inside a broader `allow`)
    Deny(RuleArgs),
    /// remove a rule by id
    Rm { id: u32 },
    /// list configured rules
    List,
    /// generate ruleset from config and load it into the kernel (needs root)
    Apply {
        /// print the generated ruleset instead of loading it
        #[arg(long)]
        dry_run: bool,
    },
    /// show currently loaded kernel ruleset
    Status,
    /// interactive rule browser
    Tui,
    /// bind NFQUEUE and enforce per-app rules (needs root; runs in the foreground,
    /// no daemonization — wrap it yourself if you want it as a service)
    Daemon {
        /// resolve and print each connection's app instead of enforcing rules (always accepts)
        #[arg(long)]
        debug: bool,
    },
    /// full audit trail of per-app connection attempts (history.jsonl — unthrottled,
    /// unlike the live TUI view which dedupes noisy repeats for readability)
    LogApp {
        #[arg(long, default_value_t = 100)]
        n: usize,
        /// only show attempts whose exe path contains this substring
        #[arg(long)]
        exe: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let cmd = cli.cmd.unwrap_or(Cmd::Tui);
    // everything except the read-only commands writes /etc/guardit, talks to
    // the kernel, or connects to the root-owned daemon socket
    let read_only = matches!(
        cmd,
        Cmd::List | Cmd::LogApp { .. } | Cmd::Apply { dry_run: true } | Cmd::App(AppCmd::List)
    );
    if !read_only && !ruleset::is_root() {
        eprintln!("guardit needs root — run with sudo");
        std::process::exit(1);
    }
    let mut cfg = Config::load();

    match cmd {
        Cmd::Allow(args) => add_rule(&mut cfg, RuleAction::Allow, args),
        Cmd::Deny(args) => add_rule(&mut cfg, RuleAction::Deny, args),
        Cmd::Rm { id } => {
            let before = cfg.rule.len();
            cfg.rule.retain(|r| r.id != id);
            if cfg.rule.len() == before {
                eprintln!("no rule #{id}");
                std::process::exit(1);
            }
            cfg.save();
            println!("removed rule #{id}");
        }
        Cmd::List => print_list(&cfg),
        Cmd::Apply { dry_run } => {
            if dry_run {
                print!("{}", ruleset::render(&cfg));
                return;
            }
            match ruleset::apply(&cfg) {
                Ok(()) => println!(
                    "applied {} rule(s)",
                    cfg.rule.iter().filter(|r| r.enabled).count()
                ),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Status => println!("{}", ruleset::status()),
        Cmd::Tui => tui::run(cfg),
        Cmd::Daemon { debug } => {
            if let Err(e) = daemon::run(cfg, debug) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Cmd::LogApp { n, exe } => daemon::print_log_app(exe.as_deref(), n),
        Cmd::App(AppCmd::List) => print_app_list(&cfg),
        Cmd::App(AppCmd::Allow(args)) => set_app_rule(RuleAction::Allow, args),
        Cmd::App(AppCmd::Deny(args)) => set_app_rule(RuleAction::Deny, args),
        Cmd::App(AppCmd::Rm { exe }) => {
            let before = cfg.app_rule.len();
            let rules = match ipc::Client::connect() {
                Ok(mut c) => c
                    .send(&ClientMsg::RmAppRule { exe: exe.clone() })
                    .and_then(|()| wait_app_rules(&mut c))
                    .unwrap_or_else(|e| fail(&format!("daemon: {e}"))),
                Err(_) => Config::update(|cfg| cfg.app_rule.retain(|r| r.exe != exe)).app_rule,
            };
            if rules.len() == before {
                fail(&format!("no rule for {exe}"));
            }
            println!("forgot {exe} ({} rule(s) removed)", before - rules.len());
        }
        Cmd::Pending => {
            let mut c = ipc::Client::connect()
                .unwrap_or_else(|e| fail(&format!("daemon not reachable: {e}")));
            let Ok(Some(ServerMsg::Snapshot { flow, .. })) = c.recv() else {
                fail("daemon sent no snapshot");
            };
            let pending: Vec<_> = flow
                .iter()
                .filter(|f| f.status == FlowStatus::Pending)
                .collect();
            if pending.is_empty() {
                println!("nothing pending");
                return;
            }
            println!(
                "{:<6}{:<5}{:<6}{:<7}{:<40}PEER",
                "ID", "DIR", "PROTO", "PORT", "EXE"
            );
            for f in pending {
                println!(
                    "{:<6}{:<5}{:<6}{:<7}{:<40}{}",
                    f.req_id.unwrap_or(0),
                    f.direction.as_str(),
                    f.proto,
                    f.port.map(|p| p.to_string()).unwrap_or_default(),
                    f.exe,
                    f.peer_ip
                );
            }
        }
        Cmd::Answer { req_id, verdict } => {
            let mut c = ipc::Client::connect()
                .unwrap_or_else(|e| fail(&format!("daemon not reachable: {e}")));
            let still_pending = matches!(c.recv(), Ok(Some(ServerMsg::Snapshot { flow, .. }))
                if flow.iter().any(|f| f.req_id == Some(req_id) && f.status == FlowStatus::Pending));
            if !still_pending {
                fail(&format!(
                    "no pending request #{req_id} (see `guardit pending`)"
                ));
            }
            c.send(&ClientMsg::Decide {
                req_id,
                verdict: verdict.into(),
            })
            .unwrap_or_else(|e| fail(&format!("daemon: {e}")));
            println!("#{req_id}: {}", format!("{verdict:?}").to_lowercase());
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

/// "1h30m", "45s", "2d" → seconds. Units s/m/h/d, any order, no spaces.
fn parse_duration(s: &str) -> Result<u64, String> {
    let bad = || format!("bad duration {s:?} (want e.g. 30s, 10m, 1h30m, 2d)");
    let mut total = 0u64;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u64 = num.parse().map_err(|_| bad())?;
        num.clear();
        let mult = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => return Err(bad()),
        };
        total = total
            .checked_add(n.checked_mul(mult).ok_or_else(bad)?)
            .ok_or_else(bad)?;
    }
    if !num.is_empty() || total == 0 {
        return Err(bad());
    }
    Ok(total)
}

/// reads until the daemon echoes the new rule list back
fn wait_app_rules(c: &mut ipc::Client) -> std::io::Result<Vec<config::AppRule>> {
    loop {
        match c.recv()? {
            Some(ServerMsg::AppRules(rules)) => return Ok(rules),
            Some(_) => {}
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "daemon closed the connection",
                ));
            }
        }
    }
}

/// through the daemon when it runs (so it enforces the rule right away),
/// straight to rules.toml otherwise (picked up when the daemon starts)
fn set_app_rule(action: RuleAction, args: AppRuleArgs) {
    let direction = args.dir.map(|d| match d {
        DirArg::In => Direction::In,
        DirArg::Out => Direction::Out,
    });
    let expires = args.expires_in.map(|secs| now_ts() + secs);
    let exe = args.exe;
    let via_daemon = match ipc::Client::connect() {
        Ok(mut c) => {
            c.send(&ClientMsg::SetAppRule {
                exe: exe.clone(),
                port: args.port,
                direction,
                action,
                expires,
            })
            .and_then(|()| wait_app_rules(&mut c))
            .unwrap_or_else(|e| fail(&format!("daemon: {e}")));
            true
        }
        Err(_) => {
            daemon::upsert_rule(&exe, args.port, direction, action, expires);
            false
        }
    };
    println!(
        "{} {exe}{}{}{}{}",
        format!("{action:?}").to_lowercase(),
        args.port.map(|p| format!(" port {p}")).unwrap_or_default(),
        direction
            .map(|d| format!(" {}", d.as_str()))
            .unwrap_or_default(),
        args.expires_in
            .map(|s| format!(" for {}", daemon::ago(s)))
            .unwrap_or_default(),
        if via_daemon {
            ""
        } else {
            " (daemon not running — saved, applies when it starts)"
        }
    );
}

fn print_app_list(cfg: &Config) {
    if cfg.app_rule.is_empty() {
        println!("no app rules");
        return;
    }
    let now = now_ts();
    println!(
        "{:<4}{:<8}{:<7}{:<5}{:<4}{:<10}EXE",
        "ID", "ACTION", "PORT", "DIR", "ON", "EXPIRES"
    );
    for r in &cfg.app_rule {
        println!(
            "{:<4}{:<8}{:<7}{:<5}{:<4}{:<10}{}{}",
            r.id,
            format!("{:?}", r.action).to_lowercase(),
            r.port.map(|p| p.to_string()).unwrap_or_else(|| "*".into()),
            r.direction.map(|d| d.as_str()).unwrap_or("*"),
            if r.enabled { "yes" } else { "no" },
            r.expires
                .map(|t| daemon::ago(t.saturating_sub(now)))
                .unwrap_or_default(),
            r.exe,
            if r.stale() { " [changed]" } else { "" },
        );
    }
}

fn add_rule(cfg: &mut Config, action: RuleAction, args: RuleArgs) {
    let rule = Rule {
        id: cfg.next_id(),
        action,
        proto: match args.proto {
            ProtoArg::Tcp => Proto::Tcp,
            ProtoArg::Udp => Proto::Udp,
            ProtoArg::Any => Proto::Any,
        },
        src: args.src,
        port: args.port,
        enabled: true,
    };
    println!("added rule #{}", rule.id);
    cfg.rule.push(rule);
    cfg.save();
}

fn print_list(cfg: &Config) {
    if cfg.rule.is_empty() {
        println!("no rules configured");
        return;
    }
    println!(
        "{:<4}{:<8}{:<6}{:<20}{:<8}{:<4}",
        "ID", "ACTION", "PROTO", "SRC", "PORT", "ON"
    );
    for r in &cfg.rule {
        println!(
            "{:<4}{:<8}{:<6}{:<20}{:<8}{:<4}",
            r.id,
            format!("{:?}", r.action).to_lowercase(),
            format!("{:?}", r.proto).to_lowercase(),
            r.src,
            r.port.map(|p| p.to_string()).unwrap_or_default(),
            if r.enabled { "yes" } else { "no" },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s"), Ok(30));
        assert_eq!(parse_duration("1h30m"), Ok(5400));
        assert_eq!(parse_duration("2d"), Ok(172800));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("1x").is_err());
    }
}
