mod blocklist;
mod config;
mod daemon;
mod ipc;
mod ruleset;
mod tui;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use config::{Action as RuleAction, Config, Direction, Proto, Rule, now_ts};
use ipc::{ClientMsg, FlowStatus, ServerMsg};

#[derive(Parser)]
#[command(
    name = "guardit",
    version,
    about = "nftables-backed firewall with per-app control and a live TUI dashboard"
)]
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
    /// only peers resolving to this name, e.g. example.com or *.example.com
    /// (wins over --port; needs the daemon's DNS tap to have seen the lookup)
    #[arg(long)]
    host: Option<String>,
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
enum BlocklistCmd {
    /// what you can block — ads, tracking, phishing, porn… — and what is on
    Categories,
    /// every individual list behind those categories
    Sources,
    /// what is on, how many domains are loaded, when each list was fetched
    Status,
    /// turn ads/tracking blocking on (enables the recommended list if none is chosen)
    On,
    /// turn it off — the downloaded lists are kept
    Off,
    /// block one or more categories (`ads`, `phishing`, `porn`…) or lists (`hagezi:pro`)
    Enable {
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// stop blocking one or more categories or lists
    Disable {
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// download the enabled lists now
    Update,
    /// never block this name, or anything under it
    Allow { domain: String },
    /// undo `allow`
    Unallow { domain: String },
    /// would this name be blocked right now, and why
    Check { domain: String },
    /// what has actually been blocked, from blocked.jsonl
    Log {
        #[arg(long, default_value_t = 100)]
        n: usize,
        /// only entries whose name or app contains this
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// ads and tracking blocking: curated domain lists, matched on every DNS lookup
    #[command(subcommand)]
    Blocklist(BlocklistCmd),
    /// per-application rules (what the daemon enforces)
    #[command(subcommand)]
    App(AppCmd),
    /// print the whole config (IP/port rules, app rules, settings) as TOML
    Export,
    /// replace the whole config with a TOML file (`-` for stdin), then reload
    /// the daemon; run `guardit apply` afterwards to load the IP/port rules
    Import { file: String },
    /// connections the daemon is holding right now, waiting for a decision
    Pending,
    /// print a shell completion script (fish: `guardit completions fish > ~/.config/fish/completions/guardit.fish`)
    Completions { shell: clap_complete::Shell },
    /// print the man page (roff): `guardit man | gzip > /usr/share/man/man1/guardit.1.gz`
    Man,
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
        Cmd::List
            | Cmd::Export
            | Cmd::LogApp { .. }
            | Cmd::Apply { dry_run: true }
            | Cmd::App(AppCmd::List)
            | Cmd::Completions { .. }
            | Cmd::Man
            | Cmd::Blocklist(
                BlocklistCmd::Categories
                    | BlocklistCmd::Sources
                    | BlocklistCmd::Status
                    | BlocklistCmd::Check { .. }
                    | BlocklistCmd::Log { .. }
            )
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
        Cmd::Blocklist(sub) => blocklist_cmd(cfg, sub),
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
        Cmd::Completions { shell } => clap_complete::generate(
            shell,
            &mut Cli::command(),
            "guardit",
            &mut std::io::stdout(),
        ),
        Cmd::Man => clap_mangen::Man::new(Cli::command())
            .render(&mut std::io::stdout())
            .unwrap_or_else(|e| fail(&format!("render man page: {e}"))),
        Cmd::Export => print!(
            "{}",
            toml::to_string_pretty(&cfg).expect("serialize config")
        ),
        Cmd::Import { file } => {
            let text = if file == "-" {
                std::io::read_to_string(std::io::stdin())
            } else {
                std::fs::read_to_string(&file)
            }
            .unwrap_or_else(|e| fail(&format!("read {file}: {e}")));
            let new: Config =
                toml::from_str(&text).unwrap_or_else(|e| fail(&format!("bad config: {e}")));
            for r in &new.rule {
                if let Err(e) = config::validate_src(&r.src) {
                    fail(&format!("bad config: rule #{}: {e}", r.id));
                }
            }
            let n_rules = new.rule.len();
            let n_app = new.app_rule.len();
            Config::update(|cfg| *cfg = new);
            let reloaded = ipc::Client::connect()
                .and_then(|mut c| {
                    c.send(&ClientMsg::Reload)
                        .and_then(|()| wait_app_rules(&mut c))
                })
                .is_ok();
            println!(
                "imported {n_rules} rule(s), {n_app} app rule(s){} — run `guardit apply` to load the IP/port rules",
                if reloaded { ", daemon reloaded" } else { "" }
            );
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
                    f.peer()
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
    if let Some(h) = &args.host
        && let Err(e) = config::validate_host(h)
    {
        fail(&e);
    }
    let exe = args.exe;
    let via_daemon = match ipc::Client::connect() {
        Ok(mut c) => {
            c.send(&ClientMsg::SetAppRule {
                exe: exe.clone(),
                port: args.port,
                direction,
                action,
                expires,
                host: args.host.clone(),
            })
            .and_then(|()| wait_app_rules(&mut c))
            .unwrap_or_else(|e| fail(&format!("daemon: {e}")));
            true
        }
        Err(_) => {
            daemon::upsert_rule(&exe, args.port, direction, action, expires, args.host.clone());
            false
        }
    };
    println!(
        "{} {exe}{}{}{}{}{}",
        format!("{action:?}").to_lowercase(),
        args.port.map(|p| format!(" port {p}")).unwrap_or_default(),
        args.host
            .as_deref()
            .map(|h| format!(" host {h}"))
            .unwrap_or_default(),
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

/// Applies a change to the blocklist section, then makes it take effect:
/// the daemon re-reads rules.toml on its own within seconds, but the nft
/// half of `block_encrypted_dns` lives in the kernel ruleset and only moves
/// when the ruleset is reloaded.
fn save_blocklist(mut cfg: Config, mutate: impl FnOnce(&mut config::BlocklistConfig)) {
    let mut section = cfg.blocklist.clone();
    mutate(&mut section);
    let reapply = section.enabled != cfg.blocklist.enabled
        || section.block_encrypted_dns != cfg.blocklist.block_encrypted_dns;
    cfg = Config::update(|fresh| fresh.blocklist = section);
    if reapply && let Err(e) = ruleset::apply(&cfg) {
        eprintln!("warning: could not reload the kernel ruleset: {e}");
    }
    if let Ok(mut c) = ipc::Client::connect() {
        let _ = c.send(&ClientMsg::Reload);
    }
}

fn blocklist_cmd(cfg: Config, sub: BlocklistCmd) {
    match sub {
        BlocklistCmd::Categories => {
            println!("{:<14}{:<8}COVERS", "CATEGORY", "LISTS");
            for c in blocklist::CATEGORIES {
                let on = cfg.blocklist.categories.iter().any(|k| k == c.key);
                println!(
                    "{} {:<12}{:<8}{}",
                    if on { "*" } else { " " },
                    c.key,
                    c.sources.len(),
                    c.about
                );
            }
            println!(
                "\n* = blocked. `guardit blocklist enable <category>`, several at a time."
            );
        }
        BlocklistCmd::Sources => {
            let on = blocklist::effective_sources(&cfg.blocklist);
            let mut category = "";
            for s in blocklist::SOURCES {
                if s.category != category {
                    category = s.category;
                    println!("\n{category}");
                }
                println!(
                    "{} {:<26}{}",
                    if on.contains(&s.key()) { "*" } else { " " },
                    s.key(),
                    s.about
                );
            }
            println!(
                "\n* = in force. Turn on a whole category with `guardit blocklist enable <category>`,"
            );
            println!("or add one list on top with `guardit blocklist enable <list>`.");
        }
        BlocklistCmd::Status => {
            let b = &cfg.blocklist;
            println!("state:         {}", if b.enabled { "on" } else { "off" });
            println!(
                "encrypted dns: {}",
                if b.block_encrypted_dns {
                    "refused (DoT/DoQ, and :443 to known DoH addresses)"
                } else {
                    "allowed — apps using DoH bypass blocking entirely"
                }
            );
            println!(
                "auto-update:   {}",
                match b.update_hours {
                    0 => "off".to_string(),
                    h => format!("every {h}h"),
                }
            );
            println!(
                "blocking:      {}",
                if b.categories.is_empty() {
                    "nothing — `guardit blocklist enable ads`".to_string()
                } else {
                    b.categories.join(", ")
                }
            );
            let keys = blocklist::effective_sources(b);
            if keys.is_empty() {
                println!("lists:         none");
            } else {
                println!("lists:");
                for key in &keys {
                    let age = match blocklist::cached_at(key) {
                        Some(t) => {
                            format!("updated {} ago", daemon::ago(now_ts().saturating_sub(t)))
                        }
                        None => "not downloaded — `guardit blocklist update`".into(),
                    };
                    println!("  {key:<26}{age}");
                }
            }
            println!("domains:       {}", blocklist::Blocklist::load(b).len());
            if !b.allow.is_empty() {
                println!("allowed:       {}", b.allow.join(", "));
            }
        }
        BlocklistCmd::On => {
            let seed = cfg.blocklist.categories.is_empty() && cfg.blocklist.sources.is_empty();
            save_blocklist(cfg, |b| {
                b.enabled = true;
                if seed {
                    b.categories = blocklist::DEFAULT_CATEGORIES
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                }
            });
            if seed {
                println!(
                    "blocking on, covering {}",
                    blocklist::DEFAULT_CATEGORIES.join(", ")
                );
            } else {
                println!("blocking on");
            }
            println!("run `guardit blocklist update` to download the lists now (the daemon does it on its own within 10 minutes)");
        }
        BlocklistCmd::Off => {
            save_blocklist(cfg, |b| b.enabled = false);
            println!("blocking off (downloaded lists kept)");
        }
        // one pair of commands for both: a category is what you normally
        // want, a list key is the escape hatch, and having to remember which
        // verb takes which would be a needless thing to remember. Both take
        // several at a time, because blocking is a set and you decide it in
        // one go — and both write once, so the daemon reloads once
        BlocklistCmd::Enable { keys } => {
            // every key is checked before any is applied: a typo in the
            // third argument must not leave the first two half-applied
            for k in &keys {
                if blocklist::category(k).is_none() && blocklist::source(k).is_none() {
                    fail(&format!(
                        "unknown {k:?} — see `guardit blocklist categories` or `... sources`"
                    ));
                }
            }
            let mut added = Vec::new();
            let mut already = Vec::new();
            save_blocklist(cfg, |b| {
                for k in &keys {
                    let on = if blocklist::category(k).is_some() {
                        &mut b.categories
                    } else {
                        &mut b.sources
                    };
                    if on.contains(k) {
                        already.push(k.clone());
                    } else {
                        on.push(k.clone());
                        added.push(k.clone());
                    }
                }
            });
            if !already.is_empty() {
                println!("already on: {}", already.join(", "));
            }
            if !added.is_empty() {
                println!("blocking {}", added.join(", "));
                println!("run `guardit blocklist update` to download the lists now");
            }
        }
        BlocklistCmd::Disable { keys } => {
            for k in &keys {
                if !cfg.blocklist.categories.contains(k) && !cfg.blocklist.sources.contains(k) {
                    fail(&format!("{k} is not on"));
                }
            }
            save_blocklist(cfg, |b| {
                b.categories.retain(|k| !keys.contains(k));
                b.sources.retain(|k| !keys.contains(k));
            });
            println!("no longer blocking {}", keys.join(", "));
        }
        BlocklistCmd::Update => {
            let results = blocklist::update_all(&cfg.blocklist);
            if results.is_empty() {
                fail("no lists enabled — `guardit blocklist enable hagezi:pro`");
            }
            let mut failed = 0;
            for (key, res) in &results {
                match res {
                    Ok(n) => println!("{key}: {n} entries"),
                    Err(e) => {
                        failed += 1;
                        eprintln!("{key}: {e}");
                    }
                }
            }
            if let Ok(mut c) = ipc::Client::connect() {
                let _ = c.send(&ClientMsg::Reload);
            }
            if failed > 0 {
                std::process::exit(1);
            }
        }
        BlocklistCmd::Allow { domain } => {
            if let Err(e) = config::validate_host(&domain) {
                fail(&e);
            }
            if cfg.blocklist.allow.contains(&domain) {
                println!("{domain} is already allowed");
                return;
            }
            save_blocklist(cfg, |b| b.allow.push(domain.clone()));
            println!("{domain} will never be blocked (nor anything under it)");
        }
        BlocklistCmd::Unallow { domain } => {
            if !cfg.blocklist.allow.contains(&domain) {
                fail(&format!("{domain} is not in the allowlist"));
            }
            save_blocklist(cfg, |b| b.allow.retain(|d| *d != domain));
            println!("{domain} removed from the allowlist");
        }
        BlocklistCmd::Log { n, filter } => {
            let entries = daemon::read_blocked(n, filter.as_deref());
            if entries.is_empty() {
                println!("nothing blocked yet");
                return;
            }
            let now = now_ts();
            println!("{:<8}{:<26}NAME", "AGO", "APP");
            for e in entries {
                println!(
                    "{:<8}{:<26}{}",
                    daemon::ago(now.saturating_sub(e.ts)),
                    e.exe.as_deref().unwrap_or("-"),
                    e.name
                );
            }
        }
        BlocklistCmd::Check { domain } => {
            if !cfg.blocklist.enabled {
                println!("(blocking is off — this is what would happen if it were on)");
            }
            let why = blocklist::explain(&cfg.blocklist, &domain);
            match (&why.allowed_by, why.blocked_by.is_empty()) {
                (Some(entry), _) => {
                    println!("{domain}: allowed");
                    println!("  allowlist entry {entry} wins over the lists");
                    if !why.blocked_by.is_empty() {
                        println!("  (it is on {} list(s) otherwise)", why.blocked_by.len());
                    }
                }
                (None, true) => println!("{domain}: allowed — on none of the enabled lists"),
                (None, false) => {
                    println!("{domain}: BLOCKED");
                    for (key, hit) in &why.blocked_by {
                        let cat = blocklist::source(key).map(|s| s.category).unwrap_or("?");
                        let how = if *hit == domain.trim_end_matches('.').to_lowercase() {
                            String::new()
                        } else {
                            format!(" — via {hit}")
                        };
                        println!("  {key} ({cat}){how}");
                    }
                    println!(
                        "\n  `guardit blocklist allow {domain}` to keep it, or disable a category above"
                    );
                }
            }
        }
    }
}

fn print_app_list(cfg: &Config) {
    if cfg.app_rule.is_empty() {
        println!("no app rules");
        return;
    }
    let now = now_ts();
    println!(
        "{:<4}{:<8}{:<7}{:<5}{:<4}{:<22}{:<10}EXE",
        "ID", "ACTION", "PORT", "DIR", "ON", "HOST", "EXPIRES"
    );
    for r in &cfg.app_rule {
        println!(
            "{:<4}{:<8}{:<7}{:<5}{:<4}{:<22}{:<10}{}{}",
            r.id,
            format!("{:?}", r.action).to_lowercase(),
            r.port.map(|p| p.to_string()).unwrap_or_else(|| "*".into()),
            r.direction.map(|d| d.as_str()).unwrap_or("*"),
            if r.enabled { "yes" } else { "no" },
            r.host.as_deref().unwrap_or("*"),
            r.expires
                .map(|t| daemon::ago(t.saturating_sub(now)))
                .unwrap_or_default(),
            r.exe,
            if r.stale() { " [changed]" } else { "" },
        );
    }
}

fn add_rule(cfg: &mut Config, action: RuleAction, args: RuleArgs) {
    if let Err(e) = config::validate_src(&args.src) {
        fail(&e);
    }
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
