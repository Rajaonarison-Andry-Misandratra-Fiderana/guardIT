mod config;
mod daemon;
mod ipc;
mod log;
mod ruleset;
mod tui;

use clap::{Parser, Subcommand, ValueEnum};
use config::{Action as RuleAction, Config, Proto, Rule};

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

#[derive(Subcommand)]
enum Cmd {
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
    /// show recent connection attempts seen by the kernel (needs `apply`d ruleset + dmesg access)
    Log {
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
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
    let mut cfg = Config::load();

    match cli.cmd.unwrap_or(Cmd::Tui) {
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
            if !ruleset::is_root() {
                eprintln!("guardit apply needs root (CAP_NET_ADMIN) — run with sudo");
                std::process::exit(1);
            }
            match ruleset::apply(&cfg) {
                Ok(()) => println!("applied {} rule(s)", cfg.rule.iter().filter(|r| r.enabled).count()),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Status => println!("{}", ruleset::status()),
        Cmd::Tui => tui::run(cfg),
        Cmd::Log { n } => match log::recent(n) {
            Ok(entries) if entries.is_empty() => println!("no connection attempts logged yet (did you `guardit apply`?)"),
            Ok(entries) => {
                println!("{:<4}{:<20}{:<6}{:<6}", "DIR", "SRC", "PROTO", "PORT");
                for e in entries {
                    println!(
                        "{:<4}{:<20}{:<6}{:<6}",
                        match e.dir {
                            log::Dir::In => "in",
                            log::Dir::Out => "out",
                        },
                        e.src,
                        e.proto,
                        e.dport.map(|p| p.to_string()).unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        Cmd::Daemon { debug } => {
            if !ruleset::is_root() {
                eprintln!("guardit daemon needs root (CAP_NET_ADMIN) — run with sudo");
                std::process::exit(1);
            }
            if let Err(e) = daemon::run(cfg, debug) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Cmd::LogApp { n, exe } => daemon::print_log_app(exe.as_deref(), n),
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
    println!("{:<4}{:<8}{:<6}{:<20}{:<8}{:<4}", "ID", "ACTION", "PROTO", "SRC", "PORT", "ON");
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
