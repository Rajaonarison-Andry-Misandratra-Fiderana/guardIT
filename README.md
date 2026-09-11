<p align="center"><img src="assets/icon.svg" width="96" height="96" alt="guardit"></p>
<h1 align="center">guardit</h1>
<p align="center">An nftables-backed firewall with per-app control and a live TUI dashboard.</p>


https://github.com/user-attachments/assets/8776d1cc-61e7-4fc2-a7b5-0da06f5d8df8




## What is GuardIT?
GuardIT is a TUI firewall for Linux that drives `nftables` directly.

- **A CLI/TUI for plain IP/port rules**, backed by `nftables` — the classic "allow this
  subnet on this port" firewall.
- **A daemon that adds per-application control** on top: it intercepts new connections via
  NFQUEUE, resolves the owning process (`/proc` → PID → exe path), and lets you allow/deny
  by application — either the whole app, or one specific port at a time.

Default policy is **deny-first and fail-closed**: every new app that wants to connect has
to be accepted first before it can talk to the network. If the daemon isn't running, those
connections are dropped, not silently let through.

## How to install

One line, no Rust toolchain needed (static x86_64 binary from the latest release):

```
curl -fsSL https://raw.githubusercontent.com/Rajaonarison-Andry-Misandratra-Fiderana/guardIT/main/install.sh | bash
```

Or from source:

```
git clone https://github.com/Rajaonarison-Andry-Misandratra-Fiderana/guardIT.git
cd guardIT
./install.sh
```

Either way `install.sh` leaves you with a working install, not a to-do list: the binary in
`/usr/local/bin/guardit`, the man page and shell completions, the daemon set up to survive
reboots, the ads and tracking lists downloaded, and the ruleset loaded into the kernel. It
picks `ads` + `phishing` on a first install and leaves an existing configuration alone,
including a deliberate `blocklist off`. It works with or without systemd — the installer
autodetects which one you have:

- **systemd present** → installs and enables `guardit.service` (`Restart=always`).
- **no systemd** → falls back to `guardit-supervise.sh` (a restart-loop script) via a
  root `cron @reboot` entry. If `cron` isn't installed either, the script stops and tells
  you to install it first.

### Everything goes through it, or nothing is enforced

The queue rules for connections carry no `bypass`, so a dead daemon means new
connections are dropped rather than let through — the deny-first guarantee only holds if
that stays true. Three things could break it, and all three are handled:

- **A reboot.** nftables keeps nothing across one. Both start paths load the ruleset before
  the daemon binds its queues (`ExecStartPre` in the unit, the loop in
  `guardit-supervise.sh`).
- **Something flushing the table underneath.** A container runtime, another firewall
  front-end, one hand-typed `nft flush ruleset` — the daemon would carry on holding queues
  nothing routes to any more, which looks like nothing at all from the outside. It checks
  every 5 seconds, reloads, and says so.
- **A crash loop.** systemd gives up on a unit that fails five times in ten seconds and
  leaves it stopped — with the ruleset still loaded and no listener, that is a machine with
  no network until someone intervenes. The unit sets `StartLimitIntervalSec=0` so it never
  stops trying.

**Forwarded traffic** — containers, bridged VMs — is off by default and covered by
`filter_forwarded = true`. Per-app control cannot apply there: a forwarded packet has no
local process to attribute it to, which is a fact about routing rather than a gap to close.
What does apply is everything about addresses and names — your ip/port rules, the
encrypted-DNS refusals, and the blocklists, since the forward chain taps DNS the same way
and a container's own lookups feed the same name map.

The chain accepts by default and its queue bypasses, so it can only ever subtract from what
already flows: a container runtime that stopped working because the firewall daemon
restarted would be a far worse bargain than the filtering is worth.

Check it's running:

```
systemctl status guardit                 # systemd
# or
tail -f /var/log/guardit-supervise.log   # cron fallback
```

Config, per-app rules and the audit log live in `/etc/guardit/`. Everything except
`list`, `log-app` and `apply --dry-run` needs root, so run the CLI and the TUI with `sudo`.

## Is it HUUUGEE???
Built with Rust — no Electron, no heavy runtime, minimal CPU and memory footprint.

# HOW TO USE
you can use CLI or TUI whatever you like

## CLI

IP/port rules (nftables level):

```
guardit allow --proto tcp --src 192.168.1.0/24 --port 22   # add an IP/port rule
guardit deny  --port 80                                     # explicit block, both directions
guardit deny  --port 25 --dir out                           # outbound only
guardit allow                                               # allow everything: pause filtering
guardit rm <id>                                             # remove a rule
                                                            # (both reload the kernel if guardit is already running)
guardit list                                                # list configured rules
guardit apply [--dry-run]                                   # load the ruleset into the kernel
guardit status                                              # show what's loaded
```

Per-app rules (what the daemon enforces) — the same things the TUI does, headless:

```
guardit app list                                            # every per-app rule
guardit app allow /usr/bin/curl                             # whole app, both directions
guardit app deny  /usr/bin/curl --port 80 --dir out         # one port, one direction
guardit app deny  /usr/bin/firefox --host '*.doubleclick.net'  # one domain, any port
guardit app allow /usr/bin/ssh --for 1h                     # expires (30s, 10m, 1h30m, 2d)
guardit app rm    /usr/bin/curl                             # forget the app entirely
guardit pending                                             # connections waiting for a decision
guardit answer <id> allow|deny                              # decide one (remembered as a rule)
```

`<exe>` is the path shown by `app list` — or `flatpak:<app-id>` / `snap:<name>.<app>`
for sandboxed apps. Rules made through the daemon remember the binary's size+mtime; when
the binary changes (update, replacement) the app is asked again instead of inheriting the
rule.

Everything else:

```
guardit export > backup.toml                                # whole config as TOML
guardit import backup.toml                                  # replace it (daemon reloads)
guardit log-app [--n 100] [--exe <substr>]                  # full per-app audit trail
guardit daemon [--debug]                                    # per-app enforcement (needs root)
guardit reset [--yes]                                       # wipe every rule, log and list
guardit completions fish|bash|zsh                           # shell completion script
guardit auto on [--fallback allow|deny|ask]                  # decide unruled connections here
guardit auto off                                            # go back to asking
guardit man                                                 # man page (roff)
guardit tui   (or just guardit)                             # the dashboard (default with no args)
```

When a new app asks and the TUI isn't open, the daemon pops a desktop notification
(`notify-send`, every logged-in session) naming the app, the peer and the `guardit answer`
command. `notify = false` in `/etc/guardit/rules.toml` turns it off. Peers show as
`github.com (140.82.121.4)` when the daemon saw the DNS answer (plain DNS only — DoH/DoT
stay invisible). A hand edit of `rules.toml` is picked up within 5 seconds.

## Auto mode

For machines nobody is watching — a server, an ssh session, a laptop whose owner has
stopped reading the prompts — guardit can decide instead of asking.

```
guardit auto on                   # decide; allow what there is no evidence against
guardit auto on --fallback deny   # decide; refuse what there is no evidence for
guardit auto on --fallback ask    # decide what it can, ask about the rest
guardit auto off
```

`m` toggles it in the TUI. Every verdict rests on **one fact**, printed next to it in the
flow pane, the audit tab and `guardit log-app`:

| Fact about the connection | Verdict |
|---|---|
| binary gone from disk, or running from `/tmp`, `/dev/shm`, `~/Downloads`… | deny |
| SMB, RDP, telnet, RPC, port 25… **to the internet** | deny |
| unsolicited inbound from outside, or to a port nothing listens on | deny |
| anything else inside your own network | allow |
| an address this machine has just resolved | allow |
| a packaged binary (`/usr/bin`, `/nix/store`, flatpak…) on a usual port | allow |
| none of the above | `--fallback` |

A fact against a connection always outranks a fact for it. Auto writes no rules and never
overrides yours: it only judges connections none of your rules cover.

> [!WARNING]
> **Mail server?** Outbound port 25 is refused — `guardit allow --proto tcp --port 25 --dir out` fixes it.
>
> **IPv6-native LAN?** A neighbour reached over a *global* v6 address counts as internet —
> allow what you serve (the `in` presets do it in one key).

### Rules by domain

```
guardit app deny /usr/bin/firefox --host '*.doubleclick.net'
```

The most specific kind of rule: **host › port › whole app**. Next to `allow firefox --port
443`, it means HTTPS everywhere except that domain. It matches names the daemon saw
resolved, so DoH, DoT or an app's own cache slip past it — a convenience, not a wall.

## Ads and tracking blocking

Pick **what** to block, guardit picks the lists. A blocked name is answered NXDOMAIN on the
spot, and a connection to it is refused even if the app had the address cached.

**Categories:** `ads` · `tracking` · `phishing` · `fake` · `crypto` · `dns-bypass` ·
`telemetry` · `social` · `gambling` · `porn` · `piracy` · `drugs`

```
sudo guardit blocklist on                          # starts with ads + phishing
sudo guardit blocklist enable tracking telemetry
sudo guardit blocklist disable porn
sudo guardit blocklist allow cdn.example.com       # never block it, nor anything under it
guardit blocklist categories                       # what each one covers
guardit blocklist status                           # what's on, domains loaded, how fresh
guardit blocklist check ads.example.com            # blocked? by which list?
guardit blocklist log                              # what was blocked, and for whom
```

Behind the categories sit 61 lists — HaGeZi, OISD, StevenBlack, AdGuard, Frogeye,
URLhaus… — one or two per category (`guardit blocklist sources` shows them all). Swap a
category's list with `s` in the TUI or in `rules.toml`: a smaller list is less memory, and
`hagezi:tif` alone is 2.3 million domains.

### Encrypted DNS

Blocking only sees the DNS it can read. So by default guardit refuses DoT/DoQ and the
known DoH resolvers, and tells Firefox to turn its own DoH off — apps fall back to plain
DNS. `require_resolved = true` goes further: :443/:853 to a public address no lookup ever
named is refused. That catches unknown DoH endpoints, and also apps with a hard-coded IP —
a per-port rule for the app lets it through.

> [!NOTE]
> Name-based blocking is an ad and tracker blocker, not a containment boundary. To
> contain an app, deny it and allow only the ports you mean.

## Configuration

Everything lives in `/etc/guardit/rules.toml`. Edit it by hand, with the CLI or from the
TUI — the daemon and an open TUI pick changes up within seconds.

```toml
[blocklist]
enabled = true
categories = ["ads", "phishing", "telemetry"]
sources = ["oisd:small"]           # extra lists on top of the categories
allow = ["cdn.example.com"]
block_encrypted_dns = true
require_resolved = false
update_hours = 24                  # 0 = never

[blocklist.category_sources]       # one line per category, written out on first save
phishing = ["hagezi:tif.medium"]   # delete a line to get the default back

[auto]
enabled = false
fallback = "allow"                 # allow | deny | ask
```

## The TUI

`Tab` or `h`/`l` moves between panes, `j`/`k` within one.

| Pane | Shows | Keys |
|---|---|---|
| **System rules** | IP/port rules | `space` toggle · `a` add · `d` delete · `p` presets |
| **Top apps** | who connects the most | — |
| **Apps** | one row per app | `y`/`n` allow/deny · `space` enable · `d` forget · `/` filter · `a` audit |
| **Flow** | the selected app's connections | `y`/`n` this exact row · `Y`/`N` this hostname · `a` audit |

| Tab | Shows | Keys |
|---|---|---|
| `B` blocking | figures, category switches, recently blocked names | `space` block · `s` switch list · `u` update · `h`/`l` to the names · `y` never block this name |
| `A` audit | the full audit trail, listening ports | `/` filter · `f` flush · `y`/`n` allow/deny a port |
| `p` presets | ready-made rules, grouped | type to filter · `Enter` add · `Esc` close |

`m` auto mode · `t` theme · `q` back, or quit.

## License

MIT — see [LICENSE](LICENSE).
