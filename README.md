<p align="center"><img src="assets/icon.svg" width="96" height="96" alt="guardit"></p>
<h1 align="center">guardit</h1>
<p align="center"> An nftables application firewall for Linux — per-app rules, ads and tracker blocking</p>

https://github.com/user-attachments/assets/d3fd40ac-70be-46c7-ab3b-6f199392ded8




## What is GuardIT?
GuardIT is an application firewall for Linux, driven from a TUI or the CLI, on top of `nftables`.

- **IP/port rules** in `nftables` — the classic "allow this subnet on this port".
- **Per-app control** — a daemon catches every new connection (NFQUEUE), finds the program
  behind it (`/proc` → PID → exe) and lets you allow or deny it: the whole app, one port,
  or one domain.
- **Ads and tracker blocking** at the DNS level — pick categories (ads, tracking,
  phishing…), guardit picks the lists.

Default policy is **deny-first and fail-closed**: every new app that wants to connect has
to be accepted first before it can talk to the network. If the daemon isn't running, those
connections are dropped, not silently let through.

## Is it HUUUGEE???
Built with Rust — no Electron, no heavy runtime, minimal CPU and memory footprint.

## How to install

One line

```
curl -fsSL https://raw.githubusercontent.com/Rajaonarison-Andry-Misandratra-Fiderana/guardIT/main/install.sh | bash
```

Or from source:

```
git clone https://github.com/Rajaonarison-Andry-Misandratra-Fiderana/guardIT.git
cd guardIT
./install.sh
```
It works with or without systemd — the installer
autodetects which one you have:

- **systemd present** → installs and enables `guardit.service` (`Restart=always`).
- **no systemd** → falls back to `guardit-supervise.sh` (a restart-loop script) via a
  root `cron @reboot` entry. If `cron` isn't installed either, the script stops and tells
  you to install it first.

Check it's running:

```
systemctl status guardit                 # systemd
# or
tail -f /var/log/guardit-supervise.log   # cron fallback
```

Config, per-app rules and the audit log live in `/etc/guardit/`.

# HOW TO USE
you can use CLI or TUI whatever you like

## Configuration

Everything lives in `/etc/guardit/rules.toml`.

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
| **Apps** | one row per app | `y`/`n` allow/deny · `space` enable · `d` forget · `/` filter · `a` audit |
| **Flow** | the selected app's connections | `y`/`n` this exact row · `Y`/`N` this hostname · `a` audit |

| Tab | Shows | Keys |
|---|---|---|
| `B` blocking | figures, category switches, recently blocked names | `space` block · `s` switch list · `u` update · `h`/`l` to the names · `y` never block this name |
| `A` audit | the full audit trail, listening ports | `/` filter · `f` flush · `y`/`n` allow/deny a port |
| `p` presets | ready-made rules, grouped | type to filter · `Enter` add · `Esc` close |

`m` auto mode · `t` theme · `q` back, or quit.

## Auto mode

For machines nobody is watching — a server, an ssh session, a laptop whose owner has
stopped reading the prompts — guardit can decide instead of asking.

```
guardit auto on                   # decide; allow what there is no evidence against
guardit auto on --fallback deny   # decide; refuse what there is no evidence for
guardit auto on --fallback ask    # decide what it can, ask about the rest
guardit auto off
```

`m` toggles it in the TUI.

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

## Ads and tracking blocking

Pick **what** to block, guardit picks the lists.

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
category's list with `s` in the TUI or in `rules.toml`: a smaller list is less memory.

### Encrypted DNS

Blocking only sees the DNS it can read. So by default guardit refuses DoT/DoQ and the
known DoH resolvers, and tells Firefox to turn its own DoH off — apps fall back to plain
DNS. `require_resolved = true` goes further: :443/:853 to a public address no lookup ever
named is refused. That catches unknown DoH endpoints, and also apps with a hard-coded IP —
a per-port rule for the app lets it through.


**Forwarded traffic** — containers, bridged VMs — is off by default and covered by
`filter_forwarded = true`. Per-app control cannot apply there: a forwarded packet has no
local process to attribute it to, which is a fact about routing rather than a gap to close.
What does apply is everything about addresses and names — your ip/port rules, the
encrypted-DNS refusals, and the blocklists, since the forward chain taps DNS the same way
and a container's own lookups feed the same name map.



## License

MIT — see [LICENSE](LICENSE).
