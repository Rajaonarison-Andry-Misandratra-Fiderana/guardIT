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

Either way `install.sh` puts the binary in `/usr/local/bin/guardit` and sets up the daemon
to survive reboots. It works with or without systemd — the installer
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
guardit deny  --port 80                                     # explicit block
guardit rm <id>                                             # remove a rule
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
guardit completions fish|bash|zsh                           # shell completion script
guardit man                                                 # man page (roff)
guardit tui   (or just guardit)                             # the dashboard (default with no args)
```

When a new app asks and the TUI isn't open, the daemon pops a desktop notification
(`notify-send`, every logged-in session) naming the app, the peer and the `guardit answer`
command. `notify = false` in `/etc/guardit/rules.toml` turns it off. Peers show as
`github.com (140.82.121.4)` when the daemon saw the DNS answer (plain DNS only — DoH/DoT
stay invisible). A hand edit of `rules.toml` is picked up within 5 seconds.

### Rules by domain

`--host` restricts a rule to peers the daemon resolved to a given name —
`example.com` exactly, or `*.example.com` for the domain and everything under it:

```
guardit app deny /usr/bin/firefox --host '*.doubleclick.net'
```

A host rule is the **most specific** kind, so it beats a per-port rule, which beats the
app's whole-app default. `allow firefox --port 443` plus `deny firefox --host
'*.doubleclick.net'` means exactly what it reads: HTTPS everywhere except that domain.

It rides on the same passive DNS tap that puts names in the dashboard, so it inherits its
limits: a peer whose lookup the daemon never saw has no name, and a rule with `--host`
can't match it — the connection falls through to the app's port and whole-app rules. An
app doing DoH/DoT, or answering from its own cache, is invisible to the tap and therefore
to host rules. Treat them as a convenience over named destinations, not a containment
boundary — for that, deny the app and allow the ports you mean.

## Ads and tracking blocking

Curated domain blocklists, matched against every DNS lookup the daemon sees. A blocked
name's answer is rewritten to NXDOMAIN, so the app never learns an address and never opens
the connection.

```
sudo guardit blocklist on                   # enables hagezi:pro
sudo guardit blocklist update                # download now (the daemon also does it daily)
guardit blocklist sources                    # the catalogue, * = enabled
sudo guardit blocklist enable hagezi:tif     # add malware/phishing coverage
sudo guardit blocklist disable hagezi:tif
guardit blocklist status                     # what's on, domains loaded, how stale
guardit blocklist check ads.example.com      # would this be blocked, right now
sudo guardit blocklist allow cdn.example.com # never block this name, nor anything under it
sudo guardit blocklist off
```

Lists come from HaGeZi, StevenBlack, OISD, AdGuard and Peter Lowe, each in several levels
(`hagezi:light` … `hagezi:ultimate`, plus focused ones: `tif` for malware/phishing, `fake`,
`gambling`, `nsfw`, `native.tiktok`, `native.winoffice`; `stevenblack:porn`,
`stevenblack:social`, and so on). `guardit blocklist sources` lists them all with what each
covers. Enabled lists are merged into one set, so several can be on at once. Downloads live
in `/var/lib/guardit/blocklists/`.

A listed name covers everything under it, and an allowlist entry beats the lists and
rescues its own subtree — so `allow good.example.com` still works with `example.com`
blocked.

### Encrypted DNS

Name-based blocking only reaches lookups the daemon can read. An app doing DNS-over-HTTPS
or DNS-over-TLS resolves names guardit never sees, and ignores blocking entirely — which
is most browsers, by default, in some regions.

So `block_encrypted_dns` is on by default. It refuses DoT/DoQ (port 853) and port 443 to
the maintained list of DoH resolver addresses, and returns NXDOMAIN for the DoH bootstrap
names and for Mozilla's `use-application-dns.net` canary, which is the documented signal
for Firefox to turn its own DoH off. `reject`, not `drop`, so a client falls back to plain
DNS immediately instead of hanging. Turn it off with `block_encrypted_dns = false` if you
run your own encrypted resolver on purpose.

### Configuration

```toml
[blocklist]
enabled = true
sources = ["hagezi:pro", "hagezi:tif"]
allow = ["cdn.example.com"]
block_encrypted_dns = true
update_hours = 24            # 0 to never auto-update
```

Edited by hand or by `guardit blocklist`; either way the daemon picks it up within
seconds.

### What it does not cover

The DNS tap sees plain DNS over UDP only. A name an app already had cached, resolved over
a channel guardit could not read, or looked up over DNS-over-TCP, is not filtered — nor is
a connection made straight to a hardcoded ip with no lookup at all. Blocking works on names, so treat it as an ad and
tracker blocker, which is what it is, rather than as a containment boundary; for that,
deny the app and allow the ports you mean.

## The TUI

The blocklists hold the right-hand column top to bottom. The rest is a top band — the
rules the kernel holds, and what the machine has been doing — over the pane you actually
work in, whose two halves line up with the two panes above them. `Tab` / `Shift+Tab` moves
between the focusable panes, the focused one gets a thick border:

| Where | Pane | What it shows | Keys |
|---|---|---|---|
| left, top | **System rules** | IP/port `Rule`s (nftables-level) | `j/k` move · `space` toggle · `d` delete · `a` add · `p` presets (changes apply immediately) |
| middle, top | **Top apps** | bar chart of the apps with the most connection attempts, over the whole audit log (reset by `f` flush), each app's total above its bar | informational |
| right, full height | **Ads & tracking** | a bar of DNS lookups blocked vs allowed with the rate above it, a sparkline of blocks per 5 s, then each figure under its own label — lookups, blocked, allowed — plus lists, domains loaded, last update and whether encrypted DNS is refused, then the names most recently blocked. A short pane drops the tail, never the top | informational |
| bottom | **Application blocking** — one pane, two halves either side of a vertical rule, because you pick an app on the left and rule on what it is doing on the right. The rule sits on the column where Top apps begins, so each half runs under the pane it belongs with | | |
| ↳ left half | **apps** | one row per app, its whole-app default, and how many per-port overrides it has | `j/k` select · `Enter` jump to the flow half · `l` this app's audit trail · `y`/`n` allow/deny (whole app) · `space` enable/disable · `d` forget this app entirely · `/` filter by name (live; `Enter` keeps it, `Esc` clears) |
| ↳ right half | **flow** | live connection history for whichever app is selected on the left | `j/k` select · `y`/`n` allow/deny **this port and direction only** (remembered as a per-port rule) · `Y`/`N` allow/deny **this peer's hostname**, any port (needs a resolved name; uses the exact name — `--host '*.foo.com'` on the CLI for a whole domain) |

`A` opens the audit tab, holding the two "what has already happened" views side by side —
`Tab` switches between them, `q`/`A` goes back:

| Pane | What it shows | Keys |
|---|---|---|
| **Audit** | the full unthrottled trail from `history.jsonl` | `j/k` move · `/` filter by port, ip or name (live; a number is matched against the port, anything else as a substring of the address, resolved name or app path) · `f` flush with confirm |
| **Listening ports** | every LISTEN/bound local socket, who owns it, and real bind conflicts (rare — the kernel already prevents most) | `j/k` select · `l` this app's log · `y`/`n` allow/deny **this port only** |

Other keys: `t` cycles color theme (remembered across restarts), `q` quits.

## License

MIT — see [LICENSE](LICENSE).
