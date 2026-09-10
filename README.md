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

## Auto mode — decide instead of asking

Holding the packet and asking is the right shape for a desktop somebody is sitting in
front of. It is the wrong one for a server, a machine you are ssh'd into, or a laptop
whose owner has stopped reading the prompts. Auto mode answers the unruled connections
itself:

```
guardit auto on                          # decide; allow what there is no evidence against
guardit auto on --fallback deny          # decide; refuse what there is no evidence for
guardit auto on --fallback ask           # decide what it can, still ask about the rest
guardit auto off
guardit auto                             # what it is doing right now
```

`m` toggles it in the TUI and the header says which mode is in force. It takes effect
within seconds under a running daemon — no restart, no held connection dropped.

Every decision rests on **one fact about the connection**, and that fact is printed next
to the verdict in the flow pane, the audit tab and `guardit log-app`, so you can read back
what it did and tell at a glance whether it was right:

| Fact | Verdict | Reason shown |
|---|---|---|
| the binary is gone from disk, or `/proc` says `(deleted)` | deny | `gone from disk` |
| it runs from `/tmp`, `/dev/shm`, `~/.cache`, `~/Downloads`… | deny | `volatile path` |
| SMB, RDP, telnet, NetBIOS, RPC, port 25, 4444/5555/6667 — **to the internet** | deny | `smb`, `rdp`, … |
| unsolicited inbound from outside your network | deny | `inbound from internet` |
| inbound from your own network, nothing serving that port | deny | `nothing listening` |
| anything within your own network, either way, to a live port | allow | `local network` |
| this machine resolved the name, then reached the address that answered | allow | `resolved name` |
| a packaged binary (`/usr/bin`, `/nix/store`, flatpak…) on a port packaged binaries use | allow | `packaged program` |
| none of the above | `--fallback` | `no evidence` |

The order is not cosmetic: a fact *against* a connection outranks every reason for it, so
"it is in `/usr/bin`" never rescues what "it is port 445 to the internet" already
condemned. A port that is an anomaly across the internet is deliberately fine on your own
network — that is a NAS or a printer, not an exfiltration route.

It writes **no rules**. Each connection is judged again on the evidence current at that
moment, so a binary replaced ten seconds ago, a name that has just landed on a blocklist,
or a service that stopped listening all change the answer with nothing to clean up
afterwards. Your own rules always win: auto only ever looks at connections no rule of
yours covers, and it runs after the blocklist and `require_resolved` have had their say,
never before.

`--fallback allow` is the default because the heuristics are written to catch what is
wrong rather than to recognise everything that is right; on a real machine most of what is
left over is some program talking to a name it resolved a moment ago. `--fallback deny` is
the strict reading, and it will break things you then have to allow by hand.

### Rules by domain

`--host` restricts a rule to peers the daemon resolved to a given name —
`example.com` exactly, or `*.example.com` for the domain and everything under it:

```
guardit app deny /usr/bin/firefox --host '*.doubleclick.net'
```

A host rule is the **most specific** kind, so it beats a per-port rule, which beats the
app's whole-app default. `allow firefox --port 443` plus `deny firefox --host
'*.doubleclick.net'` means exactly what it reads: HTTPS everywhere except that domain.

A blocked name is answered **here**, not upstream: the query is refused before it leaves
the machine, so it costs no round trip and the name is never asked out loud. That needs a
raw socket to put the answer on the wire as the resolver would have; where one is not
available, or for an IPv6 query, it falls back to rewriting the reply — same verdict, one
round trip later.

Blocking happens twice, at both layers. A blocked name's DNS answer is rewritten to
NXDOMAIN, so nothing connects. And if a connection reaches a blocked name anyway — the app
had the address cached, or resolved it somewhere unreadable — it is refused at the
connection too, using the name the tap had already attached to that address. An app rule
naming the host beats it, and so does the blocklist's own allowlist.

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

You choose **what** to block, not which list to install. Twelve categories, any number of
them at once:

| Category | Covers |
|---|---|
| `ads` | advertising |
| `tracking` | trackers and analytics, including CNAME-cloaked first-party ones |
| `phishing` | malware, phishing, scam, ransomware |
| `fake` | fake shops, fake streaming, fake support |
| `crypto` | cryptojacking and mining |
| `dns-bypass` | DoH, VPN and proxy endpoints that route around filtering |
| `telemetry` | device and OS telemetry (Windows/Office, Apple, Samsung, Xiaomi, Amazon, TikTok…) |
| `social` | social networks |
| `gambling` | gambling and betting |
| `porn` | pornography |
| `piracy` | piracy and torrents |
| `drugs` | drug and vaping shops |

```
sudo guardit blocklist on                    # on, covering ads + phishing
sudo guardit blocklist enable tracking telemetry   # several at a time
sudo guardit blocklist disable porn gambling
sudo guardit blocklist update                # download now (the daemon also does it daily)
guardit blocklist categories                 # the twelve, * = blocked
guardit blocklist status                     # what's on, domains loaded, how stale
guardit blocklist check ads.example.com      # blocked? by which list, via which entry
guardit blocklist log [--n 100] [--filter x] # what has actually been blocked, and for whom
sudo guardit blocklist allow cdn.example.com # never block this name, nor anything under it
sudo guardit blocklist off
```

In the TUI, the ads & tracking column carries the same switches: `Tab` to it, `j/k` to a
category, `space` to block or unblock it. Ticking a category whose lists aren't on disk
downloads them in the background and the numbers move as soon as they land; `u`
re-downloads everything.

Behind the categories are 61 lists from HaGeZi, StevenBlack, OISD, AdGuard, The Blocklist
Project, Peter Lowe, AdAway, Frogeye, Phishing Army, abuse.ch URLhaus, Sinfonietta and Dan
Pollock. A category turns on one or two well-chosen ones rather than every list that
touches the subject — the catalogue overlaps heavily, and merging five lists covering the
same domains costs the memory five times for the coverage once. `guardit blocklist sources`
lists all 61 grouped by category, and `guardit blocklist enable <list>` adds any of them on
top of your categories. Downloads live in `/var/lib/guardit/blocklists/`.

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

That closes the DoH endpoints anyone has a list of. `require_resolved = true` closes the
ones nobody does: the daemon already records every address it saw a DNS answer produce, so
an app connecting to a public address on port 443 or 853 that **no lookup ever named** did
not learn it from any resolver guardit can read. That is what talking DoH to an unlisted
endpoint looks like, without needing to know who provides it.

It is off by default, because an app with an address compiled in is refused on the same
evidence. A rule naming that exact port beats the policy — `guardit app allow /usr/bin/foo
--port 443` is you saying "yes, this one" — while a whole-app allow does not, since that
means "may use the network", not "by any means it likes". The daemon says which app it
refused, once per app, in its log. Local, private, link-local and CGNAT addresses are never
subject to it, and neither is anything in the first minute after the daemon starts, when
its name map is empty and every app's own DNS cache is not.

### Configuration

```toml
[blocklist]
enabled = true
categories = ["ads", "phishing", "telemetry"]
sources = ["oisd:small"]     # extra lists on top of the categories
allow = ["cdn.example.com"]
block_encrypted_dns = true
require_resolved = false     # refuse :443/:853 to addresses no lookup named
update_hours = 24            # 0 to never auto-update
```

Edited by hand or by `guardit blocklist`; either way the daemon picks it up within
seconds. Auto mode lives in the same file:

```toml
[auto]
enabled = false
fallback = "allow"           # allow | deny | ask, for connections with no evidence either way
```

### What it does not cover

The DNS tap sees plain DNS, over UDP and over TCP. What it cannot see is a channel it
cannot read: DoH, DoT, or a name an app already had cached — though a connection to a
blocked name is now refused at the connection too, whichever way the app learnt the
address. A connection made straight to a hardcoded ip with no lookup at all is only reached
by `require_resolved`. Blocking works on names, so treat it as an ad and
tracker blocker, which is what it is, rather than as a containment boundary; for that,
deny the app and allow the ports you mean.

## The TUI

Three panes, all about the same thing: the rules the kernel holds, what the machine has
been doing, and the pane you decide in — whose two halves line up with the two above them.
The blocklists live in their own tab on `B`, with a headline in the status line so you can
see at a glance whether they are on.

`Tab` / `Shift+Tab` moves between the three panes; `h` / `l` moves the same way but counts
the two halves of Application blocking separately, so `l` out of the app list lands on its
flow and `l` again leaves the pane. `j` / `k` moves within whatever is focused. The focused
pane gets a thick border:

| Where | Pane | What it shows | Keys |
|---|---|---|---|
| left, top | **System rules** | IP/port `Rule`s (nftables-level) — both directions unless the rule names one | `j/k` move · `space` toggle · `d` delete · `a` add · `p` presets (changes apply immediately) |
| middle, top | **Top apps** | bar chart of the apps with the most connection attempts, over the whole audit log (reset by `f` flush), each app's total above its bar | informational |
| bottom | **Application blocking** — one pane, two halves either side of a vertical rule, because you pick an app on the left and rule on what it is doing on the right. The rule is two columns, reproducing the seam where System rules meets Top apps, so each half runs under the pane it belongs with | | |
| ↳ left half | **apps** | one row per app and its whole-app verdict — `(custom)` when it has rules of its own for particular ports or hosts, with the dot keeping the default's colour | `j/k` select · `a` this app's audit trail · `y`/`n` allow/deny (whole app) · `space` enable/disable · `d` forget this app entirely · `/` filter by name (live; `Enter` keeps it, `Esc` clears) |
| ↳ right half | **flow** | live connection history for whichever app is selected on the left — a row refused by a blocklist or by `require_resolved` says so, and stays red whatever the app's rules allow | `j/k` select · `a` this app's audit trail · `y`/`n` allow/deny **exactly this row** — this app, this port and direction, and the peer it named (a row whose peer has no resolved name falls back to the port, which is all such a row says) · `Y`/`N` allow/deny **this peer's hostname**, any port (needs a resolved name; uses the exact name — `--host '*.foo.com'` on the CLI for a whole domain) |

The first preset under `p` is **Allow everything (pause filtering)** — an unqualified
`accept` that renders above the queue lines in both chains, so no traffic reaches the
daemon while it is on: no per-app matching, no prompts, no connection-layer blocking.
Reach for it when guardit is in the way of something and you need the machine working now.
Prefer it to `systemctl stop guardit`, which leaves the queues loaded with nothing
listening on them and so takes the network down instead of opening it. It is an ordinary
rule, so `space` switches it off again and every other rule is back in force.

`B` opens the blocking tab: the figures, the twelve category switches, and the names most
recently blocked. `j/k` moves, `space` blocks or unblocks a category — ticking one whose
lists aren't on disk downloads them there and then, in the background — and `u`
re-downloads the lot. `q`/`B` goes back.

`A` opens the audit tab, holding the two "what has already happened" views side by side —
`Tab` switches between them, `q`/`A` goes back. A pane's own `a` opens it scoped to the
selected app: both halves then show only that app, its trail and its ports.

| Pane | What it shows | Keys |
|---|---|---|
| **Audit** | the full unthrottled trail from `history.jsonl` | `j/k` move · `/` filter by port, ip or name (live; a number is matched against the port, anything else as a substring of the address, resolved name or app path) · `f` flush with confirm |
| **Listening ports** | every LISTEN/bound local socket, who owns it, and real bind conflicts (rare — the kernel already prevents most) | `j/k` select · `/` filter by port, address or owner · `a` this app's audit trail · `y`/`n` allow/deny **this port only** |

Other keys: `t` cycles color theme (remembered across restarts), `q` quits.

Downloading lists and loading the ruleset into the kernel both run off the draw loop, with
a spinner segment at the far right of the status line saying which is happening — a
category can pull half a dozen lists and one of them is 39 MB, and a frozen screen for a
minute is indistinguishable from a crash.

## License

MIT — see [LICENSE](LICENSE).
