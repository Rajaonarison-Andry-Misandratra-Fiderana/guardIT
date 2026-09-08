<p align="center"><img src="assets/icon.svg" width="96" height="96" alt="guardit"></p>
<h1 align="center">guardit</h1>
<p align="center">An nftables-backed firewall with per-app control and a live TUI dashboard.</p>

## What it is

guardit is two things sharing one config file:

- **A CLI/TUI for plain IP/port rules**, backed by `nftables` — the classic "allow this
  subnet on this port" firewall.
- **A daemon that adds per-application control** on top: it intercepts new connections via
  NFQUEUE, resolves the owning process (`/proc` → PID → exe path), and lets you allow/deny
  by application — either the whole app, or one specific port at a time.

Default policy is **deny-first and fail-closed**: the kernel drops everything by default,
and if the daemon isn't running, new connections that would need it are dropped too, not
silently let through.

## Install

```
git clone <this repo>
cd guardit
./install.sh
```

`install.sh` builds the release binary, installs it to `/usr/local/bin/guardit`, and sets
up the daemon to survive reboots:

- **systemd present** → installs and enables `guardit.service` (`Restart=always`).
- **no systemd** → falls back to `guardit-supervise.sh` (a restart-loop script) via a
  root `cron @reboot` entry. If `cron` isn't installed either, the script stops and tells
  you to install it first.

Check it's running:

```
systemctl status guardit          # systemd
# or
tail -f /var/log/guardit-supervise.log   # cron fallback
```

## CLI

```
guardit allow --proto tcp --src 192.168.1.0/24 --port 22   # add an IP/port rule
guardit deny  --port 80                                     # explicit block
guardit rm <id>                                              # remove a rule
guardit list                                                 # list configured rules
guardit apply [--dry-run]                                    # load the ruleset into the kernel
guardit status                                                # show what's loaded
guardit log [--n 20]                                          # recent connection attempts (dmesg)
guardit daemon [--debug]                                      # per-app enforcement (needs root)
guardit tui                                                   # the dashboard (default with no args)
```

## The TUI

Five panes in a fixed grid, `Tab` / `Shift+Tab` to move between them — the focused one gets
a thick border:

| Pane | What it shows | Keys |
|---|---|---|
| **System rules** | IP/port `Rule`s (nftables-level) | `j/k` move · `space` toggle · `d` delete · `a` add · `p` presets · `l` raw dmesg log · `s` apply |
| **Application blocking** | one row per app, its whole-app default, and how many per-port overrides it has | `j/k` select · `Enter` jump to its Flow · `y`/`n` allow/deny (whole app) · `space` enable/disable · `d` forget this app entirely |
| **Listening ports** | every LISTEN/bound local socket, who owns it, and real bind conflicts (rare — the kernel already prevents most) | `j/k` select · `y`/`n` allow/deny that app |
| **Top apps** | bar chart of the most active apps this session | informational |
| **Network flow** | live connection history for whichever app is selected in Application blocking | `j/k` select · `y`/`n` allow/deny **this port only**, once · `Y`/`N` allow/deny this port and remember it |

Other keys: `T` cycles color theme (remembered across restarts), `q` quits.

**Whole-app vs per-port control**: the Application blocking pane's `y`/`n` sets the app's
default for every port and clears any existing per-port overrides. The Network flow pane's
decisions are scoped to the one port you're looking at and never touch the app's other
ports or its default — that's the difference between "allow this app" and "allow just this
one connection/port".

## Known limitations

- **App identity is an exe path**, nothing more — no hash/signature. An app that moves or
  gets reinstalled to a different path (Flatpak, AppImage, some auto-updaters) needs a new
  decision; the Apps pane flags a rule pointing at a path that no longer exists.
- **Fail-closed has a real cost**: if the daemon isn't running, new connections that would
  need per-app matching are dropped, not allowed. Keep it supervised (systemd/cron, see
  above).
- **IPv6 packet parsing doesn't walk extension headers** — the common case (no
  hop-by-hop/routing/fragment headers) works, the rare case falls back to the configured
  default verdict. Existing `ip6 saddr` IP-rules are unaffected either way.
- **History lives in the daemon**, persisted to `~/.config/guardit/history.jsonl` — it
  survives a daemon restart, not a full wipe of that file.
- **PID resolution has a narrow TOCTOU window** (the same one every `/proc`-based tool
  has) — a re-check right before trusting the result shrinks it, doesn't erase it. A truly
  atomic answer needs a kernel-level hook (eBPF at `connect()`), out of scope here.
