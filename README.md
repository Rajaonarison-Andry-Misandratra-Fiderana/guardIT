<p align="center"><img src="assets/icon.svg" width="96" height="96" alt="guardit"></p>
<h1 align="center">guardit</h1>
<p align="center">An nftables-backed firewall with per-app control and a live TUI dashboard.</p>

## What it GuardIT?

<img width="1920" height="1080" alt="Recording_2026-09-08_17-03-32" src="https://github.com/user-attachments/assets/bd5914ff-b687-46a7-bf1d-d8d45340b53f" />


GuardIt est un parefeu TUI pour linux qui utilise directement nfttables.


- **A CLI/TUI for plain IP/port rules**, backed by `nftables` — the classic "allow this
  subnet on this port" firewall.
- **A daemon that adds per-application control** on top: it intercepts new connections via
  NFQUEUE, resolves the owning process (`/proc` → PID → exe path), and lets you allow/deny
  by application — either the whole app, or one specific port at a time.

Default policy is **deny-first and fail-closed**: Donc chaque nouvelle app qui veulent se connecter doivent d abord etre accepté avant d etre pouvoir utilisé
## How to install

```
git clone https://github.com/Rajaonarison-Andry-Misandratra-Fiderana/guardIT.git
cd guardit
./install.sh
```

`install.sh` builds the release binary, installs it to `/usr/local/bin/guardit`, and sets
up the daemon to survive reboots:

you can use it with or without systemd -> when you are installing it will autodetect if you have systemd or not like myself
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
guardit log-app [--n 100] [--exe <substr>]                   # full per-app audit trail
guardit daemon [--debug]                                      # per-app enforcement (needs root)
guardit tui or guardit                                         # the dashboard (default with no args)
```

## The TUI

Five panes in a fixed grid, `Tab` / `Shift+Tab` to move between them — the focused one gets
a thick border:

| Pane | What it shows | Keys |
|---|---|---|
| **System rules** | IP/port `Rule`s (nftables-level) | `j/k` move · `space` toggle · `d` delete · `a` add · `p` presets (changes apply immediately) |
| **Application blocking** | one row per app, its whole-app default, and how many per-port overrides it has | `j/k` select · `Enter` jump to its Flow · `l` this app's log · `y`/`n` allow/deny (whole app) · `space` enable/disable · `d` forget this app entirely |
| **Listening ports** | every LISTEN/bound local socket, who owns it, and real bind conflicts (rare — the kernel already prevents most) | `j/k` select · `l` log · `y`/`n` allow/deny **this port only** |
| **Top apps** | bar chart of the most active apps this session | informational |
| **Network flow** | live connection history for whichever app is selected in Application blocking | `j/k` select · `y`/`n` allow/deny **this port only** (remembered as a per-port rule) |

Other keys: `L` opens the full audit log as its own tab (`j/k` move, `f` flush with confirm, `q`/`L` back), `t` cycles color theme (remembered across restarts), `q` quits.

## License

MIT — see [LICENSE](LICENSE).
