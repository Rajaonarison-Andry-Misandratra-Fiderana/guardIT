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

## The TUI

Five panes in a fixed grid, `Tab` / `Shift+Tab` to move between them — the focused one gets
a thick border:

| Pane | What it shows | Keys |
|---|---|---|
| **System rules** | IP/port `Rule`s (nftables-level) | `j/k` move · `space` toggle · `d` delete · `a` add · `p` presets (changes apply immediately) |
| **Application blocking** | one row per app, its whole-app default, and how many per-port overrides it has — apps with no rule yet sort to the top | `j/k` select · `Enter` jump to its Flow · `l` this app's log · `y`/`n` allow/deny (whole app) · `space` enable/disable · `d` forget this app entirely · `/` filter by name (live; `Enter` keeps it, `Esc` clears) |
| **Listening ports** | every LISTEN/bound local socket, who owns it, and real bind conflicts (rare — the kernel already prevents most) | `j/k` select · `l` log · `y`/`n` allow/deny **this port only** |
| **Top apps** | bar chart of the apps with the most connection attempts, over the whole audit log (reset by `f` flush) | informational |
| **Network flow** | live connection history for whichever app is selected in Application blocking | `j/k` select · `y`/`n` allow/deny **this port and direction only** (remembered as a per-port rule) · `Y`/`N` allow/deny **this peer's hostname**, any port (needs a resolved name; uses the exact name — `--host '*.foo.com'` on the CLI for a whole domain) |

Other keys: `L` opens the full audit log as its own tab (`j/k` move, `f` flush with confirm, `q`/`L` back), `t` cycles color theme (remembered across restarts), `q` quits.

## License

MIT — see [LICENSE](LICENSE).
