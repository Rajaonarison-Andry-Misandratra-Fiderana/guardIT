# Changelog

## Unreleased

- **Rules by domain**: `guardit app deny <exe> --host '*.doubleclick.net'` restricts a
  rule to peers that resolved to a name, exactly or under a wildcard. A host rule is the
  most specific kind — it beats a per-port rule, which beats the whole-app default — so
  "allow 443, except that domain" reads and behaves that way. In the Flow pane, `Y`/`N`
  rules the selected row's hostname instead of its port. Best-effort by construction: it
  rides the passive DNS tap, so a peer with no name the daemon saw resolved never matches
  a host rule (it falls through), and DoH/DoT stay invisible.
- **Dependencies**: ratatui 0.29 → 0.30 and crossterm 0.28 → 0.29 (one crossterm in the
  tree again, not two). Clears the three `cargo audit` warnings that came in through
  ratatui's `paste` and `lru`. ratatui's default features are off — `widget-calendar`
  pulled in `time` and `uuid` for a widget this app never draws.
- **Filter the Application blocking pane** with `/`: narrows the list live as you type,
  `Enter` keeps the filter, `Esc` clears it. Flow follows the selection as before, so
  filtering down to one app and hitting `Enter` is now the fast path on a busy machine.

## 0.2.0 — 2026-09-08

Per-app rules got precise, and usable without the TUI.

- **Direction**: a decision made in the Flow pane is remembered for the direction it was
  asked in (`firefox → 443 out` and `someone → my server:443 in` are different rules);
  Listening-ports decisions are inbound-only. Whole-app rules still cover both ways.
- **Temporary rules**: `guardit app allow <exe> --for 1h`; the daemon sweeps expired rules.
- **Binary pinning**: a rule remembers the size+mtime of the exe it was made for. An
  updated or replaced binary is asked again instead of inheriting the rule (`[changed]`
  in the Apps pane).
- **Flatpak / snap** apps are identified by app id (`flatpak:org.mozilla.firefox`,
  `snap:firefox.firefox`) instead of a path inside their sandbox.
- **Domain names**: a passive DNS tap (bypassing queue, never fail-closed) shows
  `github.com (140.82.121.4)` in the Flow pane, the audit log and notifications.
- **Desktop notification** (`notify-send`, every logged-in session) when a new app asks,
  with the command to answer it. `notify = false` in `rules.toml` turns it off.
- **CLI**: `guardit app allow|deny|rm|list`, `guardit pending`, `guardit answer <id>
  allow|deny`, `guardit export`, `guardit import <file|->`, `guardit completions <shell>`,
  `guardit man`, `guardit --version`.
- **Hot reload**: the daemon picks up a hand-edited `rules.toml` within 5 s; a malformed
  file is logged and ignored, the loaded rules stay in force.
- **Top apps** counts the whole audit log, not just the current session.
- The Application blocking pane sorts apps with no rule yet to the top, instead of burying
  them alphabetically among the settled ones.
- **Security**: the daemon's IPC socket is now root-only (0600 in a 0700 dir) — any
  local user could previously connect and allow or deny apps. Rule sources are validated
  (`any`, ip, or ip/prefix) at every entry point before reaching nft.
- Performance: exe resolution is cached per (proto, port); the listening-ports rescan
  walks `/proc` once instead of once per socket.
- Packaging: man page and bash/fish/zsh completions installed by `install.sh` and the AUR
  package.

## 0.1.0 — 2026-09-08

First release.

- nftables-backed IP/port rules: `allow`, `deny`, `rm`, `list`, `apply`, `status`.
- Per-application control via NFQUEUE: the daemon resolves the owning process through
  `/proc` and asks the TUI to allow or deny, whole-app or per-port.
- Deny-first, fail-closed default policy.
- Live TUI dashboard: system rules, application blocking, listening ports, top apps,
  network flow, full audit log, colour themes.
- Config lives in `/etc/guardit/`; `install.sh` sets up systemd or a cron restart loop.
