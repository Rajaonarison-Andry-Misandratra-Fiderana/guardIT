# Changelog

## 0.1.0 — 2026-09-08

First release.

- nftables-backed IP/port rules: `allow`, `deny`, `rm`, `list`, `apply`, `status`.
- Per-application control via NFQUEUE: the daemon resolves the owning process through
  `/proc` and asks the TUI to allow or deny, whole-app or per-port.
- Deny-first, fail-closed default policy.
- Live TUI dashboard: system rules, application blocking, listening ports, top apps,
  network flow, full audit log, colour themes.
- Config lives in `/etc/guardit/`; `install.sh` sets up systemd or a cron restart loop.
