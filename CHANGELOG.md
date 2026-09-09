# Changelog

## Unreleased

- **Blocked lookups are written to `/etc/guardit/blocked.jsonl`** and read back by
  `guardit blocklist log`, so a page that broke this morning is still answerable this
  afternoon. Capped at 8 MB (the older half is dropped) because this is written per DNS
  answer rather than per connection; the dashboard's recent list is seeded from it on
  daemon start.
- **Blocked lookups are attributed to the app that asked.** The reply is held on its way
  to the socket that wanted it, so its destination port names the process — no second
  queue, no bookkeeping. The dashboard's recent list now says who, and the busiest blocked
  app gets a line of its own. A local stub resolver's own upstream leg is deliberately not
  attributed: it asks on everyone's behalf, and counting it would file the machine's whole
  total under one process.
- `guardit blocklist check` now says **which** list blocks a name and which entry matched,
  so a false positive points at the category to drop. With sixty-one lists merged into one
  set, "BLOCKED" on its own left you nowhere to go.

- **Ads and tracking blocking** (`guardit blocklist`): pick **what** to block — `ads`,
  `tracking`, `phishing`, `fake`, `crypto`, `dns-bypass`, `telemetry`, `social`,
  `gambling`, `porn`, `piracy`, `drugs` — any number at once, from the CLI or with `space`
  in the TUI's ads & tracking column, where ticking one downloads its lists there and then. Behind the twelve categories are 61 curated lists
  (HaGeZi, StevenBlack, OISD, AdGuard, The Blocklist Project, Peter Lowe, AdAway, Frogeye,
  Phishing Army, abuse.ch URLhaus, Sinfonietta, Dan Pollock); a category turns on one or
  two well-chosen ones rather than every list touching the subject, and
  `blocklist enable <list>` adds any of the rest on top. All of it is merged into one set
  and matched against every DNS lookup the daemon sees. A blocked name's reply is rewritten
  to NXDOMAIN in the queue, so the app never learns an address and never connects — no
  sinkhole process, no new hook, one lookup per DNS answer. A listed name covers everything
  under it; an allowlist entry beats the lists and rescues its own subtree. Lists are
  downloaded to `/var/lib/guardit/blocklists/` and refreshed daily by the daemon
  (`update_hours`).
- **Encrypted DNS is refused by default** when blocking is on (`block_encrypted_dns`).
  Name-based filtering can't reach an app doing DoH or DoT, which is most browsers by
  default; so DoT/DoQ (853) and :443 to the maintained list of DoH resolver addresses are
  rejected, and the DoH bootstrap names plus Mozilla's `use-application-dns.net` canary
  return NXDOMAIN. `reject`, not `drop`, so clients fall back to plain DNS at once rather
  than hanging.
- **New TUI layout**: the ads & tracking dashboard holds the right-hand column top to
  bottom; System rules and Top apps share a band above an **Application blocking** pane
  holding the app list and that app's live flow either side of a vertical rule, since
  neither is much use without the other. The rule is two columns wide, reproducing the seam
  where System rules meets Top apps, so the app list runs under the rules and its flow
  under the chart. The dashboard shows a bar of lookups blocked vs allowed, the three
  counters each with their number under their label, the category switches, then the names
  most recently blocked; a short pane drops the tail rather than clipping anything.
  The audit tab moves from `L` to **`A`** and picks up the listening ports alongside the
  trail; a pane's own `a` opens it filtered to the selected app (it was `l`). `h`/`l` now
  move between panes the way `j`/`k` move within one, and Application blocking is a single
  `Tab` stop that `h`/`l` navigates the two halves of. The listening-ports pane gets `/`
  too, on the same terms as the audit trail's. Downloading lists and loading the ruleset
  now run off the draw loop, with a spinner segment at the far right of the status line
  saying which is running — both used to freeze the screen, one of them for a minute. Rule rows wrap onto two lines rather than truncating
  the source, the app-name column shrinks with its pane so the allow/deny status never
  falls off the edge, and the apps list is plain alphabetical (it used to float undecided
  apps to the top, which moved rows under you as decisions landed).
- **Filter the audit log** with `/`: a number matches the port exactly, anything else is a
  substring of the peer address, the resolved name or the app path.
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
