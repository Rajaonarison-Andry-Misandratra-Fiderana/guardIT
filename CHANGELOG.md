# Changelog

## Unreleased

- **A blocked name is answered locally now, not refused on the way back.** The query is
  dropped before it leaves the machine and the answer is put on the wire from here, so it
  costs no round trip and the name is never asked out loud — the privacy half of blocking,
  which rewriting the reply could never give. IPv6 queries and machines without a raw
  socket fall back to the reply rewrite: same verdict, one round trip later.
- **DNS over TCP is filtered too.** The tap only ever saw UDP, so a resolver falling back
  to TCP after a truncated answer — or one configured to prefer it — walked past the lists
  for free. TCP replies are rewritten in place at exactly their original length, since
  shortening a segment mid-stream would put every sequence number after it out by the
  difference; a reply split across segments is left alone rather than half rewritten, and
  one too small to hold an SOA is answered without one.
- **The addresses a blocked name resolves to are recorded before the answer is refused.**
  That is what lets the connection layer turn away an app that got them another way, and it
  is the only thing covering a DoH endpoint whose address is on no list — hagezi's DoH
  address list is IPv4-only, so the nft set never had a single IPv6 entry.
- **Blocklists now apply to connections too, not only to lookups.** A blocked name whose
  address an app already had cached used to sail through: the DNS layer never saw a lookup
  to refuse, and the connection layer never consulted the lists — even though the dashboard
  was already showing the blocked name next to that connection. The peer name is right
  there, so checking it costs one hash lookup. An app rule naming the host overrides it.
- **`sudo guardit reset`**: every rule, every log and every downloaded list gone, back to
  a fresh install. It names and counts what will go before asking, and wants the word
  `reset` typed back — a confirmation you cannot see the size of is not one. The kernel
  ruleset is reloaded from the defaults afterwards, so what is loaded still matches what is
  on disk. `--yes` skips the prompt.
- **An app's flow survives a restart.** The daemon hands a new client a capped slice of
  recent history across all apps, so a program busy yesterday and quiet today showed an
  empty pane while its whole trail sat in `history.jsonl`. Selecting an app now reads its
  earlier flow back off that file, once, and the pane's cap is per app rather than overall
  — a global one let a single chatty program evict everything else.
- **`y`/`n` in the flow pane rules the row, not the port.** Denying
  `curl -> port 53 -> ads.example.com` used to deny curl port 53 outright, which stopped
  its DNS rather than stopping it reaching that name. The rule now carries the peer the row
  named, so the three scopes read as they look: `y`/`n` this row, `Y`/`N` this host on any
  port, the Apps pane the whole app. A row whose peer has no resolved name still falls back
  to the port — that is all such a row says. Answering a pending ask, from the TUI or
  `guardit answer`, records the same scope.
- An app with rules of its own for particular ports or hosts now reads `(custom)` instead
  of showing one of them and a count of the others.
- **`install.sh` finishes the job.** It now checks for `nft` and `curl`, turns on ads +
  phishing blocking and downloads the lists on a first install, and loads the ruleset into
  the kernel — which had been left as three commands to remember, with the consequence that
  the encrypted-DNS rules never reached the kernel at all. An existing configuration is
  left alone, including a deliberate `blocklist off`.
- **Connection setup got a lot cheaper.** Resolving which process owns a socket walked
  every `/proc/<pid>/fd` on the machine, once per connection, while that connection's first
  packet sat in the queue waiting for a verdict — and serialised, since the queue thread
  handles one at a time. Every outbound connection gets a fresh ephemeral port, so the
  existing (proto, port) cache never helped it. The processes that owned the last few
  sockets are now checked first, so a browser opening fifty sockets pays the full walk once
  and a single directory listing for the other forty-nine. Every candidate is still
  confirmed against `/proc`, so the guess can cost a listing but never name the wrong app.
- **`require_resolved`**: refuse outbound HTTPS to an address no DNS answer ever named.
  `block_encrypted_dns` closes the DoH endpoints there are lists for; this closes the ones
  there aren't, on the evidence that an app which never asked for a name cannot have
  learnt the address from a resolver we can read. Off by default — an app with a hardcoded
  address is refused on the same evidence — and a rule naming that exact port overrides it.
  The name map now evicts its oldest half at the cap instead of emptying itself, which was
  harmless while it only labelled a dashboard and would have been an outage here.
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
- Opening the audit tab for one app (`a`) now scopes **both** halves to it: the listening
  ports pane shows that app's ports, not every socket on the machine.
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
- **The ruleset can no longer go missing without the daemon noticing.** Anything with root
  can flush guardit's nftables table, and the daemon would carry on holding queues nothing
  routed to any more — traffic simply stops being controlled, and nothing about that looks
  broken. It now checks every 5 seconds and reloads, loudly.
- **The daemon never gets abandoned by systemd.** The unit hit the default start limit —
  five failures in ten seconds and it is left stopped, with the ruleset still loaded and
  no listener on the queues, which is a machine with no network at all until someone
  intervenes by hand. `StartLimitIntervalSec=0`: a crash loop now costs connectivity only
  while it lasts.
- **A connection refused by a blocklist now reads as refused in the flow pane**, and says
  which policy did it. The pane recomputed each row's colour from the app rules alone, so a
  connection to a blocked name under a whole-app `allow` was painted green while the daemon
  went on dropping it — the two policies decide on evidence of their own, which no reading
  of the rules can reach. The reason travels on the row, and the peer is truncated to make
  room for it rather than the other way round.
- **The grid is about access control again.** Ads & tracking had grown to a full-height
  third of the screen — something you read, taking more room than the pane you operate — so
  it moves to its own tab on `B`, with its headline in the status line. What is left is
  three panes on one subject: the rules the kernel holds, what the machine has been doing,
  and the app list beside its flow.
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
