# Changelog

## Unreleased

- **A selected row never hides its dimmed half.** The selection's background is the same
  colour as dimmed text, so a disabled rule, a category's lists or a flow row's reason
  vanished exactly when it was selected. Such text is now redrawn in the normal text
  colour — in every theme and every list, the rest of the row keeping its colours.

- **Recently blocked names are a list you can act on.** In the blocking tab `h`/`l` (or
  `Tab`) moves from the categories to the names most recently refused; `j/k` walks them,
  newest first, and `y` on one adds it to the allowlist — the entry `guardit blocklist
  allow` writes — so a false positive is fixed where it shows up. The selection stays on
  its name as new blocks arrive above it, so `y` never lands on a name you did not look
  at. On a narrow terminal the names take the categories' place while they have the focus.

- **Which lists a category uses is yours to choose.** `[blocklist.category_sources]` in
  rules.toml has one line per category — `phishing = ["hagezi:tif.medium"]` — written out
  with the catalogue's choice the first time guardit saves the file, so what a category
  means lives in the file rather than in the binary. The blocking tab shows each
  category's lists beside it and `s` steps it through every list filed under it; a hand
  edit shows up in an open TUI within half a second, and a list it names that is not on
  disk yet is fetched. The reason to want it: with nine categories on, `hagezi:tif` alone
  is 2.3 million of the 3 million domains the daemon holds in memory.
- **A category's lists come due on schedule.** The updater decided whether anything was
  due from the hand-added lists alone, which predate categories: a newly enabled category
  waited for the DoH ip list to go stale — up to a day — before it downloaded, and with
  `block_encrypted_dns` off a config built from categories alone never refreshed at all.

- **`guardit allow` / `deny` / `rm` reload the kernel themselves**, when guardit is already
  running. A saved rule that does nothing until you remember a second command is a rule you
  will believe is in force when it is not — the TUI has always applied on the spot for that
  reason, and the CLI writing to the same file should not be the half that quietly waits.
  It stays a no-op where the table is not loaded at all: `guardit allow` must not be the
  thing that switches the firewall on, since that also stands up the queues.

- **The config is written atomically.** `fs::write` truncates the file and then writes into
  it, so a crash, a full disk or a power cut between the two left an empty or half-written
  `/etc/guardit/rules.toml` — every rule on the machine gone, and the daemon reloading that
  into a firewall which now permits whatever the defaults permit. It now writes a sibling
  temp file, flushes it to the disk itself, and renames over the original, so a reader sees
  either the whole old file or the whole new one. A config someone tightened to 0600 keeps
  its permissions across the write.
- **history.jsonl is capped, and read without loading it.** It grew forever by design, and
  `read_history` read the whole thing into memory to hand back the last hundred lines — on
  daemon startup, on every `guardit log-app`, and every time the TUI opened its log tab. On
  a desktop that gets reinstalled eventually this was fine; on a machine that stays up it
  is hundreds of megabytes a year, read in full, several times a day. The file is now
  trimmed to its newer half past 32 MB (the same treatment blocked.jsonl already got) and
  the readers stream it, holding only the entries they are going to return.

- **Auto mode: unruled connections decided here, not asked about.** `guardit auto on`, `m`
  in the TUI, or `[auto] enabled = true`. Holding the packet and asking is the right shape
  for a desktop somebody is sitting in front of and the wrong one for everything else — a
  server, a machine you are ssh'd into, a laptop whose owner is tired of answering. Every
  decision rests on one fact about the connection that a person would reach the same
  conclusion from, and the fact is written next to the verdict in the flow pane, the audit
  tab and `guardit log-app`: a binary gone from disk or running out of `/tmp` is refused;
  SMB, RDP, telnet or port 25 *across the internet* is refused, while the same port on your
  own network is fine; unsolicited inbound from outside is refused, and from your own
  network it follows whether anything is actually serving that port; a name this machine
  resolved and then reached is allowed, as is a packaged binary on a port packaged binaries
  use. Anything it has no such fact about it declines to judge, and `--fallback
  allow|deny|ask` decides those — `allow` by default, because the heuristics are written to
  catch what is wrong rather than to recognise everything that is right, and `ask` keeps
  the prompt so auto only ever saves you the questions it could answer itself. No rule is
  written for any of it: each connection is judged again on the evidence current at that
  moment, so a replaced binary or a service that stopped listening changes the answer with
  nothing to clean up. Toggling it takes effect within seconds under a running daemon, with
  no restart and no held connection dropped.

- **The preset catalogue: 32 of them, grouped, filterable, multi-rule.** `p` now opens over
  the whole grid instead of into a quarter-width pane, because seven single-rule specs were
  never going to cover what people actually want to say. Type to filter, `↑`/`↓` to move,
  `Enter` to add. Entries are grouped by what you are trying to do — `off` for the escape
  hatches, `lan` for your own network, `in` for what this machine offers, `out` for what it
  may reach, `harden` for ports worth shutting on principle, `bundle` for a whole posture
  (laptop on untrusted wifi, web server, home desktop, paranoid) in one keystroke. One
  entry can lay down several rules, and rules you already have are skipped, so overlapping
  picks leave no duplicates. Every entry carries a line saying what it does to your traffic
  — including the part nobody guesses, that an `allow` preset is a kernel-level accept and
  so takes per-app control off that traffic entirely.
- **An "Allow everything" preset**, first in the TUI's `p` list: one unqualified `accept`
  above the queue lines in both chains, so nothing reaches the daemon at all — no per-app
  matching, no prompts, no connection-layer blocking. The thing to reach for when guardit
  is in the way of something and you need the machine working *now*, instead of
  `systemctl stop guardit`, which leaves the queues loaded with nothing listening and
  takes the network down with it. It is a rule like any other, so `space` toggles it back
  off and every other rule applies again. `guardit allow` with no arguments is the same
  thing headless.

- **IP/port rules apply outbound too, and a rule can name its direction.** They only ever
  rendered into the input chain, so `guardit deny --src 1.2.3.4` did not stop anything on
  this machine from reaching 1.2.3.4, and no ip/port rule could short-circuit the per-app
  queue on the way out — which is what made an "allow everything" rule impossible to
  write. `Rule::src` is the peer in both directions now: matched as `ip saddr` in the
  input chain and `ip daddr` in the output chain, so one rule means the same thing
  whichever end opens the connection. A rule with no direction covers both, which is what
  every rule written before this field existed meant; `--dir in` / `--dir out` (or a
  trailing `in`/`out` in the TUI's add-rule spec) narrows one to a single side.

- **`filter_forwarded`**: guardit can now filter traffic that only passes through this
  machine — containers, bridged VMs. Names and addresses only: your ip/port rules, the
  encrypted-DNS refusals, and the blocklists, fed by the same DNS tap, which now watches
  the forward chain too. Per-app control cannot apply, since a forwarded packet has no
  local process behind it. Off by default; accept-by-default and bypassing when on, so it
  can only subtract from what already flows and a restarting daemon never cuts container
  networking.
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
- **Fixed: the blocking tab could trap you.** Opening it and then opening the audit tab
  from inside it recorded the blocking tab as "where you were", so leaving audit landed
  there and leaving *that* went to itself — `q` and `B` both did nothing and the grid was
  unreachable. The two transitions are now the only way in and out, and neither can record
  a tab as somewhere to go back to.
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
