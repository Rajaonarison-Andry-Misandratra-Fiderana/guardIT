use crate::config::{
    Action, AppRule, Config, Direction, config_path, fingerprint, match_rule, now_ts,
};
use crate::ipc::{self, ClientMsg, FlowStatus, FlowWire, ServerMsg};
use crate::ruleset::{QUEUE_DNS, QUEUE_IN, QUEUE_OUT};
use nfq::{Queue, Verdict};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

type AppRules = Arc<Mutex<Vec<AppRule>>>;
/// one Sender per connected TUI — `broadcast` fans a message out to all of
/// them and lazily drops any whose paired Receiver hung up (client
/// disconnected), so multiple `guardit tui` instances can watch/act on the
/// same daemon at once instead of only the first one connected
type Subscribers = Arc<Mutex<Vec<Sender<ServerMsg>>>>;
/// capped log of every connection attempt the daemon has verdicted (pending
/// asks and their eventual resolution, plus instantly-verdicted matched
/// connections) — this is what makes a reconnecting TUI able to show "what
/// ports has this app used" instead of starting blank every time it opens
type History = Arc<Mutex<Vec<FlowWire>>>;
type PendingRegistry = Arc<Mutex<HashMap<u32, Sender<Action>>>>;
/// latest scan of every LISTENing/bound local socket, see list_listening()
type ListeningState = Arc<Mutex<Vec<ipc::ListenEntry>>>;

const HISTORY_CAP: usize = 300;
const LISTEN_SCAN_INTERVAL: Duration = Duration::from_secs(5);
const EXE_CACHE_TTL: Duration = Duration::from_secs(3);

fn push_history(history: &History, entry: FlowWire) {
    let mut h = history.lock().unwrap();
    h.push(entry);
    if h.len() > HISTORY_CAP {
        let excess = h.len() - HISTORY_CAP;
        h.drain(0..excess);
    }
}

/// returns the updated entry so the caller can persist it
fn resolve_history(history: &History, req_id: u32, status: FlowStatus) -> Option<FlowWire> {
    let mut h = history.lock().unwrap();
    let e = h.iter_mut().rev().find(|e| e.req_id == Some(req_id))?;
    e.status = status;
    Some(e.clone())
}

/// alongside `rules.toml` — an append-only record of every *final* flow
/// entry (matched connections and resolved asks, never the transient
/// Pending state) so history survives a daemon restart, not just a TUI
/// reconnect. No rotation/truncation: grows forever. Fine for how small
/// each line is and how long a desktop box actually stays up between
/// reinstalls; add rotation if that stops being true.
pub fn history_log_path() -> std::path::PathBuf {
    config_path().with_file_name("history.jsonl")
}

fn append_history_line(entry: &FlowWire) {
    use std::io::Write as _;
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_log_path())
        && let Ok(line) = serde_json::to_string(entry)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// the last `limit` entries of history.jsonl, oldest first, optionally only
/// those whose exe contains `filter` — one reader shared by the daemon's
/// startup reload, `guardit log-app`, and the TUI's log tab
pub fn read_history(limit: usize, filter: Option<&str>) -> Vec<FlowWire> {
    let Ok(text) = fs::read_to_string(history_log_path()) else {
        return Vec::new();
    };
    let mut entries: Vec<FlowWire> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &FlowWire| filter.is_none_or(|f| e.exe.contains(f)))
        .collect();
    let start = entries.len().saturating_sub(limit);
    entries.split_off(start)
}

/// connection attempts per app over the whole audit trail, streamed so a
/// large history.jsonl is never held in memory at once
pub fn count_history() -> HashMap<String, u64> {
    use std::io::BufRead;
    let mut counts = HashMap::new();
    let Ok(f) = fs::File::open(history_log_path()) else {
        return counts;
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if let Ok(e) = serde_json::from_str::<FlowWire>(&line) {
            *counts.entry(e.exe).or_default() += 1;
        }
    }
    counts
}

pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

/// `guardit log-app` — reads the full, unthrottled audit trail straight off
/// disk (not the capped/throttled in-memory buffer the TUI sees live) and
/// prints it. This is the actual answer to "what did every app try to
/// connect to, ever" — history.jsonl is never deduped, only the live view is.
pub fn print_log_app(exe_filter: Option<&str>, n: usize) {
    let entries = read_history(n, exe_filter);
    if entries.is_empty() {
        println!(
            "no matching connection attempts logged ({})",
            history_log_path().display()
        );
        return;
    }
    let now = now_ts();
    println!(
        "{:<8}{:<6}{:<20}{:<6}{:<6}{:<8}EXE",
        "AGO", "DIR", "PEER", "PROTO", "PORT", "STATUS"
    );
    for e in entries {
        let status = match e.status {
            FlowStatus::Allowed => "allow",
            FlowStatus::Denied => "deny",
            FlowStatus::Pending => "pending",
        };
        println!(
            "{:<8}{:<6}{:<20}{:<6}{:<6}{:<8}{}",
            ago(now.saturating_sub(e.ts)),
            e.direction.as_str(),
            e.peer(),
            e.proto,
            e.port.map(|p| p.to_string()).unwrap_or_default(),
            status,
            e.exe,
        );
    }
}

/// dedupes noisy repeat traffic (e.g. a resolver re-querying DNS every few
/// seconds) so an already-ruled app doesn't spam the history log and the
/// Flow pane with the same (app, proto, port) line over and over — only
/// pending *asks* skip this, since those are rare first-contact events by
/// nature, never chatty
type Throttle = Arc<Mutex<HashMap<(String, u8, u16, bool), Instant>>>;
const HISTORY_THROTTLE: Duration = Duration::from_secs(30);

fn should_log_matched(throttle: &Throttle, key: (String, u8, u16, bool)) -> bool {
    let mut t = throttle.lock().unwrap();
    let now = Instant::now();
    if let Some(&last) = t.get(&key)
        && now.duration_since(last) < HISTORY_THROTTLE
    {
        return false;
    }
    t.insert(key, now);
    true
}

struct PktInfo {
    proto: u8, // 6 = tcp, 17 = udp
    src_port: u16,
    dst_port: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    /// byte offset of the L4 header in the packet
    l4: usize,
}

/// dispatches on the version nibble in the first byte — same header shape
/// (proto + 4 ports at a fixed offset) either way, just different offsets
fn parse_packet(payload: &[u8]) -> Option<PktInfo> {
    match payload.first()? >> 4 {
        4 => parse_ipv4(payload),
        6 => parse_ipv6(payload),
        _ => None,
    }
}

/// Fixed IPv4 header: version/IHL at byte 0, protocol at byte 9, L4 header
/// starts at IHL*4 bytes in — src/dst port are the first 4 bytes of it for
/// both TCP and UDP.
fn parse_ipv4(payload: &[u8]) -> Option<PktInfo> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = (payload[0] & 0x0f) as usize * 4;
    let proto = payload[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let l4 = payload.get(ihl..ihl + 4)?;
    Some(PktInfo {
        proto,
        src_port: u16::from_be_bytes([l4[0], l4[1]]),
        dst_port: u16::from_be_bytes([l4[2], l4[3]]),
        l4: ihl,
        src_ip: IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        )),
        dst_ip: IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        )),
    })
}

/// Fixed 40-byte IPv6 header: next-header (protocol, when there are no
/// extension headers) at byte 6, src addr at 8..24, dst addr at 24..40, L4
/// header right after at byte 40. Doesn't walk an extension-header chain
/// (hop-by-hop/routing/fragment headers) — rare for ordinary app traffic,
/// falls back to the caller's default verdict when present, same as any
/// other packet this can't parse.
fn parse_ipv6(payload: &[u8]) -> Option<PktInfo> {
    if payload.len() < 44 {
        return None;
    }
    let proto = payload[6];
    if proto != 6 && proto != 17 {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    dst.copy_from_slice(&payload[24..40]);
    let l4 = &payload[40..44];
    Some(PktInfo {
        proto,
        src_port: u16::from_be_bytes([l4[0], l4[1]]),
        dst_port: u16::from_be_bytes([l4[2], l4[3]]),
        l4: 40,
        src_ip: IpAddr::V6(Ipv6Addr::from(src)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(dst)),
    })
}

/// ip -> the name whose lookup returned it, fed by dns_loop
static DNS_NAMES: LazyLock<Mutex<HashMap<IpAddr, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// ponytail: no TTL, the whole map is dropped past this many entries
const DNS_NAMES_CAP: usize = 8192;

pub fn peer_name(ip: &IpAddr) -> Option<String> {
    DNS_NAMES.lock().unwrap().get(ip).cloned()
}

/// passive DNS tap on QUEUE_DNS: every UDP reply from port 53 is parsed
/// for A/AAAA answers and accepted untouched. Only ever a display aid —
/// DoH/DoT and anything the app already had cached go unseen.
fn dns_loop() -> std::io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(QUEUE_DNS)?;
    loop {
        let mut msg = queue.recv()?;
        if let Some(pkt) = parse_packet(msg.get_payload())
            && pkt.proto == 17
            && pkt.src_port == 53
            && let Some(dns) = msg.get_payload().get(pkt.l4 + 8..)
            && let Some((name, ips)) = parse_dns_answers(dns)
        {
            let mut map = DNS_NAMES.lock().unwrap();
            if map.len() >= DNS_NAMES_CAP {
                map.clear();
            }
            for ip in ips {
                map.insert(ip, name.clone());
            }
        }
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}

/// a DNS *response*: the first question's name and every A/AAAA rdata in
/// the answer section, keyed to that name (so a CNAME chain still maps
/// the final addresses to what the app actually asked for)
fn parse_dns_answers(msg: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return None;
    }
    let u16_at = |i: usize| Some(u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]));
    let (qd, an) = (u16_at(4)?, u16_at(6)?);
    let mut pos = 12;
    let mut qname = None;
    for _ in 0..qd {
        let (name, end) = dns_read_name(msg, pos)?;
        qname.get_or_insert(name);
        pos = end + 4; // qtype, qclass
    }
    let qname = qname?;
    let mut ips = Vec::new();
    for _ in 0..an {
        let (_, end) = dns_read_name(msg, pos)?;
        let rtype = u16_at(end)?;
        let rdlen = u16_at(end + 8)? as usize; // type, class, ttl(4)
        let rdata = msg.get(end + 10..end + 10 + rdlen)?;
        match (rtype, rdlen) {
            (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?))),
            (28, 16) => ips.push(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).ok()?,
            ))),
            _ => {}
        }
        pos = end + 10 + rdlen;
    }
    Some((qname, ips))
}

/// RFC 1035 name at `pos`, following compression pointers; returns the
/// dotted name and the offset just past the name *in the original stream*
fn dns_read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            hops += 1;
            if hops > 16 {
                return None; // pointer loop
            }
            pos = ptr;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
    }
    Some((name, end.unwrap_or(pos)))
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    }
}

/// one row of /proc/net/{tcp,udp}[6]: local address as the raw hex string,
/// local port, connection state (hex, e.g. "0A" = LISTEN), socket inode
struct ProcNetRow<'a> {
    ip_hex: &'a str,
    port: u16,
    state: &'a str,
    inode: u64,
}

/// rows with a live socket (inode != 0) — the columns every /proc/net
/// consumer here needs, parsed once
fn proc_net_rows(text: &str) -> impl Iterator<Item = ProcNetRow<'_>> {
    text.lines().skip(1).filter_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            return None;
        }
        let (ip_hex, port_hex) = cols[1].split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let inode = cols[9].parse::<u64>().ok().filter(|&i| i != 0)?;
        Some(ProcNetRow {
            ip_hex,
            port,
            state: cols[3],
            inode,
        })
    })
}

/// local_port -> socket inode, by scanning /proc/net/{tcp,udp}[46]
fn find_inode(proto: u8, local_port: u16) -> Option<u64> {
    let files: [&str; 2] = match proto {
        6 => ["/proc/net/tcp", "/proc/net/tcp6"],
        17 => ["/proc/net/udp", "/proc/net/udp6"],
        _ => return None,
    };
    files.iter().find_map(|path| {
        let text = fs::read_to_string(path).ok()?;
        proc_net_rows(&text)
            .find(|r| r.port == local_port)
            .map(|r| r.inode)
    })
}

/// every socket inode -> owning pid, from a single pass over /proc/*/fd.
/// `find_pid_by_inode` walks all of /proc per lookup, so resolving a whole
/// /proc/net table one socket at a time re-walked it once per socket — this
/// walks it once for the lot. Lowest fd wins a shared inode (fork/dup), same
/// as the sequential scan's /proc read order.
fn inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(procs) = fs::read_dir("/proc") else {
        return map;
    };
    for proc_entry in procs.flatten() {
        let Some(pid) = proc_entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path())
                && let Some(inode) = link
                    .to_str()
                    .and_then(|l| l.strip_prefix("socket:["))
                    .and_then(|l| l.strip_suffix(']'))
                    .and_then(|i| i.parse().ok())
            {
                map.entry(inode).or_insert(pid);
            }
        }
    }
    map
}

/// inode -> owning pid, by scanning /proc/*/fd for a `socket:[inode]` symlink
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .find(|&pid| pid_owns_inode(pid, inode))
}

/// does `pid` still hold an fd pointing at socket `inode` right now?
fn pid_owns_inode(pid: u32, inode: u64) -> bool {
    let target = format!("socket:[{inode}]");
    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.flatten().any(|fd| {
        fs::read_link(fd.path())
            .map(|l| l.to_string_lossy() == target)
            .unwrap_or(false)
    })
}

/// port -> inode -> pid -> exe, the way any /proc-based tool (ss, lsof, ...)
/// does it — inherently racy (pid could theoretically exit and its number
/// get reused between the inode lookup and the exe read). The re-check
/// right before trusting the exe narrows that window to essentially the
/// read_link call itself; it doesn't eliminate it — a real fix needs a
/// kernel-level atomic association (e.g. an eBPF hook at connect() time),
/// which is a much bigger feature than this daemon needs today.
/// /proc/net/{tcp,udp}[6] encode an IPv4 address as 4 hex bytes in the
/// kernel's native (little-endian on x86) word order — read left to right
/// and reverse the byte order to get the real address
fn parse_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let b: Vec<u8> = (0..4)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect();
    Some(Ipv4Addr::new(b[3], b[2], b[1], b[0]))
}

/// same idea as parse_hex_ipv4 but for the 4 32-bit words that make up an
/// IPv6 address — each word individually byte-reversed
fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let chunk = &hex[word * 8..word * 8 + 8];
        for i in 0..4 {
            bytes[word * 4 + i] =
                u8::from_str_radix(&chunk[(3 - i) * 2..(3 - i) * 2 + 2], 16).unwrap_or(0);
        }
    }
    Some(Ipv6Addr::from(bytes))
}

/// every socket currently in LISTEN (TCP, state `0A`) or bound-and-receiving
/// (UDP, state `07` — UDP has no real LISTEN, this is the closest analogue)
/// state, resolved to its owning exe. This is the actual answer to "who's
/// using this port" — unlike a NEW-connection NFQUEUE event, it sees a
/// service the moment it starts listening, no incoming traffic required.
fn list_listening() -> Vec<ipc::ListenEntry> {
    const SOURCES: [(&str, &str, &str); 4] = [
        ("/proc/net/tcp", "tcp", "0A"),
        ("/proc/net/tcp6", "tcp", "0A"),
        ("/proc/net/udp", "udp", "07"),
        ("/proc/net/udp6", "udp", "07"),
    ];
    let pids = inode_pid_map();
    let mut out = Vec::new();
    for (path, proto_name, want_state) in SOURCES {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let is_v6 = path.ends_with('6');
        for row in proc_net_rows(&text).filter(|r| r.state == want_state) {
            let addr: Option<IpAddr> = if is_v6 {
                parse_hex_ipv6(row.ip_hex).map(IpAddr::V6)
            } else {
                parse_hex_ipv4(row.ip_hex).map(IpAddr::V4)
            };
            let Some(addr) = addr else { continue };
            let Some(&pid) = pids.get(&row.inode) else {
                continue;
            };
            let Some(exe) = fs::read_link(format!("/proc/{pid}/exe")).ok() else {
                continue;
            };
            out.push(ipc::ListenEntry {
                proto: proto_name.to_string(),
                addr: addr.to_string(),
                port: row.port,
                exe: exe.to_string_lossy().into_owned(),
            });
        }
    }
    out
}

/// the real EADDRINUSE rule: a wildcard bind (0.0.0.0 / ::) covers every
/// address, so it overlaps ANY other bind on the same port; two specific,
/// different addresses never overlap even on the same port
fn addrs_overlap(a: &str, b: &str) -> bool {
    let wildcard = |s: &str| s == "0.0.0.0" || s == "::";
    a == b || wildcard(a) || wildcard(b)
}

/// true port conflicts (see module docs / the daemon binary's design notes):
/// same proto+port, overlapping address scope, and — critically — a
/// *different* exe. Same exe on multiple entries is SO_REUSEPORT-style
/// worker sharing, explicitly not a conflict. In steady state this is
/// expected to almost always be empty: the kernel already refuses the
/// losing bind() before it ever shows up in /proc/net/*, so what we're
/// looking at here is only ever the (rare, transient) cases that still made
/// it into the table.
pub fn find_conflicts(entries: &[ipc::ListenEntry]) -> Vec<(ipc::ListenEntry, ipc::ListenEntry)> {
    let mut out = Vec::new();
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            let (a, b) = (&entries[i], &entries[j]);
            if a.proto == b.proto
                && a.port == b.port
                && a.exe != b.exe
                && addrs_overlap(&a.addr, &b.addr)
            {
                out.push((a.clone(), b.clone()));
            }
        }
    }
    out
}

fn resolve_exe(proto: u8, local_port: u16) -> Option<String> {
    let inode = find_inode(proto, local_port)?;
    let pid = find_pid_by_inode(inode)?;
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if !pid_owns_inode(pid, inode) {
        return None;
    }
    Some(app_identity(pid).unwrap_or_else(|| exe.to_string_lossy().into_owned()))
}

/// a sandboxed app's /proc/<pid>/exe is a path inside its own mount
/// namespace ("/app/bin/firefox"), meaningless on the host and shared by
/// every flatpak — so those get ruled by app id instead:
/// "flatpak:org.mozilla.firefox" (from the .flatpak-info the sandbox
/// mounts at its root) or "snap:firefox.firefox" (from the cgroup scope
/// snapd puts it in). None = plain host process, use the exe path.
fn app_identity(pid: u32) -> Option<String> {
    if let Ok(info) = fs::read_to_string(format!("/proc/{pid}/root/.flatpak-info"))
        && let Some(id) = flatpak_id(&info)
    {
        return Some(format!("flatpak:{id}"));
    }
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    snap_id(&cgroup).map(|id| format!("snap:{id}"))
}

/// `name=` under `[Application]` of a .flatpak-info file
fn flatpak_id(info: &str) -> Option<&str> {
    let app = info.split("[Application]").nth(1)?;
    app.lines()
        .map(str::trim)
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| l.strip_prefix("name="))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// "snap.<snap>.<app>" out of a cgroup path segment like
/// "snap.firefox.firefox-0f4e…(uuid).scope"
fn snap_id(cgroup: &str) -> Option<&str> {
    cgroup
        .split(['/', '\n'])
        .find_map(|seg| seg.strip_prefix("snap.")?.strip_suffix(".scope"))
        // snap and app names may contain '-', the uuid is fixed-width: cut it
        .map(|rest| match rest.len().checked_sub(37) {
            Some(cut)
                if rest.as_bytes()[cut] == b'-'
                    && rest[cut + 1..]
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || c == '-') =>
            {
                &rest[..cut]
            }
            _ => rest,
        })
        .filter(|id| id.contains('.'))
}

/// `resolve_exe`, but the /proc/*/fd scan it does per packet is the hot path
/// — TTL-cache it per (proto, port).
fn resolve_exe_cached(proto: u8, local_port: u16) -> Option<String> {
    type Cache = HashMap<(u8, u16), (Option<String>, Instant)>;
    static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::new()));
    let (key, now) = ((proto, local_port), Instant::now());
    if let Some((exe, at)) = CACHE.lock().unwrap().get(&key)
        && now.duration_since(*at) < EXE_CACHE_TTL
    {
        return exe.clone();
    }
    let exe = resolve_exe(proto, local_port);
    CACHE.lock().unwrap().insert(key, (exe.clone(), now));
    exe
}

/// `port: None` (whole-app, from Apps/Conflicts) wipes every existing rule
/// for `exe` — the app-wide port-specific overrides too, since "allow the
/// whole app" is meant to actually mean every port. `port: Some(p)`
/// (per-port, from Flow) only replaces that one port's existing override
/// for the same direction, leaving the app-wide default and every other
/// port alone.
pub fn upsert_rule(
    exe: &str,
    port: Option<u16>,
    direction: Option<Direction>,
    action: Action,
    expires: Option<u64>,
) -> Vec<AppRule> {
    Config::update(|cfg| {
        match port {
            None => cfg.app_rule.retain(|r| r.exe != exe),
            Some(p) => cfg
                .app_rule
                .retain(|r| !(r.exe == exe && r.port == Some(p) && r.direction == direction)),
        }
        let id = cfg.next_app_id();
        cfg.app_rule.push(AppRule {
            id,
            exe: exe.to_string(),
            port,
            direction,
            action,
            enabled: true,
            expires,
            fingerprint: fingerprint(exe),
        });
    })
    .app_rule
}

/// what the rules say for this connection — `None` also when the matching
/// rule was made for a binary that has since changed, so the app is asked
/// again (and the answer replaces the rule with a fresh fingerprint)
fn ruled(rules: &[AppRule], exe: &str, port: u16, dir: Direction) -> Option<Action> {
    let r = match_rule(rules, exe, Some(port), Some(dir))?;
    if r.stale() {
        return None;
    }
    Some(r.action)
}

/// picks up a hand edit (or `guardit import` with no daemon reachable) of
/// rules.toml: `Some(rules)` when the file's mtime moved AND its app rules
/// differ from what we hold. Our own writes move the mtime too, but then
/// the content matches and nothing is broadcast. A malformed file is
/// logged and ignored — the previous rules stay in force.
/// ponytail: 5s mtime poll, inotify if the lag ever matters
fn reload_if_edited(
    app_rules: &AppRules,
    last_mtime: &mut Option<std::time::SystemTime>,
) -> Option<Vec<AppRule>> {
    let mtime = fs::metadata(config_path()).and_then(|m| m.modified()).ok();
    if mtime == *last_mtime {
        return None;
    }
    *last_mtime = mtime;
    let fresh = match Config::try_load() {
        Ok(cfg) => cfg.app_rule,
        Err(e) => {
            eprintln!("guardit daemon: {e} — keeping the rules already loaded");
            return None;
        }
    };
    let mut cur = app_rules.lock().unwrap();
    if *cur == fresh {
        return None;
    }
    eprintln!("guardit daemon: rules.toml changed on disk, reloaded");
    *cur = fresh.clone();
    Some(fresh)
}

/// drops every expired rule from the file; `Some(rules)` when anything
/// changed. match_rule already ignores expired rules, this is the cleanup
/// that makes them disappear from the file and the TUI too.
fn sweep_expired(app_rules: &AppRules) -> Option<Vec<AppRule>> {
    let now = now_ts();
    if !app_rules.lock().unwrap().iter().any(|r| r.expired(now)) {
        return None;
    }
    let fresh = Config::update(|cfg| cfg.app_rule.retain(|r| !r.expired(now)));
    *app_rules.lock().unwrap() = fresh.app_rule.clone();
    Some(fresh.app_rule)
}

fn to_verdict(action: Action) -> Verdict {
    match action {
        Action::Allow => Verdict::Accept,
        Action::Deny => Verdict::Drop,
    }
}

pub fn run(cfg: Config, debug: bool) -> std::io::Result<()> {
    eprintln!(
        "guardit daemon {}: starting{}",
        env!("CARGO_PKG_VERSION"),
        if debug {
            " (--debug, always-accept)"
        } else {
            ""
        }
    );
    let app_rules: AppRules = Arc::new(Mutex::new(cfg.app_rule.clone()));
    let history: History = Arc::new(Mutex::new(read_history(HISTORY_CAP, None)));
    let listening: ListeningState = Arc::new(Mutex::new(list_listening()));
    let throttle: Throttle = Arc::new(Mutex::new(HashMap::new()));
    let pending_registry: PendingRegistry = Arc::new(Mutex::new(HashMap::new()));
    let next_req_id = Arc::new(AtomicU32::new(1));
    let (event_tx, event_rx) = mpsc::channel::<ServerMsg>();
    let timeout = Duration::from_secs(cfg.pending_timeout_secs as u64);
    let default_verdict = cfg.default_verdict;
    let notify = cfg.notify;

    let mut threads = Vec::new();
    for (dir, queue_num) in [(Direction::In, QUEUE_IN), (Direction::Out, QUEUE_OUT)] {
        let app_rules = app_rules.clone();
        let history = history.clone();
        let throttle = throttle.clone();
        let pending_registry = pending_registry.clone();
        let next_req_id = next_req_id.clone();
        let event_tx = event_tx.clone();
        threads.push(std::thread::spawn(move || {
            if let Err(e) = queue_loop(
                dir,
                queue_num,
                app_rules,
                history,
                throttle,
                pending_registry,
                next_req_id,
                event_tx,
                timeout,
                default_verdict,
                debug,
            ) {
                eprintln!("guardit daemon: queue {queue_num} ({dir:?}) stopped: {e}");
            }
        }));
    }

    std::thread::spawn(|| {
        if let Err(e) = dns_loop() {
            eprintln!(
                "guardit daemon: dns tap (queue {QUEUE_DNS}) stopped: {e} — peers show as ips"
            );
        }
    });

    if !debug {
        let scan_listening = listening.clone();
        let scan_event_tx = event_tx.clone();
        let scan_app_rules = app_rules.clone();
        std::thread::spawn(move || {
            let mut cfg_mtime = fs::metadata(config_path()).and_then(|m| m.modified()).ok();
            loop {
                std::thread::sleep(LISTEN_SCAN_INTERVAL);
                if let Some(rules) = reload_if_edited(&scan_app_rules, &mut cfg_mtime) {
                    let _ = scan_event_tx.send(ServerMsg::AppRules(rules));
                }
                if let Some(rules) = sweep_expired(&scan_app_rules) {
                    let _ = scan_event_tx.send(ServerMsg::AppRules(rules));
                }
                let fresh = list_listening();
                let changed = {
                    let mut cur = scan_listening.lock().unwrap();
                    let changed = *cur != fresh;
                    *cur = fresh.clone();
                    changed
                };
                if changed {
                    let _ = scan_event_tx.send(ServerMsg::Listening(fresh));
                }
            }
        });
        ipc_thread(
            app_rules,
            history,
            listening,
            pending_registry,
            event_rx,
            notify,
        )?;
    } else {
        // in --debug mode there's no IPC server; just keep the process alive
        // while the queue threads print what they resolve
        for t in threads {
            let _ = t.join();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn queue_loop(
    dir: Direction,
    queue_num: u16,
    app_rules: AppRules,
    history: History,
    throttle: Throttle,
    pending_registry: PendingRegistry,
    next_req_id: Arc<AtomicU32>,
    event_tx: Sender<ServerMsg>,
    timeout: Duration,
    default_verdict: Action,
    debug: bool,
) -> std::io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    eprintln!("guardit daemon: bound queue {queue_num} ({dir:?}) — waiting for new connections");

    loop {
        let mut msg = queue.recv()?;

        let Some(pkt) = parse_packet(msg.get_payload()) else {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        };
        let (local_port, peer_port, peer_addr) = match dir {
            Direction::In => (pkt.dst_port, pkt.src_port, pkt.src_ip),
            Direction::Out => (pkt.src_port, pkt.dst_port, pkt.dst_ip),
        };
        let peer_ip = peer_addr.to_string();
        let peer_name = peer_name(&peer_addr);
        // the port a rule is about is always the *destination* port: the
        // service being reached — remote for outbound, our own local one for
        // inbound (the peer's source port is ephemeral, ruling on it would
        // never match anything again)
        let rule_port = pkt.dst_port;

        let exe = resolve_exe_cached(pkt.proto, local_port);

        if debug {
            println!(
                "[{dir:?}] {} {peer_ip}:{peer_port} proto={}",
                exe.as_deref().unwrap_or("<unresolved>"),
                proto_name(pkt.proto)
            );
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let Some(exe) = exe else {
            msg.set_verdict(to_verdict(default_verdict));
            queue.verdict(msg)?;
            continue;
        };

        // a per-port override (Flow pane) wins over the app's whole-app
        // default (Apps/Conflicts panes) when both exist for this app
        let matched = ruled(&app_rules.lock().unwrap(), &exe, rule_port, dir);

        let verdict = match matched {
            Some(action) => {
                // already ruled — verdict immediately. history.jsonl (disk)
                // gets EVERY one of these, unthrottled — it's the actual audit
                // trail, `guardit log-app` reads it back. The live in-memory
                // history / TUI broadcast is throttled separately — a chatty
                // app (DNS resolver etc.) would otherwise spam the dashboard
                // with an identical line every few seconds; that declutter
                // only applies to what you *see* live, never to what's kept.
                let wire = FlowWire {
                    req_id: None,
                    exe: exe.clone(),
                    direction: dir,
                    proto: proto_name(pkt.proto).to_string(),
                    port: Some(rule_port),
                    peer_ip: peer_ip.clone(),
                    peer_name: peer_name.clone(),
                    status: action.into(),
                    ts: now_ts(),
                };
                append_history_line(&wire);
                let throttle_key = (exe.clone(), pkt.proto, rule_port, dir == Direction::Out);
                if should_log_matched(&throttle, throttle_key) {
                    push_history(&history, wire.clone());
                    let _ = event_tx.send(ServerMsg::FlowNew(wire));
                }
                action
            }
            None => {
                let req_id = next_req_id.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = mpsc::channel();
                pending_registry.lock().unwrap().insert(req_id, tx);
                let wire = FlowWire {
                    req_id: Some(req_id),
                    exe: exe.clone(),
                    direction: dir,
                    proto: proto_name(pkt.proto).to_string(),
                    port: Some(rule_port),
                    peer_ip: peer_ip.clone(),
                    peer_name: peer_name.clone(),
                    status: FlowStatus::Pending,
                    ts: now_ts(),
                };
                push_history(&history, wire.clone());
                let _ = event_tx.send(ServerMsg::FlowNew(wire));

                let decision = rx.recv_timeout(timeout);

                pending_registry.lock().unwrap().remove(&req_id);

                let verdict = match decision {
                    Ok(verdict) => {
                        // every answer is remembered as a per-port rule — unless
                        // a rule set meanwhile (e.g. the Apps pane's whole-app
                        // y/n, which cascades a Decide to us) already gives this
                        // exact verdict, in which case adding a redundant
                        // per-port override would just clutter the app's rules
                        if ruled(&app_rules.lock().unwrap(), &exe, rule_port, dir) != Some(verdict)
                        {
                            let rules =
                                upsert_rule(&exe, Some(rule_port), Some(dir), verdict, None);
                            *app_rules.lock().unwrap() = rules.clone();
                            let _ = event_tx.send(ServerMsg::AppRules(rules));
                        }
                        verdict
                    }
                    Err(_) => default_verdict,
                };
                let status = FlowStatus::from(verdict);
                if let Some(resolved) = resolve_history(&history, req_id, status) {
                    append_history_line(&resolved);
                }
                let _ = event_tx.send(ServerMsg::FlowResolved { req_id, status });
                verdict
            }
        };

        msg.set_verdict(to_verdict(verdict));
        queue.verdict(msg)?;
    }
}

/// pops a `notify-send` in every logged-in desktop session. The daemon is
/// root and has no session of its own, so for each /run/user/<uid>/bus it
/// runs notify-send *as that user* against that bus — the same thing
/// `sudo -u user DBUS_SESSION_BUS_ADDRESS=... notify-send` does by hand.
/// Fire-and-forget: no desktop, no notify-send, no bus = nothing happens.
fn notify_desktop(w: &FlowWire) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    let Ok(users) = fs::read_dir("/run/user") else {
        return;
    };
    let app = w.exe.rsplit('/').next().unwrap_or(&w.exe);
    let title = format!("{app} wants to connect ({})", w.direction.as_str());
    let body = format!(
        "{}\n{} port {} — {}\nsudo guardit answer {} allow|deny",
        w.exe,
        w.proto,
        w.port.unwrap_or(0),
        w.peer(),
        w.req_id.unwrap_or(0)
    );
    for u in users.flatten() {
        let Some(uid) = u.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let bus = u.path().join("bus");
        let Ok(meta) = u.metadata() else { continue };
        if !bus.exists() {
            continue;
        }
        let child = Command::new("notify-send")
            .uid(uid)
            .gid(meta.gid())
            .env_clear()
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", bus.display()),
            )
            .env("XDG_RUNTIME_DIR", u.path())
            .args([
                "-a", "guardit", "-u", "critical", "-t", "20000", &title, &body,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            // reap it off-thread so it neither blocks the fanout nor zombies
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

fn broadcast(subscribers: &Subscribers, msg: ServerMsg) {
    subscribers
        .lock()
        .unwrap()
        .retain(|tx| tx.send(msg.clone()).is_ok());
}

fn ipc_thread(
    app_rules: AppRules,
    history: History,
    listening: ListeningState,
    pending_registry: PendingRegistry,
    event_rx: Receiver<ServerMsg>,
    notify: bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // root only: anyone who can connect can allow any app's traffic. The
    // socket is created 0777 & ~umask, so clamp it (and the directory)
    // explicitly rather than trusting whatever umask we were started with.
    if let Some(dir) = ipc::socket_path().parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let _ = fs::remove_file(ipc::socket_path()); // stale socket from a previous crashed run
    let listener = UnixListener::bind(ipc::socket_path())?;
    fs::set_permissions(ipc::socket_path(), fs::Permissions::from_mode(0o600))?;
    eprintln!(
        "guardit daemon: listening on {}",
        ipc::socket_path().display()
    );

    let subscribers: Subscribers = Arc::new(Mutex::new(Vec::new()));

    // fans every daemon event out to whichever clients are currently connected
    let fanout_subscribers = subscribers.clone();
    std::thread::spawn(move || {
        for msg in event_rx {
            if notify
                && let ServerMsg::FlowNew(w) = &msg
                && w.status == FlowStatus::Pending
            {
                notify_desktop(w);
            }
            broadcast(&fanout_subscribers, msg);
        }
    });

    for stream in listener.incoming().flatten() {
        let app_rules = app_rules.clone();
        let history = history.clone();
        let listening = listening.clone();
        let pending_registry = pending_registry.clone();
        let subscribers = subscribers.clone();
        std::thread::spawn(move || {
            eprintln!("guardit daemon: tui client connected");
            handle_client(
                stream,
                &app_rules,
                &history,
                &listening,
                &pending_registry,
                &subscribers,
            );
            eprintln!("guardit daemon: tui client disconnected");
        });
    }
    Ok(())
}

/// one thread per connected client. Reads with a short timeout so the same
/// loop can also drain this client's private ServerMsg channel (fed by
/// `broadcast`) without needing yet another thread per connection.
fn handle_client(
    stream: UnixStream,
    app_rules: &AppRules,
    history: &History,
    listening: &ListeningState,
    pending_registry: &PendingRegistry,
    subscribers: &Subscribers,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    let snapshot = ServerMsg::Snapshot {
        app_rules: app_rules.lock().unwrap().clone(),
        flow: history.lock().unwrap().clone(),
        listening: listening.lock().unwrap().clone(),
    };
    if ipc::send_msg(&mut writer, &snapshot).is_err() {
        return;
    }

    let (tx, rx) = mpsc::channel::<ServerMsg>();
    subscribers.lock().unwrap().push(tx);
    // `rx` drops when this fn returns, which makes future broadcast() sends to
    // our `tx` fail — that's how we get lazily unsubscribed, no explicit cleanup

    loop {
        match ipc::read_msg::<ClientMsg>(&mut reader) {
            Ok(Some(msg)) => {
                if let Some(rules) = handle_client_msg(msg, app_rules, pending_registry) {
                    // broadcast, not a direct reply — every connected client
                    // (this one included, via its own rx below) should see
                    // a rule change made by any of them
                    broadcast(subscribers, ServerMsg::AppRules(rules));
                }
            }
            Ok(None) => return, // client disconnected
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }

        while let Ok(msg) = rx.try_recv() {
            if ipc::send_msg(&mut writer, &msg).is_err() {
                return;
            }
        }
    }
}

/// returns the new app_rule list when it changed, so the caller can echo it
/// straight back to the client that asked for the change
fn handle_client_msg(
    msg: ClientMsg,
    app_rules: &AppRules,
    pending_registry: &PendingRegistry,
) -> Option<Vec<AppRule>> {
    match msg {
        ClientMsg::Decide { req_id, verdict } => {
            if let Some(tx) = pending_registry.lock().unwrap().get(&req_id) {
                let _ = tx.send(verdict);
            }
            None
        }
        ClientMsg::ToggleAppRule { id } => {
            let fresh = Config::update(|cfg| {
                if let Some(r) = cfg.app_rule.iter_mut().find(|r| r.id == id) {
                    r.enabled = !r.enabled;
                }
            });
            *app_rules.lock().unwrap() = fresh.app_rule.clone();
            Some(fresh.app_rule)
        }
        ClientMsg::Reload => {
            let fresh = Config::load();
            *app_rules.lock().unwrap() = fresh.app_rule.clone();
            Some(fresh.app_rule)
        }
        ClientMsg::RmAppRule { exe } => {
            let fresh = Config::update(|cfg| cfg.app_rule.retain(|r| r.exe != exe));
            *app_rules.lock().unwrap() = fresh.app_rule.clone();
            Some(fresh.app_rule)
        }
        ClientMsg::SetAppRule {
            exe,
            port,
            direction,
            action,
            expires,
        } => {
            let rules = upsert_rule(&exe, port, direction, action, expires);
            *app_rules.lock().unwrap() = rules.clone();
            Some(rules)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the one check that fails if inode_pid_map stops agreeing with the
    /// per-inode scan it replaced: bind a real socket, then look it up both ways
    #[test]
    fn inode_map_finds_our_own_listening_socket() {
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let inode = find_inode(6, port).expect("our listener is in /proc/net/tcp");
        assert_eq!(
            inode_pid_map().get(&inode).copied(),
            find_pid_by_inode(inode),
            "map disagrees with the sequential scan"
        );
        assert_eq!(
            inode_pid_map().get(&inode).copied(),
            Some(std::process::id())
        );
    }

    #[test]
    fn sandbox_identities() {
        let info = "[Application]\nname=org.mozilla.firefox\nruntime=org.freedesktop.Platform/x86_64/23.08\n\n[Instance]\nname=ignored\n";
        assert_eq!(flatpak_id(info), Some("org.mozilla.firefox"));
        assert_eq!(flatpak_id("[Instance]\nname=x\n"), None);
        let cg = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.code-insiders.code-insiders-9f8a1c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b.scope\n";
        assert_eq!(snap_id(cg), Some("code-insiders.code-insiders"));
        assert_eq!(snap_id("0::/user.slice/app-ghostty-26675.scope\n"), None);
    }

    #[test]
    fn parses_dns_response_with_cname_and_pointers() {
        // response, 1 question "example.com" A, 3 answers:
        // CNAME (skipped), A 93.184.216.34, AAAA 2606:2800:220:1:248:1893:25c8:1946
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        m.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend([
            0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'w', b'w', b'w', 0xC0, 0x0C,
        ]);
        m.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        m.extend([0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        m.extend(
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let (name, ips) = parse_dns_answers(&m).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            ]
        );
        m[2] = 0x01; // QR clear = a query, not a response
        assert!(parse_dns_answers(&m).is_none());
        let looped = [0xC0, 0x00, 0, 0];
        assert!(
            dns_read_name(&looped, 0).is_none(),
            "pointer loop must not hang"
        );
    }

    #[test]
    fn parses_ipv4_tcp_header() {
        // version 4, IHL 5 (20 bytes), proto 6 (tcp), then a 20-byte tcp header
        // with src port 51234 (0xC822) and dst port 443 (0x01BB)
        let mut payload = vec![
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(&[0xC8, 0x22, 0x01, 0xBB]);
        payload.extend_from_slice(&[0; 16]);
        let info = parse_packet(&payload).unwrap();
        assert_eq!(info.proto, 6);
        assert_eq!(info.src_port, 51234);
        assert_eq!(info.dst_port, 443);
        assert_eq!(info.src_ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn parses_ipv6_udp_header() {
        // version 6, next-header 17 (udp) at byte 6, 16-byte src/dst addrs,
        // then a udp header with src port 53 and dst port 40000 (0x9C40)
        let mut payload = vec![0u8; 40];
        payload[0] = 0x60;
        payload[6] = 17;
        payload[8] = 0xfe; // src addr starts fe80::1
        payload[23] = 1;
        payload.extend_from_slice(&[0x00, 0x35, 0x9C, 0x40]);
        let info = parse_packet(&payload).unwrap();
        assert_eq!(info.proto, 17);
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 40000);
        assert!(matches!(info.src_ip, IpAddr::V6(_)));
    }

    #[test]
    fn rejects_short_or_unknown_packet() {
        assert!(parse_packet(&[0x60, 0, 0, 0, 0, 0, 6, 64]).is_none()); // v6, too short
        assert!(parse_packet(&[0x50, 0, 0, 0, 0, 0, 0, 0, 0]).is_none()); // unknown version nibble
    }

    #[test]
    fn parses_hex_ipv4_from_proc_net_tcp() {
        // "0100007F" is the classic /proc/net/tcp encoding for 127.0.0.1
        assert_eq!(
            parse_hex_ipv4("0100007F").unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(
            parse_hex_ipv4("00000000").unwrap(),
            Ipv4Addr::new(0, 0, 0, 0)
        );
        assert!(parse_hex_ipv4("bad").is_none());
    }

    #[test]
    fn parses_hex_ipv6_loopback() {
        // ::1 encoded the /proc/net/tcp6 way: 4 words, each individually
        // byte-reversed — the last word "01000000" reverses to 00 00 00 01
        let hex = "00000000".repeat(3) + "01000000";
        assert_eq!(hex.len(), 32);
        assert_eq!(parse_hex_ipv6(&hex).unwrap(), Ipv6Addr::LOCALHOST);
    }

    fn listen(proto: &str, addr: &str, port: u16, exe: &str) -> ipc::ListenEntry {
        ipc::ListenEntry {
            proto: proto.into(),
            addr: addr.into(),
            port,
            exe: exe.into(),
        }
    }

    #[test]
    fn flags_two_different_apps_on_the_same_wildcard_port() {
        let entries = vec![
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/a"),
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/b"),
        ];
        assert_eq!(find_conflicts(&entries).len(), 1);
    }

    #[test]
    fn wildcard_overlaps_a_specific_address() {
        let entries = vec![
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/a"),
            listen("tcp", "127.0.0.1", 8080, "/usr/bin/b"),
        ];
        assert_eq!(find_conflicts(&entries).len(), 1);
    }

    #[test]
    fn distinct_specific_addresses_do_not_conflict() {
        let entries = vec![
            listen("tcp", "127.0.0.1", 8080, "/usr/bin/a"),
            listen("tcp", "192.168.1.50", 8080, "/usr/bin/b"),
        ];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn same_exe_on_same_port_is_not_a_conflict() {
        // SO_REUSEPORT-style worker sharing — same app, not a collision
        let entries = vec![
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/a"),
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/a"),
        ];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn different_protocols_on_the_same_port_do_not_conflict() {
        let entries = vec![
            listen("tcp", "0.0.0.0", 8080, "/usr/bin/a"),
            listen("udp", "0.0.0.0", 8080, "/usr/bin/b"),
        ];
        assert!(find_conflicts(&entries).is_empty());
    }

    #[test]
    fn parses_proc_net_tcp_rows_and_skips_header_and_dead_sockets() {
        // format straight from /proc/net/tcp: sl local_address rem_address st ... inode ...
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0\n\
            2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0\n";
        let rows: Vec<_> = proc_net_rows(text).collect();
        assert_eq!(rows.len(), 1, "header and inode-0 rows dropped");
        assert_eq!(
            (rows[0].ip_hex, rows[0].port, rows[0].state, rows[0].inode),
            ("0100007F", 8080, "0A", 123456)
        );
    }
}
