use crate::ruleset::{LOG_PREFIX_IN, LOG_PREFIX_OUT};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub dir: Dir,
    pub src: String,
    pub proto: String,
    pub dport: Option<u16>,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
}

fn parse_line(line: &str) -> Option<LogEntry> {
    let (dir, rest) = if let Some(r) = line.split(LOG_PREFIX_IN).nth(1) {
        (Dir::In, r)
    } else if let Some(r) = line.split(LOG_PREFIX_OUT).nth(1) {
        (Dir::Out, r)
    } else {
        return None;
    };
    // for outbound traffic the "requester" is the remote peer, i.e. DST
    let addr_key = match dir {
        Dir::In => "SRC=",
        Dir::Out => "DST=",
    };
    let src = field(rest, addr_key)?.to_string();
    let proto = field(rest, "PROTO=").unwrap_or("?").to_string();
    let dport = field(rest, "DPT=").and_then(|s| s.parse().ok());
    Some(LogEntry { dir, src, proto, dport })
}

/// Most recent connection attempts guardit logged (newest last), deduped.
/// Reads via `dmesg` — no journald dependency, works under any init.
pub fn recent(limit: usize) -> Result<Vec<LogEntry>, String> {
    let out = Command::new("dmesg")
        .output()
        .map_err(|e| format!("dmesg failed: {e} (need root to read kernel log?)"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut entries: Vec<LogEntry> = text
        .lines()
        .filter_map(parse_line)
        .collect();
    entries.dedup();
    let start = entries.len().saturating_sub(limit);
    Ok(entries.split_off(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_incoming_attempt() {
        let line = "[12345.6789] guardit-in: IN=eth0 OUT= MAC=aa:bb SRC=192.168.1.42 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=51234 DPT=22 SYN URGP=0";
        let e = parse_line(line).unwrap();
        assert_eq!(e.dir, Dir::In);
        assert_eq!(e.src, "192.168.1.42");
        assert_eq!(e.proto, "TCP");
        assert_eq!(e.dport, Some(22));
    }

    #[test]
    fn parses_outgoing_attempt_uses_dst_as_peer() {
        let line = "[12345.6789] guardit-out: IN= OUT=eth0 SRC=10.0.0.1 DST=1.2.3.4 LEN=60 PROTO=TCP SPT=51234 DPT=443 SYN URGP=0";
        let e = parse_line(line).unwrap();
        assert_eq!(e.dir, Dir::Out);
        assert_eq!(e.src, "1.2.3.4");
        assert_eq!(e.dport, Some(443));
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(parse_line("[1.0] some other kernel message SRC=1.2.3.4").is_none());
    }
}
