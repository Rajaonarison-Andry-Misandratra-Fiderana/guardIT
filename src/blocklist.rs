//! Ads / tracking blocking: curated domain blocklists, downloaded to disk and
//! matched against every DNS lookup the daemon already sees.
//!
//! The enforcement point is the DNS reply, not the connection: `daemon::
//! dns_loop` is already on the wire for every plain-DNS answer (that's what
//! puts `github.com` next to an ip in the dashboard), so rewriting a blocked
//! name's reply to NXDOMAIN costs one lookup per answer and no new hook. The
//! app never learns an address, so it never opens the connection — which is
//! the same end state as a sinkhole, one round trip later.
//!
//! Everything here is name-based, so it inherits the DNS tap's blind spot:
//! a resolver the daemon can't read (DoH, DoT, an app's own cache) can't be
//! filtered. That is what `block_encrypted_dns` exists to close — see
//! `ruleset::render` and `DOH_BOOTSTRAP`.

use crate::config::BlocklistConfig;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// One downloadable list. `id` is the maintainer, `level` the flavour —
/// together they form the `id:level` key used in the config and the CLI —
/// and `category` is the kind of thing it blocks, which is what the TUI and
/// `guardit blocklist block` actually work in.
pub struct Source {
    pub id: &'static str,
    pub level: &'static str,
    pub category: &'static str,
    pub url: &'static str,
    pub about: &'static str,
}

impl Source {
    pub fn key(&self) -> String {
        format!("{}:{}", self.id, self.level)
    }
}

/// A kind of thing to block, and the lists turning it on enables.
///
/// One or two well-chosen lists per category, not every list that touches
/// the subject: the catalogue overlaps heavily, and merging five lists that
/// cover the same domains costs the memory five times for the coverage
/// once. `guardit blocklist enable <list>` adds any other list on top.
pub struct Category {
    pub key: &'static str,
    pub about: &'static str,
    pub sources: &'static [&'static str],
}

/// The catalogue the TUI and `guardit blocklist sources` show.
///
/// Every hagezi entry is a `wildcard/*-onlydomains.txt`: a plain domain per
/// line, meaning "this name and everything under it" — exactly the matching
/// `Blocklist::blocked` does, so no format-specific handling is needed. The
/// hosts-format lists are exact-name lists; the same suffix walk still
/// matches them, it just never fires above a listed name because their
/// subdomains are listed individually.
pub const SOURCES: &[Source] = &[
    Source {
        id: "hagezi",
        level: "light",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        about: "ads + trackers, size-optimised, near-zero breakage",
    },
    Source {
        id: "hagezi",
        level: "normal",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        about: "ads, trackers, telemetry, some badware",
    },
    Source {
        id: "hagezi",
        level: "pro",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        about: "ads, trackers, telemetry, badware — the recommended default",
    },
    Source {
        id: "hagezi",
        level: "pro.plus",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
        about: "pro, plus aggressive tracking and telemetry",
    },
    Source {
        id: "hagezi",
        level: "ultimate",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
        about: "maximum coverage — expect to need the allowlist",
    },
    Source {
        id: "hagezi",
        level: "popupads",
        category: "ads",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
        about: "pop-up ads and redirect chains",
    },
    Source {
        id: "oisd",
        level: "small",
        category: "ads",
        url: "https://small.oisd.nl/domainswild2",
        about: "ads + trackers, tuned hard against false positives",
    },
    Source {
        id: "oisd",
        level: "big",
        category: "ads",
        url: "https://big.oisd.nl/domainswild2",
        about: "ads, trackers, malware, phishing, scam",
    },
    Source {
        id: "stevenblack",
        level: "unified",
        category: "ads",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        about: "the classic unified hosts list: ads + malware",
    },
    Source {
        id: "adguard",
        level: "dns",
        category: "ads",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        about: "AdGuard's own DNS filter: ads + trackers",
    },
    Source {
        id: "peterlowe",
        level: "ads",
        category: "ads",
        url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        about: "Peter Lowe's ad and tracking server list",
    },
    Source {
        id: "adaway",
        level: "hosts",
        category: "ads",
        url: "https://adaway.org/hosts.txt",
        about: "AdAway: mobile ad servers",
    },
    Source {
        id: "someonewhocares",
        level: "hosts",
        category: "ads",
        url: "https://someonewhocares.org/hosts/zero/hosts",
        about: "Dan Pollock's hosts file",
    },
    Source {
        id: "blocklistproject",
        level: "ads",
        category: "ads",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
        about: "The Blocklist Project: ad servers",
    },
    Source {
        id: "frogeye",
        level: "multiparty",
        category: "tracking",
        url: "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt",
        about: "third-party trackers, resolved from the filter lists",
    },
    Source {
        id: "frogeye",
        level: "firstparty",
        category: "tracking",
        url: "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
        about: "CNAME-cloaked first-party trackers — no other list has these",
    },
    Source {
        id: "blocklistproject",
        level: "tracking",
        category: "tracking",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
        about: "The Blocklist Project: trackers",
    },
    Source {
        id: "hagezi",
        level: "tif",
        category: "phishing",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        about: "threat intelligence: malware, phishing, scam, cryptojacking",
    },
    Source {
        id: "hagezi",
        level: "tif.medium",
        category: "phishing",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
        about: "threat intelligence, medium — fewer false positives",
    },
    Source {
        id: "hagezi",
        level: "tif.mini",
        category: "phishing",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        about: "threat intelligence, minimal",
    },
    Source {
        id: "phishingarmy",
        level: "extended",
        category: "phishing",
        url: "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        about: "Phishing Army: active phishing domains",
    },
    Source {
        id: "urlhaus",
        level: "hosts",
        category: "phishing",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        about: "abuse.ch URLhaus: hosts distributing malware",
    },
    Source {
        id: "blocklistproject",
        level: "malware",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
        about: "The Blocklist Project: malware",
    },
    Source {
        id: "blocklistproject",
        level: "phishing",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
        about: "The Blocklist Project: phishing",
    },
    Source {
        id: "blocklistproject",
        level: "ransomware",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
        about: "The Blocklist Project: ransomware",
    },
    Source {
        id: "blocklistproject",
        level: "scam",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
        about: "The Blocklist Project: scams",
    },
    Source {
        id: "blocklistproject",
        level: "fraud",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
        about: "The Blocklist Project: fraud",
    },
    Source {
        id: "blocklistproject",
        level: "abuse",
        category: "phishing",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
        about: "The Blocklist Project: abuse and reported hosts",
    },
    Source {
        id: "hagezi",
        level: "fake",
        category: "fake",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
        about: "fake shops, fake streaming, fake support",
    },
    Source {
        id: "blocklistproject",
        level: "redirect",
        category: "fake",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/redirect.txt",
        about: "The Blocklist Project: redirect and doorway pages",
    },
    Source {
        id: "blocklistproject",
        level: "crypto",
        category: "crypto",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
        about: "cryptojacking and mining pools",
    },
    Source {
        id: "hagezi",
        level: "doh",
        category: "dns-bypass",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        about: "DoH / VPN / proxy endpoints used to bypass DNS filtering",
    },
    Source {
        id: "hagezi",
        level: "dyndns",
        category: "dns-bypass",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
        about: "dynamic DNS providers, commonly used to evade filtering",
    },
    Source {
        id: "hagezi",
        level: "nosafesearch",
        category: "dns-bypass",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nosafesearch-onlydomains.txt",
        about: "endpoints that let a browser skip enforced safe search",
    },
    Source {
        id: "hagezi",
        level: "native.winoffice",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.winoffice-onlydomains.txt",
        about: "Windows / Office telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.apple",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple-onlydomains.txt",
        about: "Apple device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.amazon",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.amazon-onlydomains.txt",
        about: "Amazon device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.samsung",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt",
        about: "Samsung device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.xiaomi",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.xiaomi-onlydomains.txt",
        about: "Xiaomi device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.huawei",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.huawei-onlydomains.txt",
        about: "Huawei device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.tiktok",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.tiktok-onlydomains.txt",
        about: "TikTok's own telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.lgwebos",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.lgwebos-onlydomains.txt",
        about: "LG webOS TV telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.roku",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.roku-onlydomains.txt",
        about: "Roku telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.vivo",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.vivo-onlydomains.txt",
        about: "Vivo device telemetry endpoints",
    },
    Source {
        id: "hagezi",
        level: "native.oppo-realme",
        category: "telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.oppo-realme-onlydomains.txt",
        about: "Oppo / Realme device telemetry endpoints",
    },
    Source {
        id: "sinfonietta",
        level: "social",
        category: "social",
        url: "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts",
        about: "social networks",
    },
    Source {
        id: "blocklistproject",
        level: "facebook",
        category: "social",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt",
        about: "Facebook and Meta properties",
    },
    Source {
        id: "blocklistproject",
        level: "tiktok",
        category: "social",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt",
        about: "TikTok",
    },
    Source {
        id: "blocklistproject",
        level: "youtube",
        category: "social",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/youtube.txt",
        about: "YouTube",
    },
    Source {
        id: "hagezi",
        level: "gambling",
        category: "gambling",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
        about: "gambling and betting",
    },
    Source {
        id: "hagezi",
        level: "gambling.medium",
        category: "gambling",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.medium-onlydomains.txt",
        about: "gambling and betting, medium",
    },
    Source {
        id: "blocklistproject",
        level: "gambling",
        category: "gambling",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
        about: "The Blocklist Project: gambling",
    },
    Source {
        id: "hagezi",
        level: "nsfw",
        category: "porn",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
        about: "pornography",
    },
    Source {
        id: "oisd",
        level: "nsfw",
        category: "porn",
        url: "https://nsfw.oisd.nl/domainswild2",
        about: "pornography, oisd's list",
    },
    Source {
        id: "sinfonietta",
        level: "porn",
        category: "porn",
        url: "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
        about: "pornography, Sinfonietta's list",
    },
    Source {
        id: "blocklistproject",
        level: "porn",
        category: "porn",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
        about: "The Blocklist Project: pornography",
    },
    Source {
        id: "hagezi",
        level: "anti.piracy",
        category: "piracy",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti.piracy-onlydomains.txt",
        about: "piracy and warez sites",
    },
    Source {
        id: "blocklistproject",
        level: "piracy",
        category: "piracy",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
        about: "The Blocklist Project: piracy",
    },
    Source {
        id: "blocklistproject",
        level: "torrent",
        category: "piracy",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/torrent.txt",
        about: "The Blocklist Project: torrent trackers and indexes",
    },
    Source {
        id: "blocklistproject",
        level: "drugs",
        category: "drugs",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
        about: "drug marketplaces",
    },
    Source {
        id: "blocklistproject",
        level: "vaping",
        category: "drugs",
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/vaping.txt",
        about: "vaping and e-cigarette shops",
    },
];

pub const CATEGORIES: &[Category] = &[
    Category {
        key: "ads",
        about: "advertising",
        sources: &["hagezi:pro"],
    },
    Category {
        key: "tracking",
        about: "trackers and analytics",
        sources: &["frogeye:multiparty", "frogeye:firstparty"],
    },
    Category {
        key: "phishing",
        about: "malware, phishing, scam, ransomware",
        sources: &["hagezi:tif"],
    },
    Category {
        key: "fake",
        about: "fake shops, fake streaming, fake support",
        sources: &["hagezi:fake"],
    },
    Category {
        key: "crypto",
        about: "cryptojacking and mining",
        sources: &["blocklistproject:crypto"],
    },
    Category {
        key: "dns-bypass",
        about: "DoH, VPN and proxy endpoints that route around filtering",
        sources: &["hagezi:doh"],
    },
    Category {
        key: "telemetry",
        about: "device and OS telemetry",
        sources: &["hagezi:native.winoffice", "hagezi:native.apple", "hagezi:native.samsung", "hagezi:native.xiaomi", "hagezi:native.amazon", "hagezi:native.tiktok"],
    },
    Category {
        key: "social",
        about: "social networks",
        sources: &["sinfonietta:social"],
    },
    Category {
        key: "gambling",
        about: "gambling and betting",
        sources: &["hagezi:gambling"],
    },
    Category {
        key: "porn",
        about: "pornography",
        sources: &["hagezi:nsfw"],
    },
    Category {
        key: "piracy",
        about: "piracy and torrents",
        sources: &["hagezi:anti.piracy"],
    },
    Category {
        key: "drugs",
        about: "drug and vaping shops",
        sources: &["blocklistproject:drugs"],
    },
];

/// Ads and phishing are on by default when blocking is turned on: the first
/// is what anyone installing this came for, and the second costs one list
/// and blocks the things that actually hurt.
pub const DEFAULT_CATEGORIES: &[&str] = &["ads", "phishing"];

pub fn category(key: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| c.key == key)
}

/// Every list actually in force: the lists of each enabled category, plus
/// any the user added by key. Deduplicated, since categories overlap.
pub fn effective_sources(cfg: &BlocklistConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |key: &str| {
        if !out.iter().any(|k| k == key) {
            out.push(key.to_string());
        }
    };
    for name in &cfg.categories {
        if let Some(cat) = category(name) {
            for key in cat.sources {
                push(key);
            }
        }
    }
    for key in &cfg.sources {
        push(key);
    }
    out
}

/// Names that make encrypted DNS give up and fall back to the plain DNS this
/// can actually filter. `use-application-dns.net` is Mozilla's canary: an
/// NXDOMAIN on it is the documented signal for Firefox to disable its own
/// DoH. The rest are the bootstrap names the major DoH clients resolve
/// before they can talk DoH at all — deny those and the client never gets
/// off the ground. `hagezi:doh` covers far more; this is the floor that
/// applies with no list downloaded yet.
pub const DOH_BOOTSTRAP: &[&str] = &[
    "use-application-dns.net",
    "mozilla.cloudflare-dns.com",
    "cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns.nextdns.io",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.cloudflare.com",
    "doh.dns.sb",
    "dns.controld.com",
    "doh.mullvad.net",
    "dns.alidns.com",
    "doh.pub",
    "dns.twnic.tw",
    "odvr.nic.cz",
];

/// The maintained list of ip addresses that answer DoH, used to build the
/// nft set that closes the "hardcoded resolver ip" bypass — the one case
/// name blocking cannot reach, because no lookup ever happens.
pub const DOH_IPS_URL: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt";
/// key under which the ip list is cached, kept out of SOURCES because it is
/// addresses rather than names and is driven by `block_encrypted_dns`
pub const DOH_IPS_KEY: &str = "doh-ips";

pub fn source(key: &str) -> Option<&'static Source> {
    SOURCES.iter().find(|s| s.key() == key)
}

/// downloaded lists are data, not configuration — they are refetched, never
/// hand-edited, and are far too big to sit in /etc next to rules.toml.
/// `GUARDIT_BLOCKLIST_DIR` moves them, which is the only way to exercise
/// downloading and matching without being root.
pub fn cache_dir() -> PathBuf {
    match std::env::var_os("GUARDIT_BLOCKLIST_DIR") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from("/var/lib/guardit/blocklists"),
    }
}

pub fn cache_path(key: &str) -> PathBuf {
    cache_dir().join(format!("{}.txt", key.replace([':', '/'], "_")))
}

/// unix mtime of a cached list, for "last updated" and for deciding whether
/// an auto-update is due
pub fn cached_at(key: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(cache_path(key)).ok().map(|m| m.mtime() as u64)
}

/// One line of any of the formats in SOURCES, reduced to the domain it
/// blocks — or None for everything that isn't one.
///
/// Accepts hosts lines (`0.0.0.0 ads.example`), bare domains, and the
/// AdBlock-style `||ads.example^` that AdGuard's DNS filter uses. Lines that
/// carry element-hiding or regex syntax are dropped rather than guessed at:
/// this is a domain matcher, and half-understanding a cosmetic rule would
/// block a name nobody asked to block.
pub fn parse_line(line: &str) -> Option<&str> {
    // AdBlock cosmetic/scriptlet rules (`example.com##.ad`, `#@#`, `#?#`,
    // `#$#`) start with a domain, so they have to be rejected before `#` is
    // treated as a comment — otherwise every one of them silently becomes a
    // rule blocking the site it was meant to only hide an element on
    if ["##", "#@#", "#?#", "#$#", "#%#"].iter().any(|m| line.contains(m)) {
        return None;
    }
    let line = line.split('#').next()?.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('/') {
        return None;
    }
    let candidate = if let Some(rest) = line.strip_prefix("||") {
        // ||ads.example^ / ||ads.example^$third-party — only a plain domain
        // anchor is a domain rule; anything with options or a path is not
        let rest = rest.split('^').next()?;
        if rest.contains('/') || rest.contains('*') {
            return None;
        }
        rest
    } else {
        // hosts format is "<ip> <name>"; a bare domain has no whitespace
        let mut fields = line.split_whitespace();
        let first = fields.next()?;
        match fields.next() {
            Some(name) => name,
            None => first,
        }
    };
    let candidate = candidate.trim_end_matches('.');
    // hosts files are full of loopback housekeeping and of the ip column
    // itself when a line had only one field
    if candidate.is_empty()
        || !candidate.contains('.')
        || candidate.parse::<std::net::IpAddr>().is_ok()
        || matches!(
            candidate,
            "localhost" | "localhost.localdomain" | "local" | "broadcasthost" | "ip6-localhost"
        )
        || !candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(candidate)
}

pub fn parse_into(text: &str, into: &mut HashSet<Box<str>>) -> usize {
    let before = into.len();
    for line in text.lines() {
        if let Some(d) = parse_line(line) {
            into.insert(d.to_ascii_lowercase().into_boxed_str());
        }
    }
    into.len() - before
}

/// Every enabled list, merged, plus the user's allowlist.
///
/// One flat set for all sources: which list a name came from is not worth
/// the memory of keeping them apart on the hot path, and `check` re-reads
/// the files when someone actually asks that question.
///
/// ponytail: every domain is an owned Box<str>, so the whole catalogue on at
/// once is a couple of hundred MB resident — fine for one or two categories,
/// which is the case. A shared arena, or a probabilistic filter in front of
/// the set, if anyone ever runs all twelve.
#[derive(Default)]
pub struct Blocklist {
    blocked: HashSet<Box<str>>,
    allow: HashSet<Box<str>>,
}

impl Blocklist {
    /// reads whatever is already downloaded; a listed-but-missing source is
    /// simply absent (the daemon must start and filter with the lists it
    /// has, not refuse to run because one was never fetched)
    pub fn load(cfg: &BlocklistConfig) -> Blocklist {
        let mut blocked = HashSet::new();
        if cfg.enabled {
            for key in effective_sources(cfg) {
                if let Ok(text) = fs::read_to_string(cache_path(&key)) {
                    parse_into(&text, &mut blocked);
                }
            }
            if cfg.block_encrypted_dns {
                for name in DOH_BOOTSTRAP {
                    blocked.insert((*name).into());
                }
            }
        }
        Blocklist {
            blocked,
            allow: cfg
                .allow
                .iter()
                .map(|d| d.trim_end_matches('.').to_ascii_lowercase().into_boxed_str())
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// Walks the name from most to least specific — `ads.a.example.com`,
    /// `a.example.com`, `example.com`, `com` — and takes the first verdict
    /// found. Allow is checked before block at each level, so an allowlist
    /// entry beats a blocklist entry on the same name *and* rescues a
    /// subdomain of a blocked parent, which is the whole point of having one.
    /// At most one hash lookup per label, so cost is the depth of the name,
    /// not the size of the list.
    pub fn blocked(&self, name: &str) -> bool {
        if self.blocked.is_empty() {
            return false;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = name.as_str();
        loop {
            if self.allow.contains(rest) {
                return false;
            }
            if self.blocked.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, tail)) if tail.contains('.') => rest = tail,
                _ => return false,
            }
        }
    }
}

/// Downloads `url` to the cache under `key`, atomically.
///
/// Shelling out to curl rather than linking an HTTP stack: guardit ships as
/// a static musl binary and curl is already a hard requirement of the
/// installer, so an async runtime plus a TLS stack would be ~150 crates
/// bought for one GET a day.
/// ponytail: curl/wget subprocess, only worth replacing if guardit ever
/// needs to fetch something on a path where a subprocess is too expensive
pub fn fetch(key: &str, url: &str) -> Result<usize, String> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.part", key.replace([':', '/'], "_")));

    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--compressed",
            "--max-time",
            "120",
            "--retry",
            "2",
            "-o",
        ])
        .arg(&tmp)
        .arg(url)
        .output()
        .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
    if !out.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // a list that parses to nothing is a server error page or a moved URL,
    // not an empty blocklist — refuse it rather than silently replacing a
    // working list with zero domains
    let text = fs::read_to_string(&tmp).map_err(|e| format!("read download: {e}"))?;
    let mut parsed = HashSet::new();
    let n = parse_into(&text, &mut parsed);
    if n == 0 {
        let _ = fs::remove_file(&tmp);
        return Err("downloaded file contains no domains — wrong url?".into());
    }
    fs::rename(&tmp, cache_path(key)).map_err(|e| format!("install list: {e}"))?;
    Ok(n)
}

/// the same, for the DoH ip list — which is addresses, so the domain parser
/// would (correctly) reject every line of it
pub fn fetch_doh_ips() -> Result<usize, String> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = dir.join(".doh-ips.part");
    let out = Command::new("curl")
        .args(["-fsSL", "--compressed", "--max-time", "120", "-o"])
        .arg(&tmp)
        .arg(DOH_IPS_URL)
        .output()
        .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
    if !out.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = fs::read_to_string(&tmp).map_err(|e| format!("read download: {e}"))?;
    let n = parse_ips(&text).len();
    if n == 0 {
        let _ = fs::remove_file(&tmp);
        return Err("downloaded file contains no ip addresses — wrong url?".into());
    }
    fs::rename(&tmp, cache_path(DOH_IPS_KEY)).map_err(|e| format!("install list: {e}"))?;
    Ok(n)
}

pub fn parse_ips(text: &str) -> Vec<std::net::IpAddr> {
    text.lines()
        .filter_map(|l| l.split('#').next())
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// the cached DoH addresses, for `ruleset::render` to turn into an nft set
pub fn doh_ips() -> Vec<std::net::IpAddr> {
    fs::read_to_string(cache_path(DOH_IPS_KEY))
        .map(|t| parse_ips(&t))
        .unwrap_or_default()
}

/// Refetches every enabled list (and the DoH addresses when that is on),
/// returning one result per key so a single dead url is reported instead of
/// failing the whole update.
pub fn update_all(cfg: &BlocklistConfig) -> Vec<(String, Result<usize, String>)> {
    let mut out = Vec::new();
    for key in effective_sources(cfg) {
        let r = match source(&key) {
            Some(s) => fetch(&key, s.url),
            None => Err("unknown list — see `guardit blocklist sources`".into()),
        };
        out.push((key, r));
    }
    if cfg.block_encrypted_dns {
        out.push((DOH_IPS_KEY.to_string(), fetch_doh_ips()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(blocked: &[&str], allow: &[&str]) -> Blocklist {
        Blocklist {
            blocked: blocked.iter().map(|s| (*s).into()).collect(),
            allow: allow.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn parses_every_format_in_the_catalogue() {
        // hosts
        assert_eq!(parse_line("0.0.0.0 ads.example.com"), Some("ads.example.com"));
        assert_eq!(parse_line("127.0.0.1\tads.example.com # why"), Some("ads.example.com"));
        // bare domain (hagezi wildcard, oisd)
        assert_eq!(parse_line("ads.example.com"), Some("ads.example.com"));
        assert_eq!(parse_line("ads.example.com."), Some("ads.example.com"));
        // adblock domain anchor (adguard)
        assert_eq!(parse_line("||ads.example.com^"), Some("ads.example.com"));
        assert_eq!(parse_line("||ads.example.com^$third-party"), Some("ads.example.com"));
    }

    #[test]
    fn skips_everything_that_is_not_a_domain() {
        for line in [
            "",
            "   ",
            "# a comment",
            "! adblock comment",
            "/regex.*rule/",
            "0.0.0.0 localhost",
            "::1 ip6-localhost",
            "255.255.255.255 broadcasthost",
            "0.0.0.0",
            "127.0.0.1",
            "example.com##.ad-banner",
            "||example.com/path^",
            "||*.example.com^",
            "notadomain",
        ] {
            assert_eq!(parse_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn a_listed_name_blocks_its_subdomains() {
        let l = list(&["ads.example.com"], &[]);
        assert!(l.blocked("ads.example.com"));
        assert!(l.blocked("deep.cdn.ads.example.com"));
        assert!(l.blocked("ADS.EXAMPLE.COM."), "case and trailing dot");
        assert!(!l.blocked("example.com"), "the parent is not implied");
        assert!(!l.blocked("notads.example.com"));
    }

    #[test]
    fn the_allowlist_rescues_a_subdomain_of_a_blocked_parent() {
        let l = list(&["example.com"], &["good.example.com"]);
        assert!(l.blocked("example.com"));
        assert!(l.blocked("bad.example.com"));
        assert!(!l.blocked("good.example.com"));
        assert!(!l.blocked("sub.good.example.com"), "allow covers its subtree too");
    }

    #[test]
    fn never_blocks_on_a_bare_tld() {
        // "com" in a list must not take the whole tld down with it
        let l = list(&["com"], &[]);
        assert!(!l.blocked("example.com"));
    }

    #[test]
    fn an_empty_list_blocks_nothing() {
        assert!(!Blocklist::default().blocked("ads.example.com"));
    }

    /// The one check that a url in SOURCES is still real and still in a
    /// format the parser understands — everything else here is offline, so
    /// a list that quietly moved would otherwise only show up as "blocking
    /// stopped working" on someone's machine.
    ///
    /// Needs the network, so it stays out of the normal run:
    /// `cargo test -- --ignored`
    #[test]
    #[ignore = "downloads every list in the catalogue"]
    fn every_catalogue_url_downloads_and_parses() {
        let dir = std::env::temp_dir().join(format!("guardit-bl-{}", std::process::id()));
        // SAFETY: single-threaded by construction — this test is the only
        // one that touches the variable, and it runs alone under --ignored
        unsafe { std::env::set_var("GUARDIT_BLOCKLIST_DIR", &dir) };
        let mut failures = Vec::new();
        for src in SOURCES {
            match fetch(&src.key(), src.url) {
                // `fetch` already refuses a download that parses to nothing,
                // which is what a moved url or an error page looks like.
                // This is the weaker second check: a list can legitimately be
                // small (native.roku is ~70 domains), it just can't be a
                // handful of lines that happened to look like hostnames
                Ok(n) => assert!(n >= 20, "{} parsed only {n} domains", src.key()),
                Err(e) => failures.push(format!("{}: {e}", src.key())),
            }
        }
        assert!(fetch_doh_ips().is_ok(), "doh ip list");
        assert!(failures.is_empty(), "{failures:#?}");

        // a list that downloads but blocks nothing recognisable is a format
        // change the parser did not notice
        // these are apex entries in hagezi:pro; the list deliberately does
        // NOT carry every ad apex (doubleclick.net is listed only per
        // subdomain), so picking names it actually has is the point
        let cfg = BlocklistConfig {
            enabled: true,
            sources: vec!["hagezi:pro".into()],
            allow: vec!["ok.criteo.com".into()],
            ..Default::default()
        };
        let list = Blocklist::load(&cfg);
        for blocked in ["google-analytics.com", "scorecardresearch.com", "criteo.com"] {
            assert!(list.blocked(blocked), "{blocked}");
        }
        assert!(
            list.blocked("www.google-analytics.com"),
            "a listed name covers its subdomains"
        );
        assert!(!list.blocked("ok.criteo.com"), "allowlist wins");
        for allowed in ["github.com", "wikipedia.org", "kernel.org"] {
            assert!(!list.blocked(allowed), "{allowed}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalogue_keys_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for s in SOURCES {
            assert!(seen.insert(s.key()), "duplicate {}", s.key());
            assert!(s.url.starts_with("https://"), "{} is not https", s.key());
            assert!(!s.about.is_empty());
            assert!(
                category(s.category).is_some(),
                "{} is in category {:?}, which is not one",
                s.key(),
                s.category
            );
        }
    }

    #[test]
    fn every_category_points_at_lists_that_exist() {
        let mut seen = HashSet::new();
        for c in CATEGORIES {
            assert!(seen.insert(c.key), "duplicate category {}", c.key);
            assert!(!c.about.is_empty());
            assert!(!c.sources.is_empty(), "{} enables nothing", c.key);
            for key in c.sources {
                let s = source(key)
                    .unwrap_or_else(|| panic!("{} enables {key}, which is not a list", c.key));
                assert_eq!(
                    s.category, c.key,
                    "{} enables {key}, which is filed under {}",
                    c.key, s.category
                );
            }
        }
        for d in DEFAULT_CATEGORIES {
            assert!(category(d).is_some(), "default {d} is not a category");
        }
    }

    #[test]
    fn overlapping_categories_do_not_download_a_list_twice() {
        let cfg = BlocklistConfig {
            // ads and phishing share nothing, but adding a list by hand that
            // a category already brings in must not duplicate it
            categories: vec!["ads".into(), "phishing".into()],
            sources: vec!["hagezi:pro".into(), "oisd:small".into()],
            ..Default::default()
        };
        let got = effective_sources(&cfg);
        let mut uniq = got.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(got.len(), uniq.len(), "{got:?}");
        assert!(got.contains(&"hagezi:pro".to_string()));
        assert!(got.contains(&"hagezi:tif".to_string()));
        assert!(got.contains(&"oisd:small".to_string()));
    }
}
