//! Automatic verdicts: what to do with a connection nobody has ruled on.
//!
//! guardit's normal answer to an unruled connection is to hold the packet and
//! ask. That is the right shape for a desktop somebody is sitting in front
//! of, and the wrong one for everything else — a server, a machine you are
//! ssh'd into, a laptop whose owner is tired of answering. Auto mode
//! (`[auto] enabled = true`) answers instead, from the evidence already on
//! hand at the moment of the decision, and says which piece of evidence it
//! used.
//!
//! What this is *not*: a classifier, a model, a reputation service. Every
//! rule below is a fact about the connection that a person would reach the
//! same conclusion from, which is the only kind of automatic decision worth
//! having in front of a firewall — you can read the reason it printed and
//! tell immediately whether it was right. Anything it has no such fact about
//! it declines to judge (`None`), and `Fallback` decides those.
//!
//! Nothing here persists a rule. Each new connection is judged again on the
//! evidence current at that moment, so a binary replaced ten seconds ago, a
//! name that has just landed on a blocklist, or a service that stopped
//! listening all change the answer without anything to clean up afterwards.

use crate::config::{Action, Direction};
use std::net::IpAddr;
use std::path::Path;

/// What auto mode does with a connection it found no fact about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// hold the packet and ask, exactly as without auto mode — auto then
    /// only ever saves you the questions it could answer itself
    Ask,
    /// let it through. The default, because the heuristics below are written
    /// to catch what is wrong rather than to recognise everything that is
    /// right: on a real machine most connections are some packaged program
    /// talking to a name it resolved a moment ago, and a mode that asks
    /// about those is the mode you turned off
    Allow,
    /// refuse it. The paranoid reading — safe, and it will break things you
    /// then have to allow by hand
    Deny,
}

impl Fallback {
    pub fn as_str(self) -> &'static str {
        match self {
            Fallback::Ask => "ask",
            Fallback::Allow => "allow",
            Fallback::Deny => "deny",
        }
    }
}

/// A verdict and the one fact it rests on. `why` is short because it is
/// rendered inside a column of the flow pane next to the peer — long enough
/// to recognise the rule that fired, not a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub why: &'static str,
}

const fn deny(why: &'static str) -> Option<Decision> {
    Some(Decision {
        action: Action::Deny,
        why,
    })
}

const fn allow(why: &'static str) -> Option<Decision> {
    Some(Decision {
        action: Action::Allow,
        why,
    })
}

/// Everything known about a connection at the moment it has to be decided.
/// Assembled by the daemon's queue loop, which already has all of it.
/// `decide` itself does no I/O — every fact arrives already gathered, so the
/// policy can be tested for what it decides rather than for what happens to
/// be installed on the machine running the tests.
pub struct Facts<'a> {
    /// canonical executable path of the local process, as /proc reports it
    pub exe: &'a str,
    pub dir: Direction,
    /// the destination port: the service being reached (remote for outbound,
    /// ours for inbound) — the same port a rule would be about
    pub port: u16,
    pub peer: IpAddr,
    /// the name the DNS tap saw this address answered for, if any
    pub peer_name: Option<&'a str>,
    /// is some local process listening on `port` right now? Only meaningful
    /// for inbound
    pub listening: bool,
    /// is `exe` still a file on disk? `on_disk(exe)` answers it; the daemon
    /// calls that once per new connection
    pub on_disk: bool,
}

/// is this executable still there? A program that was replaced or unlinked
/// while running keeps its /proc entry, with " (deleted)" appended to the
/// path — so both halves of the check are needed, and neither is a fact
/// `decide` can work out from the string alone.
pub fn on_disk(exe: &str) -> bool {
    !exe.ends_with(" (deleted)") && Path::new(exe).exists()
}

/// Directories whose contents anybody can write and nobody packages. A
/// program running from here is either a build artefact, a downloaded
/// binary, or something that put itself there — none of which is a thing to
/// grant network access to without being asked.
const VOLATILE: [&str; 5] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/private/"];

/// ...and the per-user equivalents, matched anywhere in the path so they
/// cover every user's home without knowing any of their names.
const VOLATILE_ANYWHERE: [&str; 3] = ["/.cache/", "/Downloads/", "/.local/share/Trash/"];

/// Paths only root can write to, filled by a package manager. Not a trust
/// root — root-owned malware is still malware — but it is the difference
/// between "the distribution shipped this" and "this appeared".
const PACKAGED: [&str; 12] = [
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/bin/",
    "/sbin/",
    "/opt/",
    "/snap/",
    "/var/lib/flatpak/",
    "/nix/store/",
];

/// Services that have no business being reached across the open internet
/// from a machine like this one.
///
/// Every one of these is either plaintext where an encrypted version is
/// universal (23 telnet, 5900 VNC), a LAN protocol that leaks credentials
/// the moment it leaves the LAN (139/445 SMB, 135 RPC, 3389 RDP), a
/// spam-bot's outbound port (25 — a real mail client submits on 465 or 587),
/// or a port whose only ordinary use is remote control of this machine by
/// someone else (4444, 5555, 6667). The list is deliberately short: it holds
/// only ports where "to the internet" is itself the anomaly, so the same
/// port to a machine on your own network stays perfectly fine.
const HOSTILE_OUTBOUND: [(u16, &str); 9] = [
    (23, "telnet"),
    (25, "smtp"),
    (135, "rpc"),
    (139, "netbios"),
    (445, "smb"),
    (3389, "rdp"),
    (4444, "shell"),
    (5555, "adb"),
    (6667, "irc"),
];

/// Ports a packaged program using the network normally uses. Not an
/// allowlist of safe ports — it is the set where "a distribution binary is
/// talking on this port" is unremarkable enough that asking a human adds
/// nothing.
const ORDINARY: [u16; 14] = [
    22,  // ssh
    53,  // dns
    67,  // dhcp
    68,  // dhcp
    80,  // http
    123, // ntp
    443, // https
    465, // smtps
    587, // submission
    993, // imaps
    995, // pop3s
    5353, // mdns
    11371, // hkp, keyservers
    9418, // git
];

fn under(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// The one verdict auto mode is willing to reach on its own, or `None` when
/// it has no fact to reach one from.
///
/// Order is not cosmetic: the denials come first, because a fact against a
/// connection has to outrank every reason for it — a packaged program on an
/// ordinary port is exactly what a compromised packaged program looks like,
/// so "it is in /usr/bin" must never rescue a connection that "it is port
/// 445 to the internet" already condemned.
pub fn decide(f: &Facts) -> Option<Decision> {
    // 1. the program is not there any more. Either it was replaced while
    //    running or it unlinked itself, and /proc keeps showing the path
    //    with " (deleted)" appended. Nothing legitimate needs this.
    if !f.on_disk {
        return deny("gone from disk");
    }

    // 2. running out of a directory anyone can write to
    if under(f.exe, &VOLATILE) || VOLATILE_ANYWHERE.iter().any(|d| f.exe.contains(d)) {
        return deny("volatile path");
    }

    let remote = !is_local_address(&f.peer);

    match f.dir {
        Direction::Out => {
            // 3. a service that is an anomaly the moment it crosses the
            //    internet — and only then; the same port on your own network
            //    is a NAS or a printer
            if remote
                && let Some((_, name)) = HOSTILE_OUTBOUND.iter().find(|(p, _)| *p == f.port)
            {
                return deny(name);
            }
            // 4. inside your own network: a printer, a NAS, a router's admin
            //    page, another machine you own. Auto mode that asked about
            //    every one of those would be unusable, and none of it is
            //    traffic leaving the premises
            if !remote {
                return allow("local network");
            }
            // 5. this machine resolved the name and then reached the address
            //    that answered. That sequence is what an ordinary program
            //    looks like from here, and it is evidence a program cannot
            //    fake without going through the DNS layer, where the
            //    blocklists already had their say — a name on a list never
            //    reaches this point (queue_loop checks first)
            if f.peer_name.is_some() {
                return allow("resolved name");
            }
            // 6. a packaged binary on a port packaged binaries use, with no
            //    name to show for it — a cached lookup, or an address in its
            //    configuration
            if under(f.exe, &PACKAGED) && ORDINARY.contains(&f.port) {
                return allow("packaged program");
            }
            None
        }
        Direction::In => {
            // 7. unsolicited inbound off the internet. This is the one every
            //    firewall exists for: an established connection never
            //    reaches the queue (`ct state new` only), so what is left is
            //    something out there opening a connection to this machine
            //    that nothing here asked for
            if remote {
                return deny("inbound from internet");
            }
            // 8. from your own network, to a port something is actually
            //    serving on: file sharing, printing, ssh between your own
            //    machines. Nothing serving means nothing to reach, and a
            //    sweep of every port on the box is what that pattern is
            if f.listening {
                return allow("local network");
            }
            deny("nothing listening")
        }
    }
}

/// Addresses this machine can reach without leaving the premises: itself,
/// the local network, and everything that is not a routable unicast
/// destination.
///
/// Lives here rather than in the daemon because it is a policy judgement,
/// not a packet detail, and both `decide` and `require_resolved` rest on the
/// same one: "is the other end out there, or is it ours?"
pub fn is_local_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 100.64/10, carrier-grade NAT — the address of a router, not
                // of anything anyone looked up
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a packaged path, so the volatile-path rule does not fire on every
    /// test below
    const PKG: &str = "/usr/bin/curl";
    /// ...and one nobody packaged, for the cases about evidence rather than
    /// about where the binary lives
    const OWN: &str = "/home/someone/bin/app";

    fn out(exe: &str, port: u16, peer: &str, name: Option<&'static str>) -> Option<Decision> {
        decide(&Facts {
            exe,
            dir: Direction::Out,
            port,
            peer: peer.parse().unwrap(),
            peer_name: name,
            listening: false,
            on_disk: true,
        })
    }

    fn inbound(port: u16, peer: &str, listening: bool) -> Option<Decision> {
        decide(&Facts {
            exe: PKG,
            dir: Direction::In,
            port,
            peer: peer.parse().unwrap(),
            peer_name: None,
            listening,
            on_disk: true,
        })
    }

    fn act(d: Option<Decision>) -> Option<Action> {
        d.map(|d| d.action)
    }

    #[test]
    fn a_binary_that_is_no_longer_on_disk_is_refused() {
        let gone = decide(&Facts {
            exe: PKG,
            dir: Direction::Out,
            port: 443,
            peer: "1.1.1.1".parse().unwrap(),
            peer_name: Some("example.com"),
            listening: false,
            on_disk: false,
        });
        assert_eq!(act(gone), Some(Action::Deny), "and no reason to allow saves it");
    }

    #[test]
    fn on_disk_covers_both_halves_of_a_vanished_binary() {
        assert!(on_disk("/proc/self/exe"), "a file that is there");
        assert!(!on_disk("/usr/bin/no-such-binary-here"), "unlinked");
        assert!(
            !on_disk("/proc/self/exe (deleted)"),
            "/proc's marker, whatever the path resolves to"
        );
    }

    /// the /usr/bin prefix and a resolved name are both reasons to allow —
    /// neither may rescue a path nobody packaged
    #[test]
    fn a_volatile_path_outranks_every_reason_to_allow() {
        for exe in [
            "/tmp/payload",
            "/dev/shm/payload",
            "/home/someone/.cache/payload",
            "/home/someone/Downloads/payload",
        ] {
            assert_eq!(
                act(out(exe, 443, "1.1.1.1", Some("example.com"))),
                Some(Action::Deny),
                "{exe} must not be allowed by anything"
            );
        }
    }

    #[test]
    fn a_hostile_port_to_the_internet_is_refused_but_the_same_port_on_the_lan_is_not() {
        assert_eq!(
            act(out(PKG, 445, "93.184.216.34", Some("files.example.com"))),
            Some(Action::Deny),
            "smb across the internet"
        );
        assert_eq!(
            act(out(PKG, 445, "192.168.1.10", None)),
            Some(Action::Allow),
            "smb to the nas in the next room"
        );
    }

    #[test]
    fn a_name_this_machine_resolved_is_enough_to_allow_the_address_that_answered() {
        assert_eq!(
            act(out(OWN, 8443, "93.184.216.34", Some("api.example.com"))),
            Some(Action::Allow),
        );
    }

    /// an unpackaged binary, no name, an unremarkable port: nothing here is
    /// suspicious and nothing here is evidence either. That is what
    /// `Fallback` is for, and auto mode must not quietly invent a verdict
    #[test]
    fn no_evidence_either_way_is_left_undecided() {
        assert_eq!(out(OWN, 8443, "93.184.216.34", None), None);
    }

    #[test]
    fn a_packaged_program_on_an_ordinary_port_needs_no_name() {
        assert_eq!(
            act(out(PKG, 123, "93.184.216.34", None)),
            Some(Action::Allow),
            "ntp has no name to resolve"
        );
        assert_eq!(
            out(PKG, 31337, "93.184.216.34", None),
            None,
            "packaged is not a blank cheque on any port"
        );
    }

    #[test]
    fn unsolicited_inbound_from_the_internet_is_refused_even_to_a_live_service() {
        assert_eq!(
            act(inbound(22, "93.184.216.34", true)),
            Some(Action::Deny),
            "a listening sshd is not consent to be reached from anywhere"
        );
    }

    #[test]
    fn inbound_from_the_lan_follows_whether_anything_is_actually_serving() {
        assert_eq!(act(inbound(22, "192.168.1.10", true)), Some(Action::Allow));
        assert_eq!(
            act(inbound(31337, "192.168.1.10", false)),
            Some(Action::Deny),
            "a port nothing serves, swept from the lan"
        );
    }

    #[test]
    fn carrier_grade_nat_and_unique_local_count_as_local() {
        assert!(is_local_address(&"100.64.0.1".parse().unwrap()));
        assert!(is_local_address(&"fd00::1".parse().unwrap()));
        assert!(!is_local_address(&"8.8.8.8".parse().unwrap()));
        assert!(!is_local_address(&"2001:4860:4860::8888".parse().unwrap()));
    }
}
