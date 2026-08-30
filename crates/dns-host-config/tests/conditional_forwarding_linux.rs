//! Meant to run unmodified against several Docker container configurations
//! that each make a different Linux backend the one
//! `LinuxDnsRoute::probe()` picks, so conditional forwarding is verified
//! to behave identically no matter which backend ends up in charge - a
//! name under our suffix resolves through us, everything else falls
//! through to whatever resolver the host already had, via the
//! REFUSED-fallback mechanism documented in
//! docs/design-dns-host-config.md.
//!
//! Currently wired into `docker/run-resolvconf.sh` only. A systemd-
//! resolved variant and a static-resolv-conf variant are both planned but
//! not wired up yet (the systemd-resolved case needs its own deterministic
//! "pre-existing resolver" setup, which is a separate, not-yet-solved
//! problem from what this test itself checks).
//!
//! Status: the resolvconf run currently fails its second assertion - see
//! src/linux/resolvconf.rs, "Known issue: the merge doesn't happen when
//! driven from this code (unresolved)". The first assertion (our suffix
//! resolves through us) passes.
//!
//! This test starts *both* fake DNS servers itself - the "VPN resolver"
//! (`VPN_SERVER_ADDR`, answers `*.myvpn` and REFUSED otherwise, like
//! `dns-stack`'s `Reply::NotMine`) and a stand-in for "the host's
//! pre-existing resolver" (`ORIGINAL_SERVER_ADDR`, answers everything with
//! a fixed record) - so it never talks to the real network. Each harness
//! script's only job is registering `ORIGINAL_SERVER_ADDR` as an existing
//! nameserver, by whatever means fits that container's backend, *before*
//! this test's `set()` call runs - see each script for how.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;

use dns_host_config::linux::LinuxDnsRoute;
use dns_host_config::{DnsRoute, DnsRouteConfig};
use tokio::net::UdpSocket;

const IFACE: &str = "dummy0";

/// Where this test's own fake "VPN resolver" listens.
const VPN_SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(127, 13, 13, 13);
const IN_SUFFIX_ANSWER: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 10);

/// Where this test's fake stand-in for "the host's pre-existing resolver"
/// listens. Each harness script registers this fixed address as an
/// existing nameserver before the test's `set()` call - see the module
/// docs.
const ORIGINAL_SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(127, 7, 7, 7);
const ORIGINAL_ANSWER: Ipv4Addr = Ipv4Addr::new(20, 20, 20, 20);

fn getent_a_record(name: &str) -> Option<Ipv4Addr> {
    let out = Command::new("getent")
        .args(["ahosts", name])
        .output()
        .expect("running getent");
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .and_then(|addr| addr.parse().ok())
}

/// Binds `addr:53` and serves `answer` with `run_fixed_answer_server`,
/// panicking with a message pointing at the harness script if the bind
/// fails (needs `CAP_NET_BIND_SERVICE` or root).
async fn spawn_fixed_answer_server(addr: Ipv4Addr, verdict: Verdict) {
    let socket = UdpSocket::bind(SocketAddr::from((addr, 53)))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "binding the fake DNS server on {addr}:53: {e} - needs \
                 CAP_NET_BIND_SERVICE or root, see docker/run*.sh"
            )
        });
    tokio::spawn(run_server(socket, verdict));
}

enum Verdict {
    /// Answer everything with this fixed A record - stands in for "the
    /// host's pre-existing resolver," which doesn't know about `*.myvpn`
    /// but resolves everything else.
    AlwaysAnswer(Ipv4Addr),
    /// Answer names ending in `myvpn` with this fixed A record, REFUSED
    /// for everything else - the same two-verdict shape `dns-stack`'s
    /// `Reply::Answer`/`Reply::NotMine` maps to on the wire, reimplemented
    /// directly here so this crate's tests don't need to depend on
    /// `dns-stack` (the two crates have no dependency on each other by
    /// design).
    AnswerInSuffixElseRefuse(Ipv4Addr),
}

/// The only DNS type this fake server ever answers - an AAAA question
/// gets a real NOERROR/0-answers response, not this mislabeled as one.
const QTYPE_A: u16 = 1;

async fn run_server(socket: UdpSocket, verdict: Verdict) {
    let mut buf = [0u8; 512];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await.expect("recv_from");
        let query = &buf[..len];
        if query.len() < 12 {
            continue;
        }
        // getent (via getaddrinfo) queries A and AAAA in parallel; this
        // fake server only ever has an A record to give, so an AAAA
        // question must get a real "no data" NOERROR/0-answers response,
        // never an A record's bytes mislabeled as an answer to it - a
        // resolver seeing a QTYPE-mismatched answer can reasonably treat
        // the whole response as malformed and fail the lookup entirely,
        // even though the *other*, correctly-answered A query would
        // otherwise have been enough.
        let qtype = query_qtype(query);
        let in_suffix = query_name_is_in_myvpn(query);
        let answer = match &verdict {
            Verdict::AlwaysAnswer(addr) if qtype == Some(QTYPE_A) => Some(*addr),
            Verdict::AnswerInSuffixElseRefuse(addr) if qtype == Some(QTYPE_A) && in_suffix => {
                Some(*addr)
            }
            _ => None,
        };
        let refused = match &verdict {
            Verdict::AlwaysAnswer(_) => false,
            Verdict::AnswerInSuffixElseRefuse(_) => !in_suffix,
        };

        let mut resp = Vec::with_capacity(query.len() + 16);
        resp.extend_from_slice(&query[0..2]); // transaction id
        resp.push(0x81); // QR=1, RD=1 (copied intent, always set here)
        resp.push(if refused { 0x85 } else { 0x80 }); // RA=1, RCODE
        resp.extend_from_slice(&query[4..6]); // qdcount, copied
        resp.extend_from_slice(if answer.is_some() { &[0, 1] } else { &[0, 0] }); // ancount
        resp.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
        resp.extend_from_slice(&query[12..]); // question section, verbatim
        if let Some(addr) = answer {
            resp.extend_from_slice(&[0xc0, 0x0c]); // name = pointer to question
            resp.extend_from_slice(&[0, 1]); // TYPE A
            resp.extend_from_slice(&[0, 1]); // CLASS IN
            resp.extend_from_slice(&[0, 0, 0, 60]); // TTL
            resp.extend_from_slice(&[0, 4]); // RDLENGTH
            resp.extend_from_slice(&addr.octets());
        }
        let _ = socket.send_to(&resp, from).await;
    }
}

/// The index of the byte right after an (uncompressed, single-question)
/// query's QNAME's terminating zero length octet - just enough DNS-label
/// parsing for this fake server's needs, not a general-purpose parser.
fn qname_end(query: &[u8]) -> Option<usize> {
    let mut i = 12usize;
    loop {
        let &len = query.get(i)?;
        if len == 0 {
            return Some(i + 1);
        }
        i += 1 + len as usize;
    }
}

/// Whether the query's QNAME ends in `myvpn`.
fn query_name_is_in_myvpn(query: &[u8]) -> bool {
    let mut labels = Vec::new();
    let mut i = 12usize;
    loop {
        let Some(&len) = query.get(i) else {
            return false;
        };
        if len == 0 {
            break;
        }
        let start = i + 1;
        let end = start + len as usize;
        let Some(label) = query.get(start..end) else {
            return false;
        };
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i = end;
    }
    labels.last().map(|l| l == "myvpn").unwrap_or(false)
}

/// The query's QTYPE (the two bytes right after the QNAME), if the
/// message is at least that long.
fn query_qtype(query: &[u8]) -> Option<u16> {
    let end = qname_end(query)?;
    let bytes = query.get(end..end + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

// Needs a real (not current_thread) runtime: getent_a_record() blocks the
// calling OS thread synchronously, and the fake DNS servers spawned below
// are tokio tasks that need a *different* thread free to actually receive
// and answer the query while that block is in progress - on the default
// single-threaded #[tokio::test] runtime, both would fight over the one
// available thread and deadlock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the harness's ORIGINAL_SERVER_ADDR pre-registration + dummy0; run via one of docker/run*.sh"]
async fn conditional_forwarding_via_the_auto_detected_backend() {
    spawn_fixed_answer_server(
        VPN_SERVER_ADDR,
        Verdict::AnswerInSuffixElseRefuse(IN_SUFFIX_ANSWER),
    )
    .await;
    spawn_fixed_answer_server(ORIGINAL_SERVER_ADDR, Verdict::AlwaysAnswer(ORIGINAL_ANSWER)).await;

    let mut route = LinuxDnsRoute::probe("dns-host-config-test").await;
    eprintln!("auto-detected backend: {}", route.backend_name());

    let config = DnsRouteConfig::new(vec![IpAddr::V4(VPN_SERVER_ADDR)], vec!["myvpn".into()])
        .expect("valid config");
    route
        .set(IFACE, &config)
        .await
        .expect("set() should succeed on every backend this test runs against");

    assert_eq!(
        getent_a_record("foo.myvpn"),
        Some(IN_SUFFIX_ANSWER),
        "a name under our suffix must resolve through the VPN server"
    );
    assert_eq!(
        getent_a_record("something.example.test"),
        Some(ORIGINAL_ANSWER),
        "a name outside our suffix must fall through to the pre-registered \
         original resolver, not dead-end at our REFUSED"
    );

    route.reset().await.expect("reset() should succeed");
}
