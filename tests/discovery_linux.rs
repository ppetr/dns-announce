//! Linux-only integration test for the RA/RDNSS *discovery* path: run the
//! beacon on a TUN and let a stock IPv6 stack (systemd-networkd +
//! systemd-resolved) find the resolver on its own, all the way to
//! `getaddrinfo`.
//!
//! Layered so a failure points at the layer that broke:
//!   1. `ra_is_well_formed_on_the_wire_per_rdisc6` - a standalone RFC 8106
//!      parser accepts the RA the beacon emits.
//!   2. `resolved_picks_up_rdnss_from_the_beacon` - networkd hands the
//!      advertised resolver + routing domain to resolved.
//!   3. `getaddrinfo_resolves_in_suffix_name_via_rdnss` - the whole chain:
//!      `getaddrinfo("foo.myvpn.example")` -> nss-resolve -> resolved -> split-DNS
//!      -> our `DnsAnnounce` -> the expected address.
//!   4. `resolved_does_not_route_foreign_names_to_us` - the DNSSL domain is
//!      a *routing* domain: non-suffix lookups do not reach our resolver.
//!
//! `#[ignore]` + needs the systemd stack. Run via `docker/run-discovery.sh`.

#![cfg(target_os = "linux")]

mod common;

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::Harness;
use dns_announce::dns::{Answer, RecordKind, Reply};

const BEACON: Duration = Duration::from_secs(2);

// --- 1: RA is well-formed on the wire -------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ndisc6 (rdisc6) + CAP_NET_RAW; run via docker/run-discovery.sh"]
async fn ra_is_well_formed_on_the_wire_per_rdisc6() {
    let h = Harness::start_with(|_| Reply::NotMine, BEACON).await;
    let server = h.server.to_string();

    // -1 = stop after the first RA, -w = wait up to 6s for it.
    let out = Command::new("rdisc6")
        .args(["-1", "-w", "6000", &h.ifname])
        .output()
        .expect("run rdisc6");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("--- rdisc6 {} ---\n{text}", h.ifname);
    assert!(
        text.contains(&server),
        "rdisc6 did not see our RDNSS server {server} in the RA"
    );
    assert!(
        text.contains("myvpn.example"),
        "rdisc6 did not see the DNSSL domain myvpn.example in the RA"
    );
    eprintln!("OK: rdisc6 parsed RDNSS server {server} and the myvpn.example domain");
}

// --- 2: resolved learns the RDNSS server + routing domain ----------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs systemd-networkd + systemd-resolved; run via docker/run-discovery.sh"]
async fn resolved_picks_up_rdnss_from_the_beacon() {
    let h = Harness::start_pinned(|_| Reply::NotMine, BEACON, 1).await;
    let server = h.server.to_string();

    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let status = run("resolvectl", &["status", &h.ifname]);
        let domains = run("resolvectl", &["domain", &h.ifname]);
        let has_server = status.contains(&server);
        let has_domain = domains.contains("myvpn.example");
        if has_server && has_domain {
            eprintln!(
                "OK: resolved learned RDNSS server {server} and routing domain \
                 ~myvpn.example from the RA beacon"
            );
            return;
        }
        if Instant::now() >= deadline {
            dump_link_state(&h.ifname);
            panic!(
                "resolved did not pick up both RDNSS server ({has_server}) and \
                 routing domain ~myvpn.example ({has_domain}) from the beacon"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// --- 3: full chain through getaddrinfo -----------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs systemd-networkd + systemd-resolved; run via docker/run-discovery.sh"]
async fn getaddrinfo_resolves_in_suffix_name_via_rdnss() {
    let want = Ipv4Addr::new(10, 1, 2, 3);
    let h = Harness::start_pinned(
        move |q| match (&*q.name, q.kind) {
            ("foo.myvpn.example", RecordKind::A) => Reply::Answer(Answer::Addrs(vec![want.into()])),
            (n, _) if n == "myvpn.example" || n.ends_with(".myvpn.example") => Reply::NxDomain,
            _ => Reply::NotMine,
        },
        BEACON,
        1,
    )
    .await;

    // getaddrinfo -> nss-resolve -> resolved -> (split-DNS on ~myvpn) -> us.
    // Retry: resolved needs a few beacons to learn the RDNSS entry.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = tokio::task::spawn_blocking(|| {
            ("foo.myvpn.example", 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|s| s.ip()).collect::<Vec<_>>())
        })
        .await
        .unwrap();
        if let Ok(ips) = &got {
            if ips.contains(&IpAddr::V4(want)) {
                eprintln!("OK: getaddrinfo(foo.myvpn.example) -> {ips:?} via RDNSS discovery");
                return;
            }
        }
        if Instant::now() >= deadline {
            dump_link_state(&h.ifname);
            panic!(
                "getaddrinfo(foo.myvpn.example) never resolved to {want} \
                 via RDNSS discovery (last result: {got:?})"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// --- 4: split-DNS scoping ----------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs systemd-networkd + systemd-resolved; run via docker/run-discovery.sh"]
async fn resolved_does_not_route_foreign_names_to_us() {
    let saw_foreign = Arc::new(AtomicBool::new(false));
    let flag = saw_foreign.clone();
    let h = Harness::start_pinned(
        move |q| {
            if q.name != "myvpn.example" && !q.name.ends_with(".myvpn.example") {
                eprintln!("resolver saw a foreign name: {}", q.name);
                flag.store(true, Ordering::SeqCst);
            }
            Reply::NotMine
        },
        BEACON,
        1,
    )
    .await;

    // Only meaningful once split DNS is actually active on the link.
    let deadline = Instant::now() + Duration::from_secs(45);
    while !run("resolvectl", &["domain", &h.ifname]).contains("myvpn.example") {
        assert!(
            Instant::now() < deadline,
            "routing domain ~myvpn.example never appeared - cannot test scoping"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // A name in a reserved TLD (RFC 6761): resolved must not send it to us.
    let _ = tokio::task::spawn_blocking(|| ("probe.example", 0u16).to_socket_addrs()).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        !saw_foreign.load(Ordering::SeqCst),
        "resolved routed a non-suffix query to our resolver - split-DNS scoping failed"
    );
    eprintln!("OK: probe.example was not routed to our resolver");
}

// --- diagnostics -------------------------------------------------

/// Run a command, return stdout+stderr as a lossy String (empty on error).
fn run(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            t
        }
        Err(_) => String::new(),
    }
}

/// Best-effort dump of everything that explains why an RA was or wasn't
/// consumed on `ifname`.
fn dump_link_state(ifname: &str) {
    let probes: [(&str, &[&str]); 8] = [
        ("ip -6 addr", &["-6", "addr", "show", "dev", ifname]),
        ("ip -6 route", &["-6", "route", "show"]),
        ("networkctl status", &["status", "--no-pager", ifname]),
        ("resolvectl status", &["status", ifname]),
        ("resolvectl domain", &["domain", ifname]),
        (
            "resolvectl query foo.myvpn.example",
            &["query", "--cache=no", "foo.myvpn.example"],
        ),
        (
            "journalctl -u systemd-networkd",
            &["-u", "systemd-networkd", "-b", "--no-pager"],
        ),
        (
            "journalctl -u systemd-resolved",
            &["-u", "systemd-resolved", "-b", "--no-pager", "-n", "40"],
        ),
    ];
    for (label, args) in probes {
        eprintln!(
            "=== {label} ({ifname}) ===\n{}",
            run(label.split_whitespace().next().unwrap(), args)
        );
    }
}
