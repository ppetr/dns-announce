//! Linux-only integration test that drives `DnsAnnounce` through a real
//! kernel IPv6 stack instead of hand-fed byte buffers.
//!
//! A dedicated TUN device acts as a private point-to-point "loopback": the
//! kernel writes the client's DNS query into the device fd, a reader task
//! forwards it onto the crate's inbound channel, the dispatcher's reply
//! comes back on the outbound channel, a writer task pushes it into the
//! device fd, and the kernel delivers it to a plain `std::net::UdpSocket`.
//! This is what `tests/stack.rs` cannot cover: that the exact IPv6/UDP
//! framing and checksums the crate emits are actually accepted by an OS.
//!
//! The client sends straight to `[server]:53`, so this exercises the DNS
//! server path only. RA/RDNSS discovery (an OS acting on the beacon) is
//! `tests/discovery_linux.rs`.
//!
//! Each harness gets its own interface and its own `fd00:5d5:<n>::/64`
//! subnet, so the tests are safe to run in parallel.
//!
//! `#[ignore]` because they need `CAP_NET_ADMIN` and create/destroy a
//! network interface. Run via `docker/run.sh`, or:
//!
//! ```text
//! sudo -E cargo test --test loopback_linux -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

mod common;

use std::net::Ipv4Addr;

use common::Harness;
use dns_announce::dns::{Answer, RecordKind, Reply};
use simple_dns::{rdata::RData, Packet, RCODE, TYPE};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_ADMIN + /dev/net/tun; run via docker/run.sh"]
async fn in_suffix_a_query_is_answered_over_a_real_tun() {
    let want = Ipv4Addr::new(10, 1, 2, 3);
    let h = Harness::start(move |q| {
        if q.name == "foo.myvpn" && q.kind == RecordKind::A {
            Reply::Answer(Answer::Addrs(vec![want.into()]))
        } else {
            Reply::NotMine
        }
    })
    .await;

    let raw = h.roundtrip("foo.myvpn", TYPE::A).await;
    let reply = Packet::parse(&raw).expect("output parses as DNS");
    assert_eq!(reply.rcode(), RCODE::NoError);
    assert_eq!(reply.answers.len(), 1);
    match &reply.answers[0].rdata {
        RData::A(a) => assert_eq!(a.address, u32::from(want)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_ADMIN + /dev/net/tun; run via docker/run.sh"]
async fn out_of_suffix_query_is_refused_over_a_real_tun() {
    let h = Harness::start(|_| Reply::NotMine).await;

    let raw = h.roundtrip("example.com", TYPE::A).await;
    let reply = Packet::parse(&raw).expect("output parses as DNS");
    assert_eq!(reply.rcode(), RCODE::Refused);
    assert!(reply.answers.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_ADMIN + /dev/net/tun; run via docker/run.sh"]
async fn missing_name_is_nxdomain_over_a_real_tun() {
    let h = Harness::start(|_| Reply::NxDomain).await;

    let raw = h.roundtrip("nope.myvpn", TYPE::AAAA).await;
    let reply = Packet::parse(&raw).expect("output parses as DNS");
    assert_eq!(reply.rcode(), RCODE::NameError);
    assert!(reply.answers.is_empty());
}
