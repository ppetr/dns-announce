//! Full-stack tests: drive `DnsStack` through nothing but its inbound
//! and outbound channels, with the tokio clock paused so the RA beacon is
//! deterministic. No real transport, no sockets - just `Vec<u8>` in,
//! `Vec<u8>` out, crafted/parsed with the crate's own `packet` helpers.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use dns_stack::dns::{Answer, DnsConfig, Query, RecordKind, Reply, Resolver};
use dns_stack::packet::{
    build_ipv6_header, build_udp_packet, parse_ipv6_udp, upper_layer_checksum, ICMPV6_NEXT_HEADER,
    IPV6_HEADER_LEN,
};
use dns_stack::ra::RaConfig;
use dns_stack::DnsStack;
use simple_dns::{rdata::RData, Name, Packet, Question, CLASS, QCLASS, QTYPE, RCODE, TYPE};

const SERVER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const OTHER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0xdead);
const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
const ROUTER_LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
const RESEND: Duration = Duration::from_secs(30);
const ICMPV6_RTR_ADVERT: u8 = 134;

// --- test resolver: a plain closure --------------------------------------

struct FnResolver<F>(F);

#[async_trait]
impl<F> Resolver for FnResolver<F>
where
    F: Fn(&Query) -> Reply + Send + Sync,
{
    async fn resolve(&self, query: &Query) -> Reply {
        (self.0)(query)
    }
}

fn start<F>(resolve: F) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)
where
    F: Fn(&Query) -> Reply + Send + Sync + 'static,
{
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(16);
    let ra_cfg = RaConfig {
        link_local_src: ROUTER_LL,
        dns_servers: vec![SERVER],
        search_domains: vec!["myvpn".to_string()],
        lifetime_secs: 600,
        router_lifetime_secs: 0,
        resend_interval: RESEND,
    };
    let dns_cfg = DnsConfig {
        server_addr: SERVER,
    };
    let resolver: Arc<dyn Resolver> = Arc::new(FnResolver(resolve));
    DnsStack::new(ra_cfg, dns_cfg).spawn(in_rx, out_tx, resolver);
    (in_tx, out_rx)
}

// --- packet builders ----------------------------------------------------

fn router_solicitation(src: Ipv6Addr) -> Vec<u8> {
    // ICMPv6 Router Solicitation: type(133) code(0) checksum(2) reserved(4).
    let mut icmp = vec![133u8, 0, 0, 0, 0, 0, 0, 0];
    let csum = upper_layer_checksum(src, ALL_ROUTERS, ICMPV6_NEXT_HEADER, &icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    let hdr = build_ipv6_header(src, ALL_ROUTERS, ICMPV6_NEXT_HEADER, 255, icmp.len() as u16);
    [hdr.as_slice(), &icmp].concat()
}

fn dns_query(dst: Ipv6Addr, name: &str, qtype: TYPE) -> Vec<u8> {
    let mut query = Packet::new_query(0x1234);
    query.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let payload = query.build_bytes_vec().unwrap();
    build_udp_packet(CLIENT, dst, 40000, 53, &payload, 64)
}

// --- output classification / parsing ----------------------------------

fn dst_ip(pkt: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap())
}

fn is_ra(pkt: &[u8]) -> bool {
    pkt.len() > IPV6_HEADER_LEN
        && pkt[6] == ICMPV6_NEXT_HEADER
        && pkt[IPV6_HEADER_LEN] == ICMPV6_RTR_ADVERT
}

fn is_dns_reply(pkt: &[u8]) -> bool {
    parse_ipv6_udp(pkt).is_some_and(|udp| udp.src_port == 53)
}

fn parse_dns(pkt: &[u8]) -> Packet<'_> {
    let udp = parse_ipv6_udp(pkt).expect("output is IPv6+UDP");
    assert_eq!(udp.src_port, 53);
    assert_eq!(udp.dst_ip, CLIENT);
    Packet::parse(udp.payload).expect("output parses as DNS")
}

async fn recv_where(out: &mut mpsc::Receiver<Vec<u8>>, pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    loop {
        let pkt = out.recv().await.expect("output channel closed");
        if pred(&pkt) {
            return pkt;
        }
    }
}

fn contains_addr(pkt: &[u8], addr: Ipv6Addr) -> bool {
    pkt.windows(16).any(|w| w == addr.octets().as_slice())
}

// --- tests ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn router_solicitation_gets_unicast_ra_advertising_our_resolver() {
    let (tx, mut rx) = start(|_| Reply::NotMine);
    tx.send(router_solicitation(CLIENT)).await.unwrap();

    let ra = recv_where(&mut rx, |p| is_ra(p) && dst_ip(p) == CLIENT).await;
    assert!(
        contains_addr(&ra, SERVER),
        "solicited RA does not carry the advertised resolver address"
    );
}

#[tokio::test(start_paused = true)]
async fn beacon_emits_unsolicited_ra_to_all_nodes() {
    let (_tx, mut rx) = start(|_| Reply::NotMine);
    let ra = recv_where(&mut rx, |p| is_ra(p) && dst_ip(p) == ALL_NODES).await;
    assert!(contains_addr(&ra, SERVER));
}

#[tokio::test(start_paused = true)]
async fn beacon_repeats_on_its_interval() {
    let (_tx, mut rx) = start(|_| Reply::NotMine);
    let _first = recv_where(&mut rx, |p| is_ra(p) && dst_ip(p) == ALL_NODES).await;
    tokio::time::advance(RESEND + Duration::from_secs(1)).await;
    let _second = recv_where(&mut rx, |p| is_ra(p) && dst_ip(p) == ALL_NODES).await;
}

#[tokio::test(start_paused = true)]
async fn in_suffix_a_query_is_answered() {
    let ip = Ipv4Addr::new(10, 1, 2, 3);
    let (tx, mut rx) = start(move |q| {
        if q.name == "foo.myvpn" && q.kind == RecordKind::A {
            Reply::Answer(Answer::Addrs(vec![ip.into()]))
        } else {
            Reply::NxDomain
        }
    });
    tx.send(dns_query(SERVER, "foo.myvpn", TYPE::A))
        .await
        .unwrap();

    let pkt = recv_where(&mut rx, is_dns_reply).await;
    let dns = parse_dns(&pkt);
    assert_eq!(dns.rcode(), RCODE::NoError);
    assert_eq!(dns.answers.len(), 1);
    match &dns.answers[0].rdata {
        RData::A(a) => assert_eq!(a.address, u32::from(ip)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn query_name_reaches_resolver_lowercased() {
    let (tx, mut rx) = start(|q| {
        if q.name == "mixed.myvpn" {
            Reply::Answer(Answer::Addrs(vec![Ipv4Addr::new(1, 1, 1, 1).into()]))
        } else {
            Reply::NxDomain
        }
    });
    tx.send(dns_query(SERVER, "MiXeD.MyVpn", TYPE::A))
        .await
        .unwrap();

    let pkt = recv_where(&mut rx, is_dns_reply).await;
    assert_eq!(parse_dns(&pkt).rcode(), RCODE::NoError);
}

#[tokio::test(start_paused = true)]
async fn out_of_suffix_query_is_refused() {
    let (tx, mut rx) = start(|_| Reply::NotMine);
    tx.send(dns_query(SERVER, "example.com", TYPE::A))
        .await
        .unwrap();

    let pkt = recv_where(&mut rx, is_dns_reply).await;
    let dns = parse_dns(&pkt);
    assert_eq!(dns.rcode(), RCODE::Refused);
    assert!(dns.answers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn missing_name_is_nxdomain() {
    let (tx, mut rx) = start(|_| Reply::NxDomain);
    tx.send(dns_query(SERVER, "nope.myvpn", TYPE::AAAA))
        .await
        .unwrap();

    let pkt = recv_where(&mut rx, is_dns_reply).await;
    let dns = parse_dns(&pkt);
    assert_eq!(dns.rcode(), RCODE::NameError);
    assert!(dns.answers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn aaaa_query_returns_only_v6_records() {
    let v4 = Ipv4Addr::new(10, 0, 0, 1);
    let v6: Ipv6Addr = "fd00::abcd".parse().unwrap();
    let (tx, mut rx) = start(move |_| Reply::Answer(Answer::Addrs(vec![v4.into(), v6.into()])));
    tx.send(dns_query(SERVER, "dual.myvpn", TYPE::AAAA))
        .await
        .unwrap();

    let pkt = recv_where(&mut rx, is_dns_reply).await;
    let dns = parse_dns(&pkt);
    assert_eq!(dns.rcode(), RCODE::NoError);
    assert_eq!(dns.answers.len(), 1);
    match &dns.answers[0].rdata {
        RData::AAAA(a) => assert_eq!(a.address, u128::from(v6)),
        other => panic!("expected only an AAAA record, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn query_to_another_address_is_ignored() {
    let (tx, mut rx) = start(|_| Reply::Answer(Answer::Addrs(vec![Ipv4Addr::LOCALHOST.into()])));
    // Not addressed to our resolver - must be dropped, not answered.
    tx.send(dns_query(OTHER_ADDR, "foo.myvpn", TYPE::A))
        .await
        .unwrap();
    // A solicitation we *do* answer; its RA proves the dispatcher has
    // consumed both inbound packets by the time we see it.
    tx.send(router_solicitation(CLIENT)).await.unwrap();

    let mut saw_dns = false;
    loop {
        let pkt = rx.recv().await.expect("output channel closed");
        saw_dns |= is_dns_reply(&pkt);
        if is_ra(&pkt) && dst_ip(&pkt) == CLIENT {
            break;
        }
    }
    assert!(
        !saw_dns,
        "a query not addressed to our resolver was answered"
    );
}
