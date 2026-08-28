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
//! server path only, not RA/RDNSS discovery (an OS acting on the beacon).
//!
//! Each harness gets its own interface *and its own `fd00:5d5:<n>::/64`
//! subnet*, so the tests are safe to run in parallel: without distinct
//! subnets the kernel could route a client query into another test's TUN.
//!
//! These tests are `#[ignore]` because they need `CAP_NET_ADMIN` and
//! create/destroy a network interface. Run them explicitly:
//!
//! ```text
//! sudo -E cargo test --test loopback_linux -- --ignored --nocapture
//! ```
//!
//! or in a container via `docker/run.sh`.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use dns_announce::dns::{Answer, DnsConfig, Query, RecordKind, Reply, Resolver};
use dns_announce::ra::RaConfig;
use dns_announce::DnsAnnounce;
use simple_dns::{rdata::RData, Name, Packet, Question, CLASS, QCLASS, QTYPE, RCODE, TYPE};

/// DNS suffix the test resolver claims.
const SUFFIX: &str = "myvpn";

// --- test resolver: a plain closure (same shape as tests/stack.rs) -------

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

// --- harness: TUN device + bridge tasks + running DnsAnnounce -----------

struct Harness {
    /// Address `DnsAnnounce` answers DNS on for this harness. Reachable
    /// on-link via the connected `/64` route that assigning `if_addr`
    /// installs; deliberately not assigned to the interface (that would
    /// route traffic to it via `lo`).
    server: Ipv6Addr,
    ifname: String,
    _device: Arc<tun_rs::AsyncDevice>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
        // The device is non-persistent, so closing the last fd already
        // tears the interface (and its route) down; this is belt-and-braces
        // in case an Arc clone outlives us briefly.
        let _ = Command::new("ip")
            .args(["link", "del", &self.ifname])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Harness {
    async fn start<F>(resolve: F) -> Harness
    where
        F: Fn(&Query) -> Reply + Send + Sync + 'static,
    {
        let n = next_slot();
        let ifname = format!("dnat{n}");
        // Per-harness subnet: fd00:5d5:<n>::1 is the resolver, ::2 the
        // interface address the kernel picks as the reply destination.
        let server = Ipv6Addr::new(0xfd00, 0x5d5, n, 0, 0, 0, 0, 1);
        let if_addr = Ipv6Addr::new(0xfd00, 0x5d5, n, 0, 0, 0, 0, 2);

        let device = tun_rs::DeviceBuilder::new()
            .name(&ifname)
            .packet_information(false)
            .offload(false)
            .mtu(1500)
            .ipv6(if_addr, 64u8)
            .enable(true)
            .build_async()
            .unwrap_or_else(|e| {
                panic!(
                    "creating TUN {ifname} failed: {e}\n\
                     This test needs CAP_NET_ADMIN. Run it with:\n\
                     sudo -E cargo test --test loopback_linux -- --ignored --nocapture\n\
                     or in a container via docker/run.sh"
                )
            });
        let device = Arc::new(device);

        // Let duplicate-address detection finish so if_addr is usable as a
        // source address before the client starts sending.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);

        let rd = device.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match rd.recv(&mut buf).await {
                    Ok(len) if len > 0 => {
                        if in_tx.send(buf[..len].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let wd = device.clone();
        let writer = tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                let _ = wd.send(&pkt).await;
            }
        });

        let ra_cfg = RaConfig {
            link_local_src: "fe80::1".parse().unwrap(),
            dns_servers: vec![server],
            search_domains: vec![SUFFIX.to_string()],
            lifetime_secs: 600,
            router_lifetime_secs: 0,
            // Long enough that the beacon fires at most once during a test.
            resend_interval: Duration::from_secs(3600),
        };
        let dns_cfg = DnsConfig {
            server_addr: server,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(FnResolver(resolve));
        DnsAnnounce::new(ra_cfg, dns_cfg).spawn(in_rx, out_tx, resolver);

        Harness {
            server,
            ifname,
            _device: device,
            reader,
            writer,
        }
    }

    /// Send one query end to end through this harness and return the raw reply.
    async fn roundtrip(&self, name: &str, qtype: TYPE) -> Vec<u8> {
        let server = self.server;
        let query = build_query(name, qtype);
        tokio::time::timeout(
            Duration::from_secs(20),
            tokio::task::spawn_blocking(move || client_query(server, &query)),
        )
        .await
        .expect("round-trip timed out")
        .expect("client thread panicked")
    }
}

/// A small per-process counter used for both the interface name and the
/// subnet. Starts at 1 (0 would be an odd subnet and `dnat0`). Only unique
/// within one test binary, which is all `cargo test` needs here.
fn next_slot() -> u16 {
    static CTR: AtomicU32 = AtomicU32::new(1);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    // Stay a valid hextet / short ifname even if a run ever spawns many.
    (n % 4096) as u16 + 1
}

// --- DNS client over the real socket ----------------------------------

fn build_query(name: &str, qtype: TYPE) -> Vec<u8> {
    let mut q = Packet::new_query(0x4242);
    q.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    q.build_bytes_vec().unwrap()
}

/// Blocking: send `query` to `[server]:53`, return the first UDP reply.
/// Retries on a short read timeout so a slow interface bring-up or a
/// not-yet-scheduled dispatcher task doesn't turn into a flake; DNS
/// resolvers resend the same way and the reply id lets us ignore dups.
fn client_query(server: Ipv6Addr, query: &[u8]) -> Vec<u8> {
    let sock = UdpSocket::bind("[::]:0").expect("bind client socket");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set read timeout");
    let dst = SocketAddr::new(IpAddr::V6(server), 53);
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut buf = [0u8; 1500];
    loop {
        if let Err(e) = sock.send_to(query, dst) {
            if Instant::now() >= deadline {
                panic!("send_to({dst}) never succeeded: {e}");
            }
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        match sock.recv_from(&mut buf) {
            Ok((len, _)) => return buf[..len].to_vec(),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    panic!("no DNS reply from {dst} within deadline");
                }
            }
            Err(e) => panic!("recv_from failed: {e}"),
        }
    }
}

// --- tests ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_ADMIN and creates a TUN interface; run: sudo -E cargo test --test loopback_linux -- --ignored --nocapture"]
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
#[ignore = "needs CAP_NET_ADMIN and creates a TUN interface; run: sudo -E cargo test --test loopback_linux -- --ignored --nocapture"]
async fn out_of_suffix_query_is_refused_over_a_real_tun() {
    let h = Harness::start(|_| Reply::NotMine).await;

    let raw = h.roundtrip("example.com", TYPE::A).await;
    let reply = Packet::parse(&raw).expect("output parses as DNS");
    assert_eq!(reply.rcode(), RCODE::Refused);
    assert!(reply.answers.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_ADMIN and creates a TUN interface; run: sudo -E cargo test --test loopback_linux -- --ignored --nocapture"]
async fn missing_name_is_nxdomain_over_a_real_tun() {
    let h = Harness::start(|_| Reply::NxDomain).await;

    let raw = h.roundtrip("nope.myvpn", TYPE::AAAA).await;
    let reply = Packet::parse(&raw).expect("output parses as DNS");
    assert_eq!(reply.rcode(), RCODE::NameError);
    assert!(reply.answers.is_empty());
}
