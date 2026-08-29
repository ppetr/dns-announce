//! Shared harness for the Linux integration tests: a TUN device wired to a
//! running `DnsStack`, plus a UDP client. Included via `mod common;` by
//! `loopback_linux.rs` (socket path) and `discovery_linux.rs` (RA/RDNSS
//! discovery path). Not a test target itself.

#![allow(dead_code)] // each including test file uses only part of this

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use dns_stack::dns::{DnsConfig, Query, Reply, Resolver};
use dns_stack::ra::RaConfig;
use dns_stack::DnsStack;
use simple_dns::{Name, Packet, Question, CLASS, QCLASS, QTYPE, TYPE};

/// DNS suffix the test resolvers claim.
const SUFFIX: &str = "myvpn.example";

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

// --- harness: TUN device + bridge tasks + running DnsStack -----------

pub struct Harness {
    /// Address `DnsStack` answers DNS on for this harness. Reachable
    /// on-link via the connected `/64` route that assigning the interface
    /// address installs; deliberately not assigned to the interface (that
    /// would route traffic to it via `lo`).
    pub server: Ipv6Addr,
    pub ifname: String,
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
    /// Beacon interval far enough out that at most one RA fires during a
    /// socket test. The discovery tests want it frequent - see `start_with`.
    pub async fn start<F>(resolve: F) -> Harness
    where
        F: Fn(&Query) -> Reply + Send + Sync + 'static,
    {
        Self::start_with(resolve, Duration::from_secs(3600)).await
    }

    pub async fn start_with<F>(resolve: F, resend_interval: Duration) -> Harness
    where
        F: Fn(&Query) -> Reply + Send + Sync + 'static,
    {
        // "dnat" so the discovery container's `[Match] Name=dnat*` picks it up.
        let n = next_slot();
        Self::start_impl(resolve, resend_interval, format!("dnat{n}"), n).await
    }

    /// Interface `dnat{n}` on subnet `fd00:5d5:{n}::/64` with a caller-fixed
    /// `n`. The discovery container's static `.network` matches `dnat1`, so
    /// the networkd-dependent tests pin `n = 1` (they run sequentially).
    pub async fn start_pinned<F>(resolve: F, resend_interval: Duration, n: u16) -> Harness
    where
        F: Fn(&Query) -> Reply + Send + Sync + 'static,
    {
        Self::start_impl(resolve, resend_interval, format!("dnat{n}"), n).await
    }

    async fn start_impl<F>(resolve: F, resend_interval: Duration, ifname: String, n: u16) -> Harness
    where
        F: Fn(&Query) -> Reply + Send + Sync + 'static,
    {
        // Per-harness subnet: fd00:5d5:<n>::1 is the resolver, ::2 the
        // interface address the kernel picks as the reply destination.
        let server = Ipv6Addr::new(0xfd00, 0x5d5, n, 0, 0, 0, 0, 1);
        let if_addr = Ipv6Addr::new(0xfd00, 0x5d5, n, 0, 0, 0, 0, 2);
        // A TUN has no MAC and the kernel won't autogenerate a link-local;
        // networkd's userspace RA client won't run on a link without one.
        // Fixed (not per-n): it must differ from RaConfig::link_local_src
        // (fe80::1) or the RA looks like it came from the interface itself
        // and gets discarded. Link-local scope, so no cross-interface clash.
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        let device = tun_rs::DeviceBuilder::new()
            .name(&ifname)
            .packet_information(false)
            .offload(false)
            .mtu(1500)
            .ipv6(if_addr, 64u8)
            .ipv6(link_local, 64u8)
            .enable(true)
            .build_async()
            .unwrap_or_else(|e| {
                panic!(
                    "creating TUN {ifname} failed: {e}\n\
                     These tests need CAP_NET_ADMIN + /dev/net/tun. Run them via\n\
                     docker/run.sh (socket) or docker/run-discovery.sh (RDNSS)."
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
            resend_interval,
        };
        let dns_cfg = DnsConfig {
            server_addr: server,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(FnResolver(resolve));
        DnsStack::new(ra_cfg, dns_cfg).spawn(in_rx, out_tx, resolver);

        Harness {
            server,
            ifname,
            _device: device,
            reader,
            writer,
        }
    }

    /// Send one query end to end through this harness (raw UDP to
    /// `[server]:53`) and return the raw reply packet.
    pub async fn roundtrip(&self, name: &str, qtype: TYPE) -> Vec<u8> {
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
