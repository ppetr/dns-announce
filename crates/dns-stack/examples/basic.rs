use async_trait::async_trait;
use dns_stack::dns::{matches_suffix, Answer, DnsConfig, Query, Reply, Resolver};
use dns_stack::ra::RaConfig;
use dns_stack::DnsStack;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Toy resolver: a static map, "app" would instead be your control-plane
/// lookup (peer registry, service discovery, whatever backs "foo.myvpn").
struct StaticResolver {
    map: HashMap<String, IpAddr>,
}

#[async_trait]
impl Resolver for StaticResolver {
    async fn resolve(&self, query: &Query) -> Reply {
        // Classic split-DNS gate: only names under "myvpn" are ours,
        // everything else is REFUSED so the OS asks its real resolver.
        if !matches_suffix(&query.name, "myvpn") {
            return Reply::NotMine;
        }
        match self.map.get(&query.name) {
            Some(&addr) => Reply::Answer(Answer::Addrs(vec![addr])),
            None => Reply::NxDomain,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // These two addresses must actually be assigned to your interface at
    // the OS level (link-local is usually auto-assigned by the kernel when
    // the interface comes up with IPv6 enabled; the ULA address you assign
    // yourself). This crate does not do interface configuration.
    let link_local: Ipv6Addr = "fe80::1".parse()?;
    let dns_server_addr: Ipv6Addr = "fd00:aaaa::1".parse()?;

    let mut map = HashMap::new();
    map.insert("foo.myvpn".to_string(), IpAddr::V6("fd00:aaaa::2".parse()?));
    let resolver: Arc<dyn Resolver> = Arc::new(StaticResolver { map });

    let ra_cfg = RaConfig {
        link_local_src: link_local,
        dns_servers: vec![dns_server_addr],
        search_domains: vec!["myvpn".to_string()],
        lifetime_secs: 1800,
        router_lifetime_secs: 0, // don't become the default IPv6 route
        resend_interval: Duration::from_secs(600),
    };
    let dns_cfg = DnsConfig {
        server_addr: dns_server_addr,
    };

    // --- dns-stack side: just channels, no knowledge of the transport ---
    let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Vec<u8>>(256);

    DnsStack::new(ra_cfg, dns_cfg).spawn(incoming_rx, outgoing_tx, resolver);

    // --- bridge side: the only part tied to a concrete packet source.
    // Here that's a virtual interface via `tun-rs`; swap in io_uring, a
    // raw socket, or anything else that gives you IPv6 frames. Creating
    // the device and assigning `link_local` / `dns_server_addr` to it is
    // platform-specific setup that lives in your own bring-up code.
    let device = Arc::new(tun_rs::DeviceBuilder::new().build_async()?);

    // Reader: device -> incoming_tx. Whatever else consumes this link's
    // non-DNS/non-RS traffic, you'll want to fan this out upstream of
    // dns-stack rather than only feeding it here (see lib.rs docs).
    let reader_device = device.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match reader_device.recv(&mut buf).await {
                Ok(n) => {
                    if incoming_tx.send(buf[..n].to_vec()).await.is_err() {
                        break; // dns-stack dispatcher gone
                    }
                }
                Err(e) => {
                    log::error!("device read error: {e}");
                    break;
                }
            }
        }
    });

    // Writer: outgoing_rx -> device.
    let writer_device = device.clone();
    tokio::spawn(async move {
        while let Some(pkt) = outgoing_rx.recv().await {
            if let Err(e) = writer_device.send(&pkt).await {
                log::warn!("device write error: {e}");
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    Ok(())
}
