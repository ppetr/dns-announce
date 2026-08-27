//! Announce a DNS resolver to link-local IPv6 clients via RA/RDNSS
//! (RFC 8106) so a stock OS IPv6 stack auto-discovers it, paired with a
//! minimal built-in DNS server that answers the subset of queries an
//! application-supplied filter accepts (e.g. one DNS suffix).
//!
//! This crate is deliberately transport-agnostic: it never touches a TUN
//! device, socket, or any OS API directly. It only consumes raw IP
//! packets from a `tokio::sync::mpsc::Receiver<Vec<u8>>` and produces raw
//! IP packets on a `tokio::sync::mpsc::Sender<Vec<u8>>`. Bridging those
//! channels to an actual TUN device (tun-rs, tun2, or anything else) is
//! the caller's job - see `examples/basic.rs` for a tun-rs bridge. This
//! keeps the crate trivially unit-testable (just push/pop `Vec<u8>` in
//! tests) and immune to churn in any specific TUN crate's API.
//!
//! ## What this does and doesn't do
//! - It advertises `dns_servers`/`search_domains` via unsolicited Router
//!   Advertisements sent to `ff02::1`, and answers Router Solicitations.
//! - The [`dns::Resolver`] decides per query whether to answer, return
//!   NXDOMAIN, or disclaim it (REFUSED) so the OS's other resolvers (if
//!   any) can still handle it - the classic case answers one suffix.
//! - Platform support for RDNSS varies a lot - macOS/iOS in particular do
//!   not implement it at all as of this writing. Treat RA/RDNSS as
//!   best-effort and pair it with a platform-specific resolver
//!   configuration fallback for production use.
//! - You are still responsible for assigning `link_local_src` and
//!   `dns_config.server_addr` as real addresses on the TUN interface, and
//!   for bridging the interface's raw packet I/O to the channels this
//!   crate uses - this module only handles the packets once they're
//!   flowing through those channels.

pub mod dns;
pub mod packet;
pub mod ra;

use dns::{DnsConfig, Resolver};
use ra::{
    build_router_advertisement, is_router_solicitation, solicitation_src, RaConfig,
    ALL_NODES_MULTICAST,
};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct DnsAnnounce {
    ra_cfg: RaConfig,
    dns_cfg: DnsConfig,
}

impl DnsAnnounce {
    pub fn new(ra_cfg: RaConfig, dns_cfg: DnsConfig) -> Self {
        Self { ra_cfg, dns_cfg }
    }

    /// Spawns two background tasks:
    /// - a periodic beacon that pushes unsolicited Router Advertisements
    ///   onto `outgoing`
    /// - a dispatcher that consumes every packet from `incoming` (i.e.
    ///   everything your TUN bridge reads off the device) and, for
    ///   Router Solicitations or DNS queries sent to our resolver address,
    ///   pushes a reply onto `outgoing`; anything else is silently ignored
    ///   so it can
    ///   fall through to whatever else is consuming `incoming` upstream
    ///   of this, if you're sharing it.
    ///
    /// Both tasks stop cleanly once `outgoing` has no more live
    /// receivers (send fails) or `incoming` closes (recv returns None).
    pub fn spawn(
        self,
        incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
        resolver: Arc<dyn Resolver>,
    ) {
        let beacon_cfg = self.ra_cfg.clone();
        let beacon_out = outgoing.clone();
        tokio::spawn(async move {
            ra_beacon_loop(beacon_out, beacon_cfg).await;
        });

        tokio::spawn(async move {
            dispatch_loop(incoming, outgoing, self.ra_cfg, self.dns_cfg, resolver).await;
        });
    }
}

/// Periodically pushes an unsolicited RA onto `outgoing`, addressed to
/// the all-nodes multicast group.
async fn ra_beacon_loop(outgoing: mpsc::Sender<Vec<u8>>, cfg: RaConfig) {
    let unsolicited = build_router_advertisement(&cfg, ALL_NODES_MULTICAST);
    let mut ticker = tokio::time::interval(cfg.resend_interval);
    loop {
        ticker.tick().await;
        if outgoing.send(unsolicited.clone()).await.is_err() {
            log::debug!("outgoing channel closed, stopping RA beacon");
            break;
        }
    }
}

/// Consumes every inbound packet and replies to the two kinds of traffic
/// this crate cares about: Router Solicitations and DNS queries sent to
/// our resolver address. Everything else is dropped - if you need other
/// packets to go somewhere too (e.g. other data traffic sharing the
/// link), fan `incoming` out upstream of this crate rather than trying to
/// reuse the same receiver for both purposes.
async fn dispatch_loop(
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    ra_cfg: RaConfig,
    dns_cfg: DnsConfig,
    resolver: Arc<dyn Resolver>,
) {
    while let Some(pkt) = incoming.recv().await {
        if is_router_solicitation(&pkt) {
            if let Some(src) = solicitation_src(&pkt) {
                let reply = build_router_advertisement(&ra_cfg, src);
                if outgoing.send(reply).await.is_err() {
                    break;
                }
            }
            continue;
        }

        if let Some(reply) = dns::handle_packet(&dns_cfg, resolver.as_ref(), &pkt).await {
            if outgoing.send(reply).await.is_err() {
                break;
            }
        }
    }
    log::info!("incoming channel closed, dns-announce dispatcher stopped");
}
