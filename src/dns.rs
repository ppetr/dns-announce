//! Tiny DNS server that runs entirely in-process. It only answers
//! queries whose name ends with the configured suffix (e.g. ".myvpn") by
//! delegating to an application-supplied [`Resolver`]; every
//! other query gets REFUSED so the OS falls back to whatever other
//! resolvers it has configured, rather than us silently blackholing
//! unrelated lookups.
//!
//! Message parsing/serialization is delegated to the `simple-dns` crate
//! instead of hand-rolled wire-format code - it correctly handles name
//! compression, multi-question edge cases, etc. that a hand-rolled parser
//! would need to special-case.

use crate::packet::{build_udp_packet, parse_ipv6_udp};
use async_trait::async_trait;
use simple_dns::{
    rdata::{RData, A, AAAA},
    Packet, PacketFlag, ResourceRecord, CLASS, QTYPE, RCODE, TYPE,
};
use std::net::{IpAddr, Ipv6Addr};

pub const DNS_PORT: u16 = 53;

#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve a fully-qualified name (without trailing dot) that has
    /// already been confirmed to end with our suffix. Return `None` for
    /// "does not exist".
    async fn resolve(&self, name: &str) -> Option<IpAddr>;
}

pub struct DnsConfig {
    /// IPv6 address this server answers on (the TUN interface's address).
    pub server_addr: Ipv6Addr,
    /// Suffix to intercept, WITHOUT leading dot, e.g. "myvpn".
    pub suffix: String,
}

fn matches_suffix(name: &str, suffix: &str) -> bool {
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

/// Handle one inbound raw IPv6 packet read from the TUN device. Returns
/// the raw IPv6 packet to write back (if any) - the caller is responsible
/// for actually sending it (e.g. onto the `outgoing` mpsc channel).
pub async fn handle_packet(cfg: &DnsConfig, resolver: &dyn Resolver, pkt: &[u8]) -> Option<Vec<u8>> {
    let udp = parse_ipv6_udp(pkt)?;
    if udp.dst_ip != cfg.server_addr || udp.dst_port != DNS_PORT {
        return None; // not addressed to us
    }

    let query = Packet::parse(udp.payload).ok()?;
    let question = query.questions.first()?;
    let qname = question.qname.to_string();

    let mut reply = Packet::new_reply(query.id());
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.questions.push(question.clone());

    if !matches_suffix(&qname, &cfg.suffix) {
        // Not ours - REFUSED, so the OS can try another configured
        // resolver instead of treating this as authoritative NXDOMAIN.
        *reply.rcode_mut() = RCODE::Refused;
    } else if !matches!(question.qtype, QTYPE::TYPE(TYPE::A) | QTYPE::TYPE(TYPE::AAAA)) {
        // Under our suffix but not a record type we serve - clean
        // NOERROR/empty-answer rather than pretending to resolve it.
    } else {
        match resolver.resolve(&qname).await {
            Some(ip) => {
                let rdata = match ip {
                    IpAddr::V4(v4) => RData::A(A::from(v4)),
                    IpAddr::V6(v6) => RData::AAAA(AAAA::from(v6)),
                };
                reply
                    .answers
                    .push(ResourceRecord::new(question.qname.clone(), CLASS::IN, 60, rdata));
            }
            None => {
                *reply.rcode_mut() = RCODE::NameError; // NXDOMAIN
            }
        }
    }

    let dns_payload = reply.build_bytes_vec_compressed().ok()?;
    Some(build_udp_packet(
        udp.dst_ip,
        udp.src_ip,
        DNS_PORT,
        udp.src_port,
        &dns_payload,
        64,
    ))
}
