//! Tiny DNS server that runs entirely in-process. Every incoming query is
//! handed to the application-supplied [`Resolver`], which returns a
//! [`Reply`]: answer with records, NXDOMAIN, or "not mine" (REFUSED, so
//! the OS falls back to its other resolvers rather than us silently
//! blackholing unrelated lookups).
//!
//! Serving a single DNS suffix - the original use case - is just a
//! `Resolver` that returns [`Reply::NotMine`] for names outside the
//! suffix; [`matches_suffix`] is the ready-made check, see
//! `examples/basic.rs`.
//!
//! Message parsing/serialization is delegated to the `simple-dns` crate
//! instead of hand-rolled wire-format code - it correctly handles name
//! compression, multi-question edge cases, etc. that a hand-rolled parser
//! would need to special-case. `simple-dns` types are deliberately kept
//! out of this module's public API so the wire-format library can be
//! swapped later without a breaking change.

use crate::packet::{build_udp_packet, parse_ipv6_udp};
use async_trait::async_trait;
use simple_dns::{
    rdata::{RData, A, AAAA},
    Packet, PacketFlag, ResourceRecord, CLASS, QTYPE, RCODE, TYPE,
};
use std::net::{IpAddr, Ipv6Addr};

pub const DNS_PORT: u16 = 53;

/// TTL (seconds) placed on every answer record we synthesize.
const ANSWER_TTL: u32 = 60;

/// One question pulled off an incoming DNS query, in a parser-independent
/// form so this crate's public API does not leak the wire-format library.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Query {
    /// Queried name without the trailing dot, ASCII-lowercased (DNS names
    /// are case-insensitive), e.g. "foo.myvpn".
    pub name: String,
    /// Record type requested.
    pub kind: RecordKind,
}

/// Record type of a [`Query`]. Anything this server cannot express as an
/// address is collapsed into [`RecordKind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordKind {
    /// `A` - IPv4 address.
    A,
    /// `AAAA` - IPv6 address.
    Aaaa,
    /// Any other QTYPE (`MX`, `TXT`, `SRV`, ...).
    Other,
}

impl RecordKind {
    fn from_qtype(qtype: QTYPE) -> Self {
        match qtype {
            QTYPE::TYPE(TYPE::A) => RecordKind::A,
            QTYPE::TYPE(TYPE::AAAA) => RecordKind::Aaaa,
            _ => RecordKind::Other,
        }
    }
}

/// The records the [`Resolver`] wants in the answer section.
///
/// Deliberately an enum with a single variant today: it lets us add other
/// record types (`CNAME`, `TXT`, ...) later without breaking the trait.
/// `#[non_exhaustive]` forces downstream `match`es to keep a wildcard arm
/// so that addition stays backwards-compatible.
#[non_exhaustive]
pub enum Answer {
    /// Resolve the name to these addresses. An empty list is a valid
    /// NOERROR / no-data reply: the name exists but has no address of the
    /// requested family.
    Addrs(Vec<IpAddr>),
}

/// The [`Resolver`]'s verdict on a single query.
#[non_exhaustive]
pub enum Reply {
    /// Answer the query with these records.
    Answer(Answer),
    /// The name does not exist under a zone we serve - NXDOMAIN. The
    /// client caches this and does not consult its other resolvers.
    NxDomain,
    /// This query is outside what we serve - REFUSED, so the OS falls
    /// back to its other configured resolvers. Returning this rather than
    /// NXDOMAIN is what keeps unrelated lookups working.
    NotMine,
}

#[async_trait]
pub trait Resolver: Send + Sync {
    /// Decide what to do with `query` - see [`Reply`] for the three
    /// outcomes. [`matches_suffix`] helps implement the "one suffix" gate.
    async fn resolve(&self, query: &Query) -> Reply;
}

pub struct DnsConfig {
    /// IPv6 address this server answers on (the interface's address).
    pub server_addr: Ipv6Addr,
}

/// True if `name` falls under `suffix`: it equals `suffix`, or ends with
/// `.suffix` on a label boundary. Comparison is ASCII case-insensitive,
/// as DNS names are. The ready-made check for a [`Resolver`] that serves
/// a single DNS suffix (return [`Reply::NotMine`] when this is false).
/// `suffix` is given WITHOUT a leading dot, e.g. "myvpn".
pub fn matches_suffix(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    let Some(head_len) = name.len().checked_sub(suffix.len()) else {
        return false;
    };
    let (head, tail) = name.split_at(head_len);
    tail.eq_ignore_ascii_case(suffix) && (head.is_empty() || head.last() == Some(&b'.'))
}

/// Handle one inbound raw IPv6 packet read from the interface. Returns the
/// raw IPv6 packet to write back (if any) - the caller is responsible for
/// actually sending it (e.g. onto the `outgoing` mpsc channel).
pub async fn handle_packet(
    cfg: &DnsConfig,
    resolver: &dyn Resolver,
    pkt: &[u8],
) -> Option<Vec<u8>> {
    let udp = parse_ipv6_udp(pkt)?;
    if udp.dst_ip != cfg.server_addr || udp.dst_port != DNS_PORT {
        return None; // not addressed to us
    }

    let packet = Packet::parse(udp.payload).ok()?;
    let question = packet.questions.first()?;
    let query = Query {
        name: question.qname.to_string().to_ascii_lowercase(),
        kind: RecordKind::from_qtype(question.qtype),
    };

    let mut reply = Packet::new_reply(packet.id());
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.questions.push(question.clone());

    match resolver.resolve(&query).await {
        Reply::NotMine => {
            // REFUSED, so the OS can try another configured resolver
            // instead of treating this as authoritative NXDOMAIN.
            *reply.rcode_mut() = RCODE::Refused;
        }
        Reply::NxDomain => {
            *reply.rcode_mut() = RCODE::NameError;
        }
        Reply::Answer(Answer::Addrs(addrs)) => {
            for addr in addrs {
                // Only emit records of the family the client asked for;
                // answering an A query with AAAA records (or vice versa)
                // just confuses resolvers. A query for a non-address type
                // therefore yields an empty answer section, i.e. a clean
                // NOERROR/no-data reply.
                let rdata = match (query.kind, addr) {
                    (RecordKind::A, IpAddr::V4(v4)) => RData::A(A::from(v4)),
                    (RecordKind::Aaaa, IpAddr::V6(v6)) => RData::AAAA(AAAA::from(v6)),
                    _ => continue,
                };
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    ANSWER_TTL,
                    rdata,
                ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matches_exact_name_and_subdomains() {
        assert!(matches_suffix("myvpn", "myvpn"));
        assert!(matches_suffix("foo.myvpn", "myvpn"));
        assert!(matches_suffix("a.b.c.myvpn", "myvpn"));
    }

    #[test]
    fn suffix_match_is_ascii_case_insensitive() {
        assert!(matches_suffix("MyVPN", "myvpn"));
        assert!(matches_suffix("Foo.MYVPN", "myvpn"));
        assert!(matches_suffix("foo.myvpn", "MyVpn"));
    }

    #[test]
    fn suffix_rejects_partial_and_unrelated_names() {
        // A shared tail that does not sit on a label boundary must not match.
        assert!(!matches_suffix("notmyvpn", "myvpn"));
        assert!(!matches_suffix("xmyvpn", "myvpn"));
        // The suffix as a leading label is not a match either.
        assert!(!matches_suffix("myvpn.example", "myvpn"));
        assert!(!matches_suffix("", "myvpn"));
        assert!(!matches_suffix("example.com", "myvpn"));
    }

    #[test]
    fn record_kind_maps_address_qtypes() {
        assert_eq!(RecordKind::from_qtype(QTYPE::TYPE(TYPE::A)), RecordKind::A);
        assert_eq!(
            RecordKind::from_qtype(QTYPE::TYPE(TYPE::AAAA)),
            RecordKind::Aaaa
        );
    }

    #[test]
    fn record_kind_collapses_everything_else_to_other() {
        for qtype in [
            QTYPE::TYPE(TYPE::MX),
            QTYPE::TYPE(TYPE::TXT),
            QTYPE::TYPE(TYPE::CNAME),
            QTYPE::TYPE(TYPE::NS),
            QTYPE::ANY,
            QTYPE::AXFR,
        ] {
            assert_eq!(RecordKind::from_qtype(qtype), RecordKind::Other);
        }
    }
}
