//! Builds ICMPv6 Router Advertisements carrying the RDNSS (RFC 8106) and
//! DNSSL options, so a stock OS IPv6 stack can auto-discover our DNS
//! server and search domain over the link without any platform-specific
//! resolver configuration.
//!
//! Important RFC 4861 requirement: RA/RS packets MUST be sent with an
//! IPv6 Hop Limit of 255, and the source address SHOULD be the router's
//! link-local address. Receivers are required to drop RA packets that
//! don't satisfy this - it's what stops an off-link attacker from
//! injecting RAs, and stacks enforce it strictly.

use crate::packet::{build_ipv6_header, upper_layer_checksum, IPV6_HEADER_LEN};
use std::net::Ipv6Addr;
use std::time::Duration;

pub const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

const ICMPV6_RTR_SOLICIT: u8 = 133;
const ICMPV6_RTR_ADVERT: u8 = 134;
const RA_HOP_LIMIT: u8 = 255;

const OPT_RDNSS: u8 = 25;
const OPT_DNSSL: u8 = 31;

/// Configuration for the RA/RDNSS beacon.
#[derive(Clone)]
pub struct RaConfig {
    /// Link-local source address of our interface on the link (fe80::/10).
    pub link_local_src: Ipv6Addr,
    /// Address(es) of the DNS resolver(s) to advertise (usually just our
    /// own address on this link).
    pub dns_servers: Vec<Ipv6Addr>,
    /// Search domain(s) to advertise via DNSSL, e.g. "myvpn".
    pub search_domains: Vec<String>,
    /// How long (in seconds) resolvers should trust the RDNSS/DNSSL
    /// entries. Should be >= how often you resend RAs; RFC 8106 recommends
    /// this be at least 2x the RA interval you use.
    pub lifetime_secs: u32,
    /// Router lifetime advertised in the RA header itself. Keep this 0
    /// unless you actually want to become the default IPv6 route - most
    /// setups only want the DNS side effect, not to hijack default
    /// routing.
    pub router_lifetime_secs: u16,
    /// How often to (re)send unsolicited RAs to ff02::1.
    pub resend_interval: Duration,
}

/// Encode a DNSSL domain name list per RFC 1035 wire format (labels
/// prefixed by length, terminated by a zero byte), concatenated for all
/// domains, RFC 8106 does not use name compression here.
fn encode_dnssl_names(domains: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for domain in domains {
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            debug_assert!(bytes.len() <= 63, "DNS label too long");
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        out.push(0);
    }
    out
}

fn build_rdnss_option(servers: &[Ipv6Addr], lifetime_secs: u32) -> Vec<u8> {
    // Length field is in units of 8 octets, header is 8 bytes + 16 bytes
    // per address.
    let len_units = (1 + 2 * servers.len()) as u8;
    let mut opt = Vec::with_capacity(8 + servers.len() * 16);
    opt.push(OPT_RDNSS);
    opt.push(len_units);
    opt.extend_from_slice(&[0, 0]); // reserved
    opt.extend_from_slice(&lifetime_secs.to_be_bytes());
    for addr in servers {
        opt.extend_from_slice(&addr.octets());
    }
    opt
}

fn build_dnssl_option(domains: &[String], lifetime_secs: u32) -> Vec<u8> {
    let names = encode_dnssl_names(domains);
    let body_len = 4 + names.len(); // reserved(2)+lifetime(4)-2... see below
                                    // header(type+len)=2 bytes, reserved=2, lifetime=4, then names, padded
                                    // to an 8-byte multiple.
    let mut opt = Vec::new();
    opt.push(OPT_DNSSL);
    opt.push(0); // length placeholder, filled below
    opt.extend_from_slice(&[0, 0]); // reserved
    opt.extend_from_slice(&lifetime_secs.to_be_bytes());
    opt.extend_from_slice(&names);
    let _ = body_len;

    // Pad to a multiple of 8 bytes total.
    while opt.len() % 8 != 0 {
        opt.push(0);
    }
    let len_units = (opt.len() / 8) as u8;
    opt[1] = len_units;
    opt
}

/// Build a full IPv6 packet containing an ICMPv6 Router Advertisement with
/// RDNSS + (optionally) DNSSL options, ready to push onto the outbound
/// channel.
pub fn build_router_advertisement(cfg: &RaConfig, dst: Ipv6Addr) -> Vec<u8> {
    let mut icmp = Vec::new();
    icmp.push(ICMPV6_RTR_ADVERT);
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.push(64); // Cur Hop Limit (advisory value for hosts using this link)
    icmp.push(0); // flags: M=0, O=0 (no DHCPv6 needed for our purposes)
    icmp.extend_from_slice(&cfg.router_lifetime_secs.to_be_bytes());
    icmp.extend_from_slice(&0u32.to_be_bytes()); // reachable time (unspecified)
    icmp.extend_from_slice(&0u32.to_be_bytes()); // retrans timer (unspecified)

    icmp.extend_from_slice(&build_rdnss_option(&cfg.dns_servers, cfg.lifetime_secs));
    if !cfg.search_domains.is_empty() {
        icmp.extend_from_slice(&build_dnssl_option(&cfg.search_domains, cfg.lifetime_secs));
    }

    let csum = upper_layer_checksum(cfg.link_local_src, dst, 58, &icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let ip_hdr = build_ipv6_header(cfg.link_local_src, dst, 58, RA_HOP_LIMIT, icmp.len() as u16);
    let mut pkt = Vec::with_capacity(IPV6_HEADER_LEN + icmp.len());
    pkt.extend_from_slice(&ip_hdr);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// Returns true if `pkt` is a valid Router Solicitation (ICMPv6 type 133)
/// that we should respond to with a unicast RA. Validates the hop limit
/// per RFC 4861 §6.1.1 to reject spoofed/off-link solicitations.
pub fn is_router_solicitation(pkt: &[u8]) -> bool {
    if pkt.len() < IPV6_HEADER_LEN + 8 {
        return false;
    }
    let hop_limit = pkt[7];
    let next_header = pkt[6];
    hop_limit == 255 && next_header == 58 && pkt[IPV6_HEADER_LEN] == ICMPV6_RTR_SOLICIT
}

pub fn solicitation_src(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 24 {
        return None;
    }
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?))
}
