//! Minimal, dependency-free helpers for building raw IPv6 / ICMPv6 / UDP
//! packets that are written directly into the TUN device.
//!
//! We do this by hand (instead of pulling in `pnet` or similar) so the
//! module stays small and easy to audit. Everything here assumes a plain
//! IPv6 header with no extension headers.

use std::net::Ipv6Addr;

pub const IPV6_HEADER_LEN: usize = 40;
pub const ICMPV6_NEXT_HEADER: u8 = 58;
pub const UDP_NEXT_HEADER: u8 = 17;

/// Build a bare IPv6 header (40 bytes). `payload_len` is the length of
/// whatever comes after this header (ICMPv6 message, UDP datagram, ...).
pub fn build_ipv6_header(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload_len: u16,
) -> [u8; IPV6_HEADER_LEN] {
    let mut hdr = [0u8; IPV6_HEADER_LEN];
    // Version (6) + traffic class + flow label, all zero except version.
    hdr[0] = 0x60;
    hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
    hdr[6] = next_header;
    hdr[7] = hop_limit;
    hdr[8..24].copy_from_slice(&src.octets());
    hdr[24..40].copy_from_slice(&dst.octets());
    hdr
}

/// RFC 1071 one's-complement checksum over an arbitrary byte slice,
/// starting from an existing accumulator (so pseudo-header + payload can be
/// folded together).
fn checksum_accumulate(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv6 upper-layer pseudo-header checksum (RFC 8200 §8.1), used for both
/// ICMPv6 and UDP over IPv6.
pub fn upper_layer_checksum(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    upper_layer_packet: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    sum = checksum_accumulate(sum, &src.octets());
    sum = checksum_accumulate(sum, &dst.octets());
    let len = upper_layer_packet.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += next_header as u32;
    sum = checksum_accumulate(sum, upper_layer_packet);
    checksum_finish(sum)
}

/// Build a full IPv6 + UDP packet with a correctly computed checksum.
pub fn build_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    hop_limit: u8,
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);

    let csum = upper_layer_checksum(src_ip, dst_ip, UDP_NEXT_HEADER, &udp);
    // UDP checksum of 0 is reserved to mean "no checksum"; RFC 768 says a
    // computed value of 0 must be sent as all-ones instead.
    let csum = if csum == 0 { 0xffff } else { csum };
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    let ip_hdr = build_ipv6_header(src_ip, dst_ip, UDP_NEXT_HEADER, hop_limit, udp_len as u16);
    let mut packet = Vec::with_capacity(IPV6_HEADER_LEN + udp_len);
    packet.extend_from_slice(&ip_hdr);
    packet.extend_from_slice(&udp);
    packet
}

/// Parsed view of an inbound IPv6+UDP packet, if it is one.
pub struct UdpV6<'a> {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_ipv6_udp(pkt: &[u8]) -> Option<UdpV6<'_>> {
    if pkt.len() < IPV6_HEADER_LEN + 8 {
        return None;
    }
    if pkt[0] >> 4 != 6 {
        return None; // not IPv6
    }
    let next_header = pkt[6];
    if next_header != UDP_NEXT_HEADER {
        return None; // no extension header support - keep it simple
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    let udp = &pkt[IPV6_HEADER_LEN..];
    if udp.len() < 8 || udp.len() < payload_len {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = &udp[8..payload_len.max(8)];
    Some(UdpV6 {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    })
}
