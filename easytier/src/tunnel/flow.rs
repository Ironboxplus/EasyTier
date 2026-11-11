//! Local IP flow metadata for unfragmented TCP and UDP packets.
//!
//! Port of upstream `packet/flow.rs` (#2753). The header parsing is the one the data-plane
//! classifier already uses (`mp_dataplane::parse_inner_ip`), so the send path parses a packet
//! one way only. Flows behind IPv6 extension headers have no key and are never pinned.

use std::net::SocketAddr;

use super::{
    mp_dataplane::{IP_PROTO_TCP, IP_PROTO_UDP, parse_inner_ip},
    packet_def::ZCPacket,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: u8,
}

/// The key of the unfragmented TCP or UDP packet in `packet`'s payload; `None` for anything
/// else, including every fragment (the first one has the ports, the others do not, and all of
/// them must travel together).
pub(crate) fn parse_flow_key(packet: &ZCPacket) -> Option<FlowKey> {
    let inner = parse_inner_ip(packet.payload())?;
    if inner.fragment_id.is_some() || !matches!(inner.protocol, IP_PROTO_TCP | IP_PROTO_UDP) {
        return None;
    }
    let (src_port, dst_port) = inner.ports?;
    Some(FlowKey {
        src: SocketAddr::new(inner.src, src_port),
        dst: SocketAddr::new(inner.dst, dst_port),
        protocol: inner.protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::packet_def::{PacketType, ZCPacketType};

    fn ipv4(protocol: u8, flags: u16, id: u16) -> ZCPacket {
        let len = if protocol == 6 { 40 } else { 28 };
        let mut bytes = vec![0; len];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[6..8].copy_from_slice(&flags.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        packet(bytes)
    }

    fn packet(bytes: Vec<u8>) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn ipv6(fragment_header: bool) -> ZCPacket {
        let mut bytes = vec![0; 48];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
        bytes[6] = if fragment_header { 44 } else { 17 };
        bytes[23] = 1;
        bytes[39] = 2;
        bytes[40..44].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        packet(bytes)
    }

    #[test]
    fn identifies_ipv4_and_ipv6_tcp_and_udp() {
        let udp = parse_flow_key(&ipv4(17, 0, 0)).unwrap();
        assert_eq!(udp.src, "10.0.0.1:4660".parse().unwrap());
        assert_eq!(udp.dst, "10.0.0.2:22136".parse().unwrap());
        let tcp = parse_flow_key(&ipv4(6, 0, 0)).unwrap();
        assert_eq!(tcp.src, udp.src);
        assert_eq!(tcp.dst, udp.dst);
        assert_eq!(tcp.protocol, 6);
        assert_ne!(udp, tcp);
        // "don't fragment" is not a fragment
        assert_eq!(Some(udp), parse_flow_key(&ipv4(17, 0x4000, 0)));
        let v6 = parse_flow_key(&ipv6(false)).unwrap();
        assert_eq!(v6.src, "[::1]:4660".parse().unwrap());
        assert_eq!(v6.protocol, 17);
    }

    #[test]
    fn first_middle_and_last_fragments_do_not_supply_a_flow_key() {
        for protocol in [6, 17, 1, 50] {
            for flags in [0x2000, 0x2001, 1] {
                assert!(parse_flow_key(&ipv4(protocol, flags, 99)).is_none());
            }
        }
    }

    #[test]
    fn other_protocols_and_extension_headers_do_not_supply_a_flow_key() {
        assert!(parse_flow_key(&ipv4(1, 0, 0)).is_none());
        assert!(parse_flow_key(&ipv4(50, 0, 0)).is_none());
        assert!(parse_flow_key(&ipv6(true)).is_none());
    }

    #[test]
    fn truncated_headers_never_supply_a_flow_key() {
        for original in [ipv4(17, 0, 0), ipv4(6, 0, 0), ipv6(false)] {
            let full = original.payload().len();
            // the transport header is complete only for the full packet
            for len in 0..full - 4 {
                assert!(parse_flow_key(&packet(original.payload()[..len].to_vec())).is_none());
            }
        }
    }

    #[test]
    fn flow_key_survives_local_conversions_but_is_not_on_the_wire() {
        let mut original = ipv4(17, 0, 0);
        original.set_flow_key(parse_flow_key(&original));
        let key = original.flow_key();
        assert!(key.is_some());
        let mut converted = original.clone();
        for kind in [
            ZCPacketType::TCP,
            ZCPacketType::UDP,
            ZCPacketType::DummyTunnel,
            ZCPacketType::TCP,
        ] {
            converted = converted.convert_type(kind);
            assert_eq!(converted.flow_key(), key);
            assert_eq!(converted.payload(), original.payload());
        }
        let received = ZCPacket::new_from_buf(converted.inner(), ZCPacketType::TCP);
        assert!(received.flow_key().is_none());
        let wrapped = ZCPacket::new_for_foreign_network(&"network".to_owned(), 2, &original);
        assert_eq!(wrapped.flow_key(), key);
        let unwrapped = wrapped.foreign_network_packet();
        assert_eq!(unwrapped.flow_key(), key);
        assert_eq!(unwrapped.payload(), original.payload());
    }
}
