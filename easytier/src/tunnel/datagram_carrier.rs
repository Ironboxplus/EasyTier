//! Carrier abstraction for the mpquic send path (MP_SQM_PLAN.md §4.4,
//! CAKE_SQM_PLAN.md).
//!
//! [`DatagramCarrier`] is the engine-agnostic shape every physical/logical
//! datagram path (UDP socket, FakeTCP-upgraded pseudo-datagram channel,
//! relay-forwarded first hop, ...) must implement -- the one carrier trait in
//! this crate. The send primitive stays synchronous and non-blocking
//! (`try_send_to`), because the only caller that matters --
//! `tquic::PacketSendHandler::on_packets_send` -- is itself a synchronous
//! callback with no executor context to block on.
//!
//! [`GovernedCarrier`] binds a carrier to the egress it leaves through (an
//! [`EgressHandle`]) and, once the peer reported the path's public address,
//! to that WAN's handle too. It does no admission control of its own: every
//! packet is queued in the egress's single CAKE queue
//! (`tunnel::mpquic::egress_cake`), which shapes to
//! [`GovernedCarrier::shaping_rate`] and calls
//! [`GovernedCarrier::send_dequeued`] for each packet it releases.
//!
//! MP_SQM_PLAN.md S2.14: a carrier whose path the peer has reported a public
//! address for is shaped by that WAN's scope, a child of its NIC scope, so a
//! multi-WAN router behind one NIC gets per-WAN autorate while the NIC-level
//! static ceiling still caps their sum.

use std::{net::SocketAddr, sync::Arc};

use crate::common::egress_quality::{EgressHandle, EgressQualityError, SqmEstimate, SqmSample};
use crate::common::transport_quality::budget::EgressScope;
use crate::common::transport_quality::rate::WireBitrate;

/// Standard IPv4/UDP (20+8=28) or IPv6/UDP (40+8=48) framing overhead for one
/// datagram sent to `remote`. This is the default
/// [`DatagramCarrier::per_packet_overhead`] implementation; a carrier that is
/// not plain UDP on the wire (a FakeTCP-upgraded pseudo-datagram channel, a
/// relay-forwarded first hop, ...) must override the trait method with its
/// own framing math instead of inheriting this one.
///
/// Known imprecision: this switches purely on `SocketAddr`'s own variant, so
/// a dual-stack socket whose `remote` is an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`) reports 48 even though the packet is actually IPv4 (28)
/// on the wire, a ~1.4% over-charge.
pub fn udp_ip_header_overhead(remote: SocketAddr) -> u64 {
    match remote {
        SocketAddr::V4(_) => 28,
        SocketAddr::V6(_) => 48,
    }
}

/// Standard IPv4/TCP (20+20=40) or IPv6/TCP (40+20=60) framing overhead
/// (no TCP options) for one segment sent to `remote`, on the same basis and
/// with the same imprecision as [`udp_ip_header_overhead`]. Used by a
/// FakeTCP-upgraded pseudo-datagram channel's
/// [`DatagramCarrier::per_packet_overhead`] override: its wire encapsulation
/// is a real OS TCP socket, not a raw UDP datagram.
pub fn tcp_ip_header_overhead(remote: SocketAddr) -> u64 {
    match remote {
        SocketAddr::V4(_) => 40,
        SocketAddr::V6(_) => 60,
    }
}

/// One physical path an engine session can send datagrams over. Carries no
/// congestion control, scheduling or scope identity: the egress it leaves
/// through is [`GovernedCarrier`]'s.
#[async_trait::async_trait]
pub trait DatagramCarrier: Send + Sync {
    fn local_addr(&self) -> SocketAddr;

    /// Raw, non-blocking send. `Ok(n)` with `n < payload.len()` is a partial
    /// send; `Err` with `ErrorKind::WouldBlock` is the UDP-style "nothing
    /// went out, retry later" case.
    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;

    /// A conservative stand-in for "one full-sized packet" -- our carrier
    /// MTUs are all <= 1500 today.
    fn mtu(&self) -> usize {
        1500
    }

    /// Real on-the-wire framing bytes this carrier adds to `payload.len()`
    /// for one datagram sent to `remote` (IP + UDP headers by default, see
    /// [`udp_ip_header_overhead`]). The egress queue shapes in wire bytes.
    fn per_packet_overhead(&self, remote: SocketAddr) -> u64 {
        udp_ip_header_overhead(remote)
    }
}

/// A carrier together with the NIC it leaves through.
pub struct GovernedCarrier {
    carrier: Arc<dyn DatagramCarrier>,
    handle: EgressHandle,
}

impl GovernedCarrier {
    pub fn new(carrier: Arc<dyn DatagramCarrier>, handle: EgressHandle) -> Self {
        Self { carrier, handle }
    }

    /// The egress this carrier is shaped by: its NIC. Every carrier leaving
    /// through one NIC -- direct paths and relay paths alike, whatever public
    /// address the peer sees -- shares that NIC's one CAKE queue
    /// (`tunnel::mpquic::egress_cake`): one queue per link, as `sch_cake`
    /// is one qdisc per interface.
    pub fn bottleneck(&self) -> EgressHandle {
        self.handle.clone()
    }

    /// The rate the egress queue is shaped to, in wire bits per second.
    pub fn shaping_rate(&self) -> WireBitrate {
        self.handle.shaping_rate()
    }

    /// What `payload_len` bytes to `remote` cost on the wire.
    pub fn wire_bytes(&self, payload_len: usize, remote: SocketAddr) -> u64 {
        payload_len as u64 + self.carrier.per_packet_overhead(remote)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.carrier.local_addr()
    }

    pub fn mtu(&self) -> usize {
        self.carrier.mtu()
    }

    /// This carrier's physical egress identity, answered from its own
    /// `EgressHandle`.
    pub fn egress_scope(&self) -> EgressScope {
        self.handle.scope().clone()
    }

    /// MP_SQM_PLAN.md S2.5: a standalone `mpquic://` connection has no
    /// `MpSessionManager` sampling it, so the driver that owns this carrier
    /// publishes on its own periodic tick, straight into this carrier's own
    /// egress.
    pub fn publish_autorate_sample(
        &self,
        sample: SqmSample,
    ) -> Result<SqmEstimate, EgressQualityError> {
        self.handle.publish_sample(sample)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.carrier.recv_from(buf).await
    }

    /// The one send primitive: the egress queue calls it for each packet it
    /// releases. There is no accessor for the raw carrier, so nothing can
    /// reach around the queue.
    pub fn send_dequeued(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
        self.carrier.try_send_to(payload, remote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::egress_inventory::EgressStableId;
    use crate::common::egress_quality::{EgressQualityConfig, EgressQualityManager};
    use crate::common::transport_quality::budget::EgressDirection;
    use std::sync::Mutex;

    #[test]
    fn tcp_ip_header_overhead_differs_from_the_udp_default_by_the_tcp_udp_header_gap() {
        let v4: SocketAddr = "203.0.113.1:1234".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        assert_eq!(tcp_ip_header_overhead(v4), udp_ip_header_overhead(v4) + 12);
        assert_eq!(tcp_ip_header_overhead(v6), udp_ip_header_overhead(v6) + 12);
        assert_eq!(tcp_ip_header_overhead(v4), 40);
        assert_eq!(tcp_ip_header_overhead(v6), 60);
    }

    fn scope(ifindex: u32) -> EgressScope {
        EgressScope {
            stable_id: EgressStableId::Linux {
                netns_inode: 1,
                ifindex,
            },
            direction: EgressDirection::Egress,
            generation: 1,
        }
    }

    struct RecordingCarrier {
        local: SocketAddr,
        overhead: u64,
        sent: Mutex<Vec<(usize, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl DatagramCarrier for RecordingCarrier {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }
        fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
            self.sent.lock().unwrap().push((payload.len(), remote));
            Ok(payload.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn per_packet_overhead(&self, _remote: SocketAddr) -> u64 {
            self.overhead
        }
    }

    fn governed(
        manager: &Arc<EgressQualityManager>,
        ifindex: u32,
        overhead: u64,
    ) -> (Arc<RecordingCarrier>, GovernedCarrier) {
        let carrier = Arc::new(RecordingCarrier {
            local: "127.0.0.1:4000".parse().unwrap(),
            overhead,
            sent: Mutex::new(Vec::new()),
        });
        let governed = GovernedCarrier::new(carrier.clone(), manager.handle_for(scope(ifindex)));
        (carrier, governed)
    }

    /// The carrier's own framing overhead is what the queue shapes by, and
    /// `send_dequeued` reaches the raw carrier unchanged.
    #[tokio::test]
    async fn wire_bytes_use_the_carriers_own_overhead_and_send_reaches_it() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let (raw, carrier) = governed(&manager, 1, 40);
        let remote: SocketAddr = "203.0.113.9:443".parse().unwrap();
        assert_eq!(carrier.wire_bytes(1_000, remote), 1_040);
        assert_eq!(carrier.send_dequeued(&[0u8; 100], remote).unwrap(), 100);
        assert_eq!(*raw.sent.lock().unwrap(), vec![(100, remote)]);
    }

    /// Shaping is never unlimited, follows the NIC's estimate and is capped
    /// by a ceiling the user declared for the NIC.
    #[tokio::test]
    async fn shaping_rate_follows_the_nic_and_a_declared_ceiling_caps_it() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let (_, carrier) = governed(&manager, 2, 28);
        assert!(carrier.shaping_rate().0 > 0);
        carrier.bottleneck().set_budget(Some(WireBitrate(300_000_000))).unwrap();
        assert_eq!(carrier.shaping_rate(), WireBitrate(300_000_000));

        manager.set_static_ceiling(
            None,
            std::collections::HashMap::from([(
                carrier.egress_scope().stable_id,
                WireBitrate(100_000_000),
            )]),
        );
        assert_eq!(carrier.shaping_rate(), WireBitrate(100_000_000));
    }
}
