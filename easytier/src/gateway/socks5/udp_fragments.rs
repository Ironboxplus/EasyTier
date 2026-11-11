//! Where the fragments of a UDP datagram go.
//!
//! Only the first fragment carries the UDP ports, so the tails cannot be matched to a socket by
//! themselves. The first fragment decides: its destination endpoint belongs to a smoltcp socket
//! ([`FragmentRoute::Stack`]) or it does not ([`FragmentRoute::Kernel`]). The decision is kept
//! under the datagram's source, destination and IP id, and applied to the tails that follow.
//! A tail that comes before its first fragment is kept for a moment and handed to the stack if the
//! first fragment turns out to be the stack's. A tail whose first fragment never comes is never
//! given to the stack: such orphans used to take the stack's 16 reassembly slots one by one until
//! no real datagram could be reassembled.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::tunnel::packet_def::ZCPacket;

/// How long a decision is kept after the datagram's last fragment was seen.
const ROUTE_TTL: Duration = Duration::from_secs(60);
const MAX_ROUTES: usize = 4096;
/// How long tails wait for their first fragment: the reordering of one path, not a retransmission.
const PENDING_TTL: Duration = Duration::from_secs(5);
const MAX_PENDING_DATAGRAMS: usize = 64;
const MAX_PENDING_PACKETS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FragmentKey {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub id: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FragmentRoute {
    Stack,
    Kernel,
}

#[derive(Default)]
pub(super) struct UdpFragments {
    routes: HashMap<FragmentKey, (FragmentRoute, Instant)>,
    pending: HashMap<FragmentKey, (Instant, Vec<ZCPacket>)>,
    pending_packets: usize,
}

impl UdpFragments {
    /// The decision for this datagram, if its first fragment was seen; refreshes its lifetime.
    pub fn route(&mut self, key: &FragmentKey, now: Instant) -> Option<FragmentRoute> {
        let (route, seen) = self.routes.get_mut(key)?;
        if now.duration_since(*seen) > ROUTE_TTL {
            self.routes.remove(key);
            return None;
        }
        *seen = now;
        Some(*route)
    }

    /// Records the first fragment's decision and returns the tails that came before it, oldest
    /// first, when the stack is to have them. Tails for the kernel went there when they arrived.
    pub fn decide(&mut self, key: FragmentKey, route: FragmentRoute, now: Instant) -> Vec<ZCPacket> {
        if self.routes.len() >= MAX_ROUTES {
            self.routes.retain(|_, (_, seen)| now.duration_since(*seen) <= ROUTE_TTL);
            if self.routes.len() >= MAX_ROUTES {
                self.routes.clear();
            }
        }
        self.routes.insert(key, (route, now));
        let tails = self.pending.remove(&key).map(|(_, tails)| tails).unwrap_or_default();
        self.pending_packets -= tails.len();
        match route {
            FragmentRoute::Stack => tails,
            FragmentRoute::Kernel => Vec::new(),
        }
    }

    /// Keeps a tail whose first fragment has not been seen. Over the bounds the tail is not kept.
    pub fn buffer_tail(&mut self, key: FragmentKey, packet: &ZCPacket, now: Instant) {
        if self.pending_packets >= MAX_PENDING_PACKETS
            || (!self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_DATAGRAMS)
        {
            self.expire_pending(now);
            if self.pending_packets >= MAX_PENDING_PACKETS
                || (!self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_DATAGRAMS)
            {
                return;
            }
        }
        self.pending
            .entry(key)
            .or_insert_with(|| (now, Vec::new()))
            .1
            .push(packet.clone());
        self.pending_packets += 1;
    }

    fn expire_pending(&mut self, now: Instant) {
        let mut dropped = 0;
        self.pending.retain(|_, (first, tails)| {
            let keep = now.duration_since(*first) <= PENDING_TTL;
            if !keep {
                dropped += tails.len();
            }
            keep
        });
        self.pending_packets -= dropped;
    }

    /// Forgets everything: the stack these decisions were made for is gone.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.pending.clear();
        self.pending_packets = 0;
    }

    #[cfg(test)]
    fn pending_packets(&self) -> usize {
        self.pending_packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u16) -> FragmentKey {
        FragmentKey {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            id,
        }
    }

    fn tail(tag: u8) -> ZCPacket {
        ZCPacket::new_with_payload(&[tag])
    }

    #[test]
    fn tails_follow_the_decision_of_their_first_fragment() {
        let mut frags = UdpFragments::default();
        let now = Instant::now();
        assert_eq!(frags.route(&key(1), now), None);
        assert!(frags.decide(key(1), FragmentRoute::Stack, now).is_empty());
        assert!(frags.decide(key(2), FragmentRoute::Kernel, now).is_empty());
        assert_eq!(frags.route(&key(1), now), Some(FragmentRoute::Stack));
        assert_eq!(frags.route(&key(2), now), Some(FragmentRoute::Kernel));
        assert_eq!(frags.route(&key(3), now), None);
    }

    #[test]
    fn tails_before_the_first_fragment_go_to_the_stack_in_order() {
        let mut frags = UdpFragments::default();
        let now = Instant::now();
        frags.buffer_tail(key(7), &tail(1), now);
        frags.buffer_tail(key(7), &tail(2), now);
        frags.buffer_tail(key(8), &tail(9), now);
        let tails = frags.decide(key(7), FragmentRoute::Stack, now);
        let payloads: Vec<_> = tails.iter().map(|p| p.payload().to_vec()).collect();
        assert_eq!(payloads, vec![vec![1], vec![2]]);
        // the other datagram's tail is still waiting
        assert_eq!(frags.pending_packets(), 1);
    }

    #[test]
    fn tails_for_the_kernel_are_not_given_to_the_stack() {
        let mut frags = UdpFragments::default();
        let now = Instant::now();
        frags.buffer_tail(key(7), &tail(1), now);
        assert!(frags.decide(key(7), FragmentRoute::Kernel, now).is_empty());
        assert_eq!(frags.pending_packets(), 0);
    }

    #[test]
    fn orphan_tails_are_bounded_and_expire() {
        let mut frags = UdpFragments::default();
        let now = Instant::now();
        for id in 0..1000u16 {
            frags.buffer_tail(key(id), &tail(0), now);
        }
        assert!(frags.pending_packets() <= MAX_PENDING_PACKETS);
        assert!(frags.pending.len() <= MAX_PENDING_DATAGRAMS);
        // after the wait they make room for new ones, and a late first fragment finds nothing
        let later = now + PENDING_TTL + Duration::from_secs(1);
        frags.buffer_tail(key(5000), &tail(1), later);
        assert_eq!(frags.pending_packets(), 1);
        assert!(frags.decide(key(3), FragmentRoute::Stack, later).is_empty());
    }

    #[test]
    fn a_decision_expires_when_the_datagram_goes_quiet_and_stays_while_it_is_busy() {
        let mut frags = UdpFragments::default();
        let start = Instant::now();
        frags.decide(key(1), FragmentRoute::Stack, start);
        let mut now = start;
        for _ in 0..4 {
            now += Duration::from_secs(40);
            assert_eq!(frags.route(&key(1), now), Some(FragmentRoute::Stack));
        }
        now += ROUTE_TTL + Duration::from_secs(1);
        assert_eq!(frags.route(&key(1), now), None);
    }

    #[test]
    fn the_route_table_is_bounded_and_clear_forgets_everything() {
        let mut frags = UdpFragments::default();
        let now = Instant::now();
        for id in 0..=u16::MAX {
            frags.decide(key(id), FragmentRoute::Kernel, now);
        }
        assert!(frags.routes.len() <= MAX_ROUTES);
        frags.buffer_tail(key(1), &tail(1), now);
        frags.clear();
        assert_eq!(frags.route(&key(65535), now), None);
        assert_eq!(frags.pending_packets(), 0);
    }
}
