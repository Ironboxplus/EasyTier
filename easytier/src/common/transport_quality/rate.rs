//! Explicit wire/transport rate units (MP_SQM_PLAN.md §4.2).
//!
//! Resource budgets and public RPC fields use [`WireBitrate`] exclusively;
//! transport packetizers/pacers consume [`TransportByteRate`]. Callers must
//! convert explicitly at the adapter boundary instead of passing a bare
//! `u64` across that boundary, which is how the two units used to get
//! silently conflated.

/// Rate on the wire in bits per second.  Resource budgets and public RPC
/// fields use this unit exclusively.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct WireBitrate(pub u64);

/// Rate consumed by a transport packetizer/pacer in bytes per second.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransportByteRate(pub u64);

impl WireBitrate {
    pub const fn to_transport_bytes_per_second(self) -> TransportByteRate {
        TransportByteRate(self.0 / 8)
    }
}

impl TransportByteRate {
    /// Round upward so a requested byte-rate is never silently underreported
    /// when crossing into the bit/s resource control plane.
    pub const fn to_wire_bits_per_second(self) -> WireBitrate {
        WireBitrate(self.0.saturating_mul(8))
    }
}

impl WireBitrate {
    /// Bits/s from a cumulative-counter byte delta measured over `dt_micros`
    /// microseconds. This is the single convergence point for what used to be
    /// three independent roundings: `connector/mp_egress_sqm.rs`'s
    /// `bytes_per_interval_to_bps` and `peers/link_sqm.rs`'s `rate_bps`. A
    /// zero interval yields a known zero rate rather than a division panic;
    /// callers own detecting counter reset/wrap and passing a zero delta in
    /// that case so this function never has to guess intent from raw counters.
    pub fn from_byte_delta_over_micros(delta_bytes: u64, dt_micros: u64) -> Self {
        if dt_micros == 0 {
            return Self(0);
        }
        let bits = (delta_bytes as u128) * 8 * 1_000_000 / (dt_micros as u128);
        Self(bits.min(u64::MAX as u128) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_delta_rate_matches_the_two_call_sites_it_replaces() {
        // 1_000_000 bytes over 1s = 8 Mbit/s (peers/link_sqm.rs::rate_bps case).
        assert_eq!(
            WireBitrate::from_byte_delta_over_micros(1_000_000, 1_000_000),
            WireBitrate(8_000_000)
        );
        // half a second -> double the rate.
        assert_eq!(
            WireBitrate::from_byte_delta_over_micros(1_000_000, 500_000),
            WireBitrate(16_000_000)
        );
        // zero interval -> 0, no panic (connector/mp_egress_sqm.rs's guard).
        assert_eq!(
            WireBitrate::from_byte_delta_over_micros(1_000_000, 0),
            WireBitrate(0)
        );
        // zero bytes -> 0.
        assert_eq!(
            WireBitrate::from_byte_delta_over_micros(0, 1_000_000),
            WireBitrate(0)
        );
    }

    #[test]
    fn wire_and_transport_rate_conversion_has_no_eight_x_ambiguity() {
        assert_eq!(
            WireBitrate(0).to_transport_bytes_per_second(),
            TransportByteRate(0)
        );
        assert_eq!(
            WireBitrate(80_000_000).to_transport_bytes_per_second(),
            TransportByteRate(10_000_000)
        );
        assert_eq!(
            TransportByteRate(10_000_000).to_wire_bits_per_second(),
            WireBitrate(80_000_000)
        );
        assert_eq!(
            TransportByteRate(u64::MAX).to_wire_bits_per_second(),
            WireBitrate(u64::MAX)
        );
    }
}
