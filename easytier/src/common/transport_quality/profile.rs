//! Congestion-control profile and scheduler state of the TQUIC transport
//! (MP_SQM_PLAN.md §4.2).
//!
//! MP_SQM_PLAN.md S2.13 removed the `TransportEngine`/`QualityCapabilities`/
//! `resolve_scheduler` engine-capability skeleton: TQUIC is the only engine,
//! and nothing outside this file used it.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerState {
    /// One usable path means the TQUIC scheduler has no choice. TQUIC still
    /// owns its normal recovery/pacing machinery; this does not claim that its
    /// internal scheduler code is disabled.
    NoChoiceSinglePath,
    ActiveMultipath,
}

impl SchedulerState {
    pub const fn for_path_count(path_count: u32) -> Self {
        if path_count > 1 {
            Self::ActiveMultipath
        } else {
            Self::NoChoiceSinglePath
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionControlProfile {
    /// Preserve the selected engine's historical default.
    EngineDefault,
    Bbr,
    Cubic,
    Bbr3,
    Copa,
    /// MP_SQM_PLAN.md S2.4: fixed-rate, externally driven congestion control
    /// (ported from Hysteria). Requires a configured tx rate
    /// (`MpConfig.congestion_control_params_json`'s `up_mbps`, Mbit/s) --
    /// `validate_mp_config` rejects selecting it without one rather than
    /// silently falling back to some default rate.
    Brutal,
    /// Deliberately not exposed through normal configuration; tests/explicit
    /// experiments may opt in through a future separately guarded surface.
    DummyExperimental,
}

impl CongestionControlProfile {
    const ALL: [Self; 7] = [
        Self::EngineDefault,
        Self::Bbr,
        Self::Cubic,
        Self::Bbr3,
        Self::Copa,
        Self::Brutal,
        Self::DummyExperimental,
    ];

    /// A controller that sends at the rate it is given rather than finding
    /// one: it has no bandwidth estimate of its own, so the egress budget
    /// (autorate within the user's bounds and ceilings, MP_SQM_PLAN.md §3)
    /// is its capacity and the allocator's share is its rate. The adaptive
    /// controllers (BBR/BBRv3/CUBIC/COPA) find the SQM bottleneck themselves.
    pub fn is_rate_driven(&self) -> bool {
        matches!(self, Self::Brutal)
    }

    /// Accepts what the plugin registry (`tunnel::mp_plugin::MpCcRegistry`,
    /// the one list of selectable congestion controls, MP_SQM_PLAN.md S2.7)
    /// registers, plus the historical aliases and the test-only `dummy`.
    pub fn parse(value: &str) -> Result<Self, QualityConfigError> {
        let lowered = value.trim().to_ascii_lowercase();
        let name = match lowered.as_str() {
            "" | "default" => "engine-default",
            "bbrv3" => "bbr3",
            other => other,
        };
        let selectable = name == Self::DummyExperimental.as_str()
            || crate::tunnel::mp_plugin::MpCcRegistry::with_builtins()
                .get(name)
                .is_some();
        Self::ALL
            .into_iter()
            .find(|profile| selectable && profile.as_str() == name)
            .ok_or_else(|| QualityConfigError::UnknownCongestionControl {
                field: "congestion-control",
                value: lowered.clone(),
            })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngineDefault => "engine-default",
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::Bbr3 => "bbr3",
            Self::Copa => "copa",
            Self::Brutal => "brutal",
            Self::DummyExperimental => "dummy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QualityConfigError {
    #[error("{field}: unknown congestion-control profile {value:?}")]
    UnknownCongestionControl { field: &'static str, value: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_state_follows_the_usable_path_count() {
        assert_eq!(
            SchedulerState::for_path_count(1),
            SchedulerState::NoChoiceSinglePath
        );
        assert_eq!(
            SchedulerState::for_path_count(2),
            SchedulerState::ActiveMultipath
        );
    }

    #[test]
    fn every_registered_congestion_control_parses_to_its_profile() {
        let registry = crate::tunnel::mp_plugin::MpCcRegistry::with_builtins();
        for plugin in registry.list() {
            let profile = CongestionControlProfile::parse(plugin.name()).unwrap();
            assert_eq!(profile.as_str(), plugin.name());
        }
        assert_eq!(
            CongestionControlProfile::parse(" BBRv3 "),
            Ok(CongestionControlProfile::Bbr3)
        );
        assert_eq!(
            CongestionControlProfile::parse(""),
            Ok(CongestionControlProfile::EngineDefault)
        );
        assert_eq!(
            CongestionControlProfile::parse("dummy"),
            Ok(CongestionControlProfile::DummyExperimental)
        );
    }

    #[test]
    fn unknown_congestion_control_is_a_typed_error_not_a_fallback() {
        assert!(matches!(
            CongestionControlProfile::parse("reno"),
            Err(QualityConfigError::UnknownCongestionControl { .. })
        ));
    }
}
