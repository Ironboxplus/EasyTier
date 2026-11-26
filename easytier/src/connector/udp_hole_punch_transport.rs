use std::{net::SocketAddr, sync::Arc};

use anyhow::Error;
use tokio::net::UdpSocket;

use crate::{
    common::PeerId,
    peers::peer_manager::PeerManager,
    tunnel::Tunnel,
};

#[cfg(feature = "mpquic")]
use crate::connector::{
    mp_path::{CarrierKind, UdpMpPathProvider},
    mp_session::OfferPathResult,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UdpPunchRole {
    Client,
    Server,
}

pub(crate) fn tquic_role(my_peer_id: PeerId, remote_peer_id: PeerId) -> UdpPunchRole {
    if my_peer_id < remote_peer_id {
        UdpPunchRole::Client
    } else {
        UdpPunchRole::Server
    }
}

fn effective_tquic_role(
    explicit_role: Option<UdpPunchRole>,
    my_peer_id: PeerId,
    remote_peer_id: PeerId,
) -> UdpPunchRole {
    explicit_role.unwrap_or_else(|| tquic_role(my_peer_id, remote_peer_id))
}

pub(crate) fn mp_udp_punch_enabled(flags: &crate::common::config::Flags) -> bool {
    mp_udp_provider_enabled(flags, "udp-punch")
}

pub(crate) fn mp_udp_provider_enabled(
    flags: &crate::common::config::Flags,
    provider: &str,
) -> bool {
    #[cfg(feature = "mpquic")]
    {
        let mp = flags
            .mp
            .clone()
            .unwrap_or_else(crate::common::config::gen_default_mp_config);
        mp.enabled && mp.providers.iter().any(|configured| configured == provider)
    }

    #[cfg(not(feature = "mpquic"))]
    {
        let _ = (flags, provider);
        false
    }
}

pub(crate) fn normalize_mp_udp_provider(provider: &str) -> &str {
    if provider.is_empty() {
        "udp-punch"
    } else {
        provider
    }
}

pub(crate) enum FinishOutcome {
    NewTunnel {
        tunnel: Box<dyn Tunnel>,
        mp_role: Option<UdpPunchRole>,
    },
    PathAdded,
}

/// A raw UDP punch that has already completed its transaction-level
/// confirmation and is ready to become either a legacy tunnel or an MP path.
pub(crate) struct EstablishedUdpCarrier {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    provider_name: String,
    explicit_role: Option<UdpPunchRole>,
    lifetime_guard: Option<Arc<dyn Send + Sync>>,
    /// The NIC the socket is bound to; `None` detects it from the local address.
    #[cfg_attr(not(feature = "mpquic"), allow(dead_code))]
    egress_device: Option<String>,
}

impl EstablishedUdpCarrier {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        provider_name: &str,
        explicit_role: Option<UdpPunchRole>,
        lifetime_guard: Option<Arc<dyn Send + Sync>>,
    ) -> Self {
        Self {
            socket,
            remote_addr,
            provider_name: normalize_mp_udp_provider(provider_name).to_owned(),
            explicit_role,
            lifetime_guard,
            egress_device: None,
        }
    }

    #[cfg_attr(not(feature = "mpquic"), allow(dead_code))]
    pub(crate) fn with_egress_device(mut self, egress_device: Option<String>) -> Self {
        self.egress_device = egress_device;
        self
    }

    #[cfg(feature = "mpquic")]
    fn mp_provider(&self, carrier_kind: CarrierKind) -> Result<UdpMpPathProvider, Error> {
        let mut provider = UdpMpPathProvider::new(
            carrier_kind,
            self.socket.clone(),
            self.remote_addr,
            self.egress_device.clone(),
        )
        .map_err(anyhow::Error::msg)?;
        if let Some(guard) = self.lifetime_guard.clone() {
            provider = provider.with_lifetime_guard(guard);
        }
        Ok(provider)
    }
}

fn effective_attach_role(mp_role: Option<UdpPunchRole>, legacy_role: UdpPunchRole) -> UdpPunchRole {
    mp_role.unwrap_or(legacy_role)
}

pub(crate) async fn attach_new_tunnel(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    tunnel: Box<dyn Tunnel>,
    mp_role: Option<UdpPunchRole>,
    legacy_role: UdpPunchRole,
    is_directly_connected: bool,
) -> Result<(), Error> {
    let is_mp = mp_role.is_some();
    match effective_attach_role(mp_role, legacy_role) {
        UdpPunchRole::Client if is_mp => peer_mgr
            .add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, Some(peer_id))
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new),
        UdpPunchRole::Client => peer_mgr
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new),
        UdpPunchRole::Server => peer_mgr
            .add_tunnel_as_server(tunnel, is_directly_connected)
            .await
            .map_err(anyhow::Error::new),
    }
}

pub(crate) async fn finish(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    use_mp: bool,
    lifetime_guard: Option<Arc<dyn Send + Sync>>,
) -> Result<FinishOutcome, Error> {
    finish_with_provider_and_role(
        peer_mgr,
        peer_id,
        socket,
        remote_addr,
        use_mp,
        "udp-punch",
        None,
        lifetime_guard,
    )
    .await
}

/// Finish an original UDP punch with an explicit TQUIC role.  UDP punching has
/// a natural initiator/responder relationship; using it avoids a peer-ID
/// ordering race in which the responder would have to start a client before it
/// knows the symmetric-NAT port.
pub(crate) async fn finish_with_role(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    use_mp: bool,
    role: UdpPunchRole,
    lifetime_guard: Option<Arc<dyn Send + Sync>>,
) -> Result<FinishOutcome, Error> {
    finish_with_provider_and_role(
        peer_mgr,
        peer_id,
        socket,
        remote_addr,
        use_mp,
        "udp-punch",
        Some(role),
        lifetime_guard,
    )
    .await
}

pub(crate) async fn finish_with_provider_and_role(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    use_mp: bool,
    provider_name: &str,
    explicit_role: Option<UdpPunchRole>,
    lifetime_guard: Option<Arc<dyn Send + Sync>>,
) -> Result<FinishOutcome, Error> {
    finish_established(
        peer_mgr,
        peer_id,
        use_mp,
        EstablishedUdpCarrier::new(
            socket,
            remote_addr,
            provider_name,
            explicit_role,
            lifetime_guard,
        ),
    )
    .await
}

pub(crate) async fn finish_established(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    use_mp: bool,
    carrier: EstablishedUdpCarrier,
) -> Result<FinishOutcome, Error> {
    let provider_name = carrier.provider_name.as_str();
    #[cfg(feature = "mpquic")]
    if use_mp && mp_udp_provider_enabled(&peer_mgr.get_global_ctx().get_flags(), provider_name) {
        let (carrier_kind, tunnel_type) = match provider_name {
            "udp-punch" => (CarrierKind::UdpPunch, "mpquic_udp_punch"),
            "udp-direct" => (CarrierKind::UdpDirect, "mpquic_udp_direct"),
            unknown => {
                return Err(anyhow::anyhow!(
                    "unsupported UDP MP path provider {unknown:?}"
                ));
            }
        };
        let provider = carrier.mp_provider(carrier_kind)?;
        let remote_url =
            crate::tunnel::build_url_from_socket_addr(&carrier.remote_addr.to_string(), "mpquic");
        let role = effective_tquic_role(carrier.explicit_role, peer_mgr.my_peer_id(), peer_id);
        let mut outcomes = peer_mgr
            .get_mp_session_manager()
            .offer_provider(
                peer_id,
                role == UdpPunchRole::Server,
                &provider,
                remote_url,
                tunnel_type,
            )
            .await
            .map_err(anyhow::Error::new)?;
        return match outcomes.as_slice() {
            [OfferPathResult::NewTunnel(_)] => {
                let OfferPathResult::NewTunnel(tunnel) = outcomes.pop().unwrap() else {
                    unreachable!()
                };
                Ok(FinishOutcome::NewTunnel {
                    tunnel,
                    mp_role: Some(role),
                })
            }
            [OfferPathResult::PathAdded] => Ok(FinishOutcome::PathAdded),
            _ => Err(anyhow::anyhow!(
                "UDP MP provider returned an invalid result count"
            )),
        };
    }

    #[cfg(not(feature = "mpquic"))]
    let _ = (
        peer_id,
        use_mp,
        provider_name,
        carrier.explicit_role,
        carrier.lifetime_guard.as_ref(),
    );

    let tunnel = super::udp_hole_punch::common::try_connect_with_socket(
        peer_mgr.get_global_ctx(),
        carrier.socket,
        carrier.remote_addr,
    )
    .await?;
    Ok(FinishOutcome::NewTunnel {
        tunnel,
        mp_role: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mpquic")]
    #[test]
    fn udp_mp_transport_is_gated_by_both_master_switch_and_provider() {
        let mut flags = crate::common::config::gen_default_flags();
        assert!(!mp_udp_punch_enabled(&flags));

        flags.mp.as_mut().unwrap().enabled = true;
        assert!(mp_udp_punch_enabled(&flags));

        flags.mp.as_mut().unwrap().providers.clear();
        assert!(!mp_udp_punch_enabled(&flags));
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn udp_direct_provider_uses_the_same_mp_master_switch() {
        let mut flags = crate::common::config::gen_default_flags();
        flags.mp.as_mut().unwrap().enabled = true;
        flags.mp.as_mut().unwrap().providers = vec!["udp-direct".into()];

        assert!(mp_udp_provider_enabled(&flags, "udp-direct"));
        assert!(!mp_udp_provider_enabled(&flags, "udp-punch"));
    }

    #[cfg(not(feature = "mpquic"))]
    #[test]
    fn udp_mp_transport_is_disabled_when_the_binary_lacks_mpquic() {
        let mut flags = crate::common::config::gen_default_flags();
        flags.mp.as_mut().unwrap().enabled = true;
        assert!(!mp_udp_punch_enabled(&flags));
    }

    #[test]
    fn udp_tquic_role_is_deterministic_on_both_ends() {
        assert_eq!(tquic_role(10, 20), UdpPunchRole::Client);
        assert_eq!(tquic_role(20, 10), UdpPunchRole::Server);
    }

    #[test]
    fn punch_initiator_role_overrides_peer_id_tie_breaking() {
        assert_eq!(
            effective_tquic_role(Some(UdpPunchRole::Client), 20, 10),
            UdpPunchRole::Client
        );
        assert_eq!(
            effective_tquic_role(Some(UdpPunchRole::Server), 10, 20),
            UdpPunchRole::Server
        );
    }

    #[test]
    fn mp_role_overrides_hole_punch_requester_role_for_attachment() {
        assert_eq!(
            effective_attach_role(Some(UdpPunchRole::Server), UdpPunchRole::Client),
            UdpPunchRole::Server
        );
        assert_eq!(
            effective_attach_role(None, UdpPunchRole::Client),
            UdpPunchRole::Client
        );
    }
}
