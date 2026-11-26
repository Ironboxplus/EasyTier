use anyhow::Error;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::{
    common::{PeerId, config::TcpHolePunchMode},
    peers::peer_manager::PeerManager,
    tunnel::{Tunnel, tcp::tunnel_from_tcp_stream},
};

#[cfg(all(feature = "faketcp", feature = "mpquic"))]
use crate::connector::mp_path::{CarrierKind, MpPathSpec, StaticMpPathProvider};
#[cfg(all(feature = "faketcp", feature = "mpquic"))]
use crate::connector::mp_session::{MpSessionManager, OfferPathResult};

pub(crate) fn configured_mode(value: &str) -> Result<TcpHolePunchMode, Error> {
    effective_mode(value.parse()?)
}

pub(crate) fn configured_mode_for_flags(
    flags: &crate::common::config::Flags,
) -> Result<TcpHolePunchMode, Error> {
    let mode = configured_mode(&flags.tcp_hole_punch_mode)?;
    if mode == TcpHolePunchMode::Tcp {
        return Ok(mode);
    }
    let mp = flags
        .mp
        .clone()
        .unwrap_or_else(crate::common::config::gen_default_mp_config);
    let faketcp_enabled = mp.enabled && mp.providers.iter().any(|p| p == "faketcp-punch");
    match (mode, faketcp_enabled) {
        (TcpHolePunchMode::Auto, false) => Ok(TcpHolePunchMode::Tcp),
        (TcpHolePunchMode::FakeTcp, false) => Err(anyhow::anyhow!(
            "tcp_hole_punch_mode=faketcp requires mp.enabled=true and the faketcp-punch provider"
        )),
        _ => Ok(mode),
    }
}

pub(crate) fn parse_wire_mode(value: &str) -> Result<TcpHolePunchMode, Error> {
    if value.trim().is_empty() {
        // Older peers only know the original plain-TCP hole-punch transport.
        Ok(TcpHolePunchMode::Tcp)
    } else {
        value.parse()
    }
}

pub(crate) fn negotiate_mode(
    local: TcpHolePunchMode,
    remote: TcpHolePunchMode,
) -> Result<TcpHolePunchMode, Error> {
    if local == TcpHolePunchMode::Tcp || remote == TcpHolePunchMode::Tcp {
        if local == TcpHolePunchMode::FakeTcp || remote == TcpHolePunchMode::FakeTcp {
            return Err(anyhow::anyhow!(
                "incompatible TCP hole-punch modes: forced faketcp cannot negotiate with tcp"
            ));
        }
        return Ok(TcpHolePunchMode::Tcp);
    }

    Ok(TcpHolePunchMode::FakeTcp)
}

fn effective_mode(mode: TcpHolePunchMode) -> Result<TcpHolePunchMode, Error> {
    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    {
        Ok(mode)
    }

    #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
    {
        match mode {
            TcpHolePunchMode::Auto | TcpHolePunchMode::Tcp => Ok(TcpHolePunchMode::Tcp),
            TcpHolePunchMode::FakeTcp => Err(anyhow::anyhow!(
                "tcp_hole_punch_mode=faketcp requires both faketcp and mpquic build features"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TcpPunchRole {
    Client,
    Server,
}

struct UpgradeFailure {
    error: Error,
}

enum UpgradeOutcome {
    NewTunnel(Box<dyn Tunnel>),
    PathAdded,
}

pub(crate) enum FinishOutcome {
    NewTunnel {
        tunnel: Box<dyn Tunnel>,
        mp_role: Option<TcpPunchRole>,
    },
    PathAdded,
}

fn effective_attach_role(mp_role: Option<TcpPunchRole>, legacy_role: TcpPunchRole) -> TcpPunchRole {
    mp_role.unwrap_or(legacy_role)
}

pub(crate) async fn attach_new_tunnel(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    tunnel: Box<dyn Tunnel>,
    mp_role: Option<TcpPunchRole>,
    legacy_role: TcpPunchRole,
    is_directly_connected: bool,
) -> Result<(), Error> {
    let is_mp = mp_role.is_some();
    match effective_attach_role(mp_role, legacy_role) {
        TcpPunchRole::Client if is_mp => peer_mgr
            .add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, Some(peer_id))
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new),
        TcpPunchRole::Client => peer_mgr
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new),
        TcpPunchRole::Server => peer_mgr
            .add_tunnel_as_server(tunnel, is_directly_connected)
            .await
            .map_err(anyhow::Error::new),
    }
}

struct UpgradeContext {
    role: TcpPunchRole,
    peer_id: PeerId,
    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    sessions: Option<Arc<MpSessionManager>>,
}

#[async_trait::async_trait]
trait Upgrader: Send + Sync {
    async fn try_upgrade(
        &self,
        stream: TcpStream,
        remote_url: url::Url,
        context: &UpgradeContext,
    ) -> Result<UpgradeOutcome, UpgradeFailure>;
}

struct FakeTcpMpQuicUpgrader;

#[async_trait::async_trait]
impl Upgrader for FakeTcpMpQuicUpgrader {
    async fn try_upgrade(
        &self,
        stream: TcpStream,
        remote_url: url::Url,
        context: &UpgradeContext,
    ) -> Result<UpgradeOutcome, UpgradeFailure> {
        #[cfg(all(feature = "faketcp", feature = "mpquic"))]
        {
            let path = crate::tunnel::fake_tcp::mp_datagram_path_from_tcp_stream(stream)
                .await
                .map_err(|failure| UpgradeFailure {
                    error: anyhow::Error::new(failure.error),
                })?;
            let remote = path.remote_addr();
            let egress_device = path.egress_device().to_string();
            let carrier: Arc<dyn crate::tunnel::mpquic::MpDatagramPath> = path.clone();
            let spec = MpPathSpec::with_egress_device(
                carrier,
                remote,
                &egress_device,
                CarrierKind::FakeTcpPunch,
            )
            .map_err(|error| UpgradeFailure {
                error: anyhow::anyhow!(error),
            })?;
            let recovery_path = path;
            let provider = StaticMpPathProvider::new(CarrierKind::FakeTcpPunch, vec![spec]);
            let sessions = context
                .sessions
                .as_ref()
                .expect("real FakeTCP upgrade requires an MP session manager");
            match sessions
                .offer_provider(
                    context.peer_id,
                    context.role == TcpPunchRole::Server,
                    &provider,
                    remote_url,
                    "mpquic_faketcp",
                )
                .await
            {
                Ok(mut outcomes)
                    if matches!(outcomes.as_slice(), [OfferPathResult::NewTunnel(_)]) =>
                {
                    let OfferPathResult::NewTunnel(tunnel) = outcomes.pop().unwrap() else {
                        unreachable!()
                    };
                    recovery_path.commit();
                    Ok(UpgradeOutcome::NewTunnel(tunnel))
                }
                Ok(outcomes) if matches!(outcomes.as_slice(), [OfferPathResult::PathAdded]) => {
                    recovery_path.commit();
                    Ok(UpgradeOutcome::PathAdded)
                }
                Ok(_) => {
                    recovery_path.close();
                    Err(UpgradeFailure {
                        error: anyhow::anyhow!(
                            "FakeTCP MP provider returned an invalid result count"
                        ),
                    })
                }
                Err(error) => {
                    recovery_path.close();
                    Err(UpgradeFailure {
                        error: anyhow::Error::new(error),
                    })
                }
            }
        }

        #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
        {
            let _ = (stream, remote_url, context);
            Err(UpgradeFailure {
                error: anyhow::anyhow!("binary was built without FakeTCP MPQUIC support"),
            })
        }
    }
}

pub(crate) async fn finish(
    peer_mgr: &Arc<PeerManager>,
    peer_id: PeerId,
    stream: TcpStream,
    remote_url: url::Url,
    mode: TcpHolePunchMode,
    role: TcpPunchRole,
) -> Result<FinishOutcome, Error> {
    #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
    let _ = peer_mgr;
    let context = UpgradeContext {
        role,
        peer_id,
        #[cfg(all(feature = "faketcp", feature = "mpquic"))]
        sessions: Some(peer_mgr.get_mp_session_manager()),
    };
    let result = finish_with(stream, remote_url, mode, context, &FakeTcpMpQuicUpgrader).await;
    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    if mode != TcpHolePunchMode::Tcp {
        peer_mgr.get_mp_session_manager().record_faketcp_upgrade(
            peer_id,
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:#}")),
        );
    }
    result
}

async fn finish_with(
    stream: TcpStream,
    remote_url: url::Url,
    mode: TcpHolePunchMode,
    context: UpgradeContext,
    upgrader: &dyn Upgrader,
) -> Result<FinishOutcome, Error> {
    if mode == TcpHolePunchMode::Tcp {
        return Ok(FinishOutcome::NewTunnel {
            tunnel: tunnel_from_tcp_stream(stream, remote_url)?,
            mp_role: None,
        });
    }

    match upgrader
        .try_upgrade(stream, remote_url.clone(), &context)
        .await
    {
        Ok(UpgradeOutcome::NewTunnel(tunnel)) => Ok(FinishOutcome::NewTunnel {
            tunnel,
            mp_role: Some(context.role),
        }),
        Ok(UpgradeOutcome::PathAdded) => Ok(FinishOutcome::PathAdded),
        // A raw carrier cannot be returned as a native TCP stream after
        // sequence ownership changes. Dropping the path closes it while its
        // tuple guard is still alive; the next punch retries, and
        // `auto` punches plain TCP after repeated failures.
        Err(failure) => {
            tracing::warn!(
                ?mode,
                ?failure.error,
                "FakeTCP MPQUIC upgrade failed after TCP punch; closing the punched carrier"
            );
            Err(failure.error.context("FakeTCP MPQUIC upgrade failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingUpgrader;

    #[async_trait::async_trait]
    impl Upgrader for FailingUpgrader {
        async fn try_upgrade(
            &self,
            _stream: TcpStream,
            _remote_url: url::Url,
            _context: &UpgradeContext,
        ) -> Result<UpgradeOutcome, UpgradeFailure> {
            Err(UpgradeFailure {
                error: anyhow::anyhow!("expected upgrade failure"),
            })
        }
    }

    fn upgrade_context(role: TcpPunchRole) -> UpgradeContext {
        UpgradeContext {
            role,
            peer_id: 1,
            #[cfg(all(feature = "faketcp", feature = "mpquic"))]
            sessions: None,
        }
    }

    async fn connected_tcp_stream() -> (TcpStream, url::Url) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap();
        (client, format!("tcp://{addr}").parse().unwrap())
    }

    #[tokio::test]
    async fn failed_upgrade_closes_the_punched_carrier_instead_of_reusing_it() {
        let (stream, remote_url) = connected_tcp_stream().await;
        let error = finish_with(
            stream,
            remote_url,
            TcpHolePunchMode::FakeTcp,
            upgrade_context(TcpPunchRole::Client),
            &FailingUpgrader,
        )
        .await
        .err()
        .expect("a failed upgrade must not hand back a TCP tunnel");
        assert!(format!("{error:#}").contains("expected upgrade failure"));
    }

    #[tokio::test]
    async fn plain_tcp_mode_never_tries_the_upgrade() {
        let (stream, remote_url) = connected_tcp_stream().await;
        let outcome = finish_with(
            stream,
            remote_url,
            TcpHolePunchMode::Tcp,
            upgrade_context(TcpPunchRole::Client),
            &FailingUpgrader,
        )
        .await
        .unwrap();
        let FinishOutcome::NewTunnel { tunnel, mp_role } = outcome else {
            panic!("plain TCP mode must return the TCP tunnel");
        };
        assert_eq!(mp_role, None);
        assert_eq!(tunnel.info().unwrap().tunnel_type, "tcp");
    }

    #[test]
    fn mode_negotiation_is_symmetric_and_legacy_safe() {
        assert_eq!(parse_wire_mode("").unwrap(), TcpHolePunchMode::Tcp);
        assert_eq!(
            negotiate_mode(TcpHolePunchMode::Auto, TcpHolePunchMode::Auto).unwrap(),
            TcpHolePunchMode::FakeTcp
        );
        assert_eq!(
            negotiate_mode(TcpHolePunchMode::Auto, TcpHolePunchMode::Tcp).unwrap(),
            TcpHolePunchMode::Tcp
        );
        assert!(negotiate_mode(TcpHolePunchMode::FakeTcp, TcpHolePunchMode::Tcp).is_err());
        assert_eq!(
            negotiate_mode(TcpHolePunchMode::Tcp, TcpHolePunchMode::Auto).unwrap(),
            TcpHolePunchMode::Tcp
        );
    }

    #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
    #[test]
    fn auto_mode_uses_plain_tcp_when_upgrade_support_is_not_built() {
        assert_eq!(configured_mode("auto").unwrap(), TcpHolePunchMode::Tcp);
        assert!(configured_mode("faketcp").is_err());
    }

    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    #[test]
    fn auto_mode_remains_auto_when_upgrade_support_is_built() {
        assert_eq!(configured_mode("auto").unwrap(), TcpHolePunchMode::Auto);
    }

    #[test]
    fn mp_config_gates_faketcp_upgrade_and_preserves_tcp_fallback() {
        let mut flags = crate::common::config::gen_default_flags();
        assert_eq!(
            configured_mode_for_flags(&flags).unwrap(),
            TcpHolePunchMode::Tcp,
            "MP disabled must keep the legacy TCP transport"
        );

        let mp = flags.mp.as_mut().unwrap();
        mp.enabled = true;
        assert_eq!(
            configured_mode_for_flags(&flags).unwrap(),
            TcpHolePunchMode::Auto
        );

        flags.mp.as_mut().unwrap().providers.clear();
        flags.tcp_hole_punch_mode = "faketcp".into();
        assert!(configured_mode_for_flags(&flags).is_err());
    }

    #[test]
    fn mp_role_overrides_tcp_punch_initiator_role_for_attachment() {
        assert_eq!(
            effective_attach_role(Some(TcpPunchRole::Server), TcpPunchRole::Client),
            TcpPunchRole::Server
        );
        assert_eq!(
            effective_attach_role(None, TcpPunchRole::Client),
            TcpPunchRole::Client
        );
    }
}
