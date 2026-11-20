use std::{sync::Arc, time::Duration};

use anyhow::Context;
use hotpath::instant::Instant;
use tokio::net::UdpSocket;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{PeerId, upnp},
    connector::{
        udp_hole_punch::{
            common::{HOLE_PUNCH_PACKET_BODY_LEN, UdpSocketArray},
            handle_rpc_result,
        },
        udp_hole_punch_transport::{
            FinishOutcome, UdpPunchRole, finish_with_role,
            mp_udp_punch_enabled,
        },
    },
    peers::peer_manager::PeerManager,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketConeRequest, UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::udp::new_hole_punch_packet,
};

use super::common::PunchHoleServerCommon;

/// `dest_addr`'s port at each of the requester's other public IPv4s
/// (`SendPunchPacketConeRequest.mp_alt_dest_ips`).
#[cfg(feature = "mpquic")]
fn mp_alt_dest_addrs(
    dest_addr: std::net::SocketAddr,
    alt_ips: Vec<crate::proto::common::Ipv4Addr>,
) -> Vec<std::net::SocketAddr> {
    let mut addrs = Vec::new();
    for ip in alt_ips.into_iter().map(std::net::Ipv4Addr::from) {
        let addr = std::net::SocketAddr::from((ip, dest_addr.port()));
        if !ip.is_unspecified() && !ip.is_multicast() && addr != dest_addr && !addrs.contains(&addr)
        {
            addrs.push(addr);
        }
    }
    addrs
}

/// Our public IPv4s other than `mapped`'s, for `mp_alt_dest_ips` and
/// `SelectPunchListenerResponse.mp_alt_listener_ips`.
#[cfg(feature = "mpquic")]
pub(super) fn mp_alt_public_ips(
    public_ips: &[String],
    mapped: std::net::SocketAddr,
) -> Vec<crate::proto::common::Ipv4Addr> {
    public_ips
        .iter()
        .filter_map(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| std::net::IpAddr::V4(*ip) != mapped.ip())
        .map(Into::into)
        .collect()
}

pub(crate) struct PunchConeHoleServer {
    common: Arc<PunchHoleServerCommon>,
}

impl PunchConeHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self { common }
    }

    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_cone(
        &self,
        _: BaseController,
        request: SendPunchPacketConeRequest,
    ) -> Result<Void, rpc_types::error::Error> {
        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing listener_mapped_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        #[cfg(feature = "mpquic")]
        let listener = if request.use_mp {
            self.common.find_mp_listener(&listener_addr).await
        } else {
            self.common.find_listener(&listener_addr).await
        };
        #[cfg(not(feature = "mpquic"))]
        let listener = self.common.find_listener(&listener_addr).await;
        let listener = listener.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone failed to find listener"
        ))?;

        let dest_addr = request.dest_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing dest_addr"
        ))?;
        let dest_addr = std::net::SocketAddr::from(dest_addr);
        let dest_ip = dest_addr.ip();
        if dest_ip.is_unspecified() || dest_ip.is_multicast() {
            return Err(anyhow::anyhow!(
                "send_punch_packet_for_cone dest_ip is malformed, {:?}",
                request
            )
            .into());
        }

        #[cfg(feature = "mpquic")]
        if request.use_mp {
            let peer_id = request.requester_peer_id;
            if peer_id == 0 {
                return Err(
                    anyhow::anyhow!("MP UDP punch request is missing requester_peer_id").into(),
                );
            }
            tracing::info!(
                peer_id,
                provider = %request.mp_provider,
                ?dest_addr,
                transaction_id = request.transaction_id,
                "waiting to hand confirmed raw UDP punch to MP"
            );
            super::common::spawn_confirmed_raw_mp_server_handoff(
                self.common.get_peer_mgr(),
                peer_id,
                listener.clone(),
                request.transaction_id,
                Some(dest_addr),
                request.mp_provider.clone(),
            );
        }

        let mut dest_addrs = vec![dest_addr];
        #[cfg(feature = "mpquic")]
        if request.use_mp {
            dest_addrs.extend(mp_alt_dest_addrs(dest_addr, request.mp_alt_dest_ips.clone()));
        }

        let global_ctx = self.common.get_global_ctx();
        let local_addr = listener.local_addr().ok();
        for _ in 0..request.packet_batch_count {
            tracing::info!(?request, "sending hole punching packet");

            for _ in 0..request.packet_count_per_batch {
                for dest_addr in &dest_addrs {
                    if !global_ctx
                        .allow_punch_packet(local_addr, dest_addr.ip())
                        .await
                    {
                        continue;
                    }
                    let udp_packet =
                        new_hole_punch_packet(request.transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                    if let Err(e) = listener.send_to(&udp_packet.into_bytes(), dest_addr).await {
                        tracing::error!(?e, "failed to send hole punch packet to dest addr");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(request.packet_interval_ms as u64)).await;
        }

        Ok(Void::default())
    }
}

pub(crate) struct PunchConeHoleClient {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchConeHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr,
            blacklist,
        }
    }

    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
    ) -> Result<Option<FinishOutcome>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        tracing::info!(?dst_peer_id, "start hole punching");
        let tid = rand::random();

        let global_ctx = self.peer_mgr.get_global_ctx();
        let udp_array = UdpSocketArray::new(1, global_ctx.clone());

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let request_mp = mp_udp_punch_enabled(&global_ctx.get_flags());
        let requester_peer_id = self.peer_mgr.my_peer_id();
        let resp = rpc_stub
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    force_new: false,
                    prefer_port_mapping: true,
                    use_mp: request_mp,
                    requester_peer_id,
                    mp_provider: "udp-punch".into(),
                },
            )
            .await;

        let resp = handle_rpc_result(resp, dst_peer_id, &self.blacklist)?;

        let remote_mapped_addr = resp.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "select_punch_listener response missing listener_mapped_addr"
        ))?;
        let use_mp = request_mp && resp.mp_accepted;
        // MP: the listener's answer may come from another of its WANs (mwan3), at the same port;
        // open our NAT toward each of them too.
        #[cfg(feature = "mpquic")]
        let remote_alt_addrs = if use_mp {
            mp_alt_dest_addrs(remote_mapped_addr.into(), resp.mp_alt_listener_ips)
        } else {
            Vec::new()
        };
        #[cfg(not(feature = "mpquic"))]
        let remote_alt_addrs: Vec<std::net::SocketAddr> = Vec::new();

        let local_socket = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
        };
        let local_addr = local_socket
            .local_addr()
            .with_context(|| "failed to get local addr from udp punch socket")?;
        let local_listener: url::Url = format!("udp://0.0.0.0:{}", local_addr.port())
            .parse()
            .unwrap();
        let (local_mapped_addr, local_port_mapping_lease) = upnp::resolve_udp_public_addr(
            global_ctx.clone(),
            &local_listener,
            local_socket.clone(),
        )
        .await
        .with_context(|| "failed to resolve udp public addr for cone hole punch")?;
        let lifetime_guard =
            local_port_mapping_lease.map(|lease| Arc::new(lease) as Arc<dyn Send + Sync>);

        tracing::debug!(
            ?local_mapped_addr,
            ?remote_mapped_addr,
            "hole punch got remote listener"
        );

        udp_array.add_new_socket(local_socket).await?;
        udp_array.add_intreast_tid(tid);
        let send_from_local = || async {
            for addr in std::iter::once(remote_mapped_addr.into()).chain(remote_alt_addrs.iter().copied())
            {
                udp_array
                    .send_with_all(
                        &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                        addr,
                    )
                    .await
                    .with_context(|| "failed to send hole punch packet from local")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        send_from_local().await?;

        #[cfg(feature = "mpquic")]
        let mp_alt_dest_ips = if use_mp {
            mp_alt_public_ips(
                &global_ctx.get_stun_info_collector().get_stun_info().public_ip,
                local_mapped_addr,
            )
        } else {
            Vec::new()
        };
        #[cfg(not(feature = "mpquic"))]
        let mp_alt_dest_ips = Vec::new();

        let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
            if let Err(e) = rpc_stub
                .send_punch_packet_cone(
                    BaseController {
                        timeout_ms: 4000,
                        ..Default::default()
                    },
                    SendPunchPacketConeRequest {
                        listener_mapped_addr: Some(remote_mapped_addr),
                        dest_addr: Some(local_mapped_addr.into()),
                        transaction_id: tid,
                        packet_count_per_batch: 2,
                        packet_batch_count: 5,
                        packet_interval_ms: 400,
                        use_mp,
                        requester_peer_id,
                        mp_provider: "udp-punch".into(),
                        mp_alt_dest_ips,
                    },
                )
                .await
            {
                tracing::error!(?e, "failed to call remote send punch packet");
            }
        }));

        // server: will send some punching resps, total 10 packets.
        // client: use the socket to create UdpTunnel with UdpTunnelConnector
        // NOTICE: UdpTunnelConnector will ignore the punching resp packet sent by remote.
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && punch_task.is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, send some more hole punch packets");
                send_from_local().await?;
                continue;
            };

            tracing::debug!(?socket, ?tid, "punched socket found, try connect with it");

            // The server hands its listener to MPQUIC once a punch packet from us arrives, or a
            // QUIC packet from the address we declared. When the punch left through another WAN
            // than that address (mwan3), the punch packets sent before the server's reply opened
            // its NAT were all dropped: confirm from the socket that got through. The answer may
            // also have come from another of the listener's WANs: talk to where it came from.
            let remote_addr = if use_mp {
                socket.remote_addr
            } else {
                remote_mapped_addr.into()
            };
            if use_mp {
                let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
                for _ in 0..3 {
                    socket.socket.send_to(&packet, remote_addr).await?;
                }
            }

            for _ in 0..2 {
                let outcome = finish_with_role(
                    &self.peer_mgr,
                    dst_peer_id,
                    socket.socket.clone(),
                    remote_addr,
                    use_mp,
                    UdpPunchRole::Client,
                    lifetime_guard.clone(),
                )
                .await;
                match outcome {
                    Ok(outcome) => {
                        tracing::info!("UDP hole punched transport ready");
                        return Ok(Some(outcome));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                    }
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    #[cfg(feature = "mpquic")]
    use std::time::Duration;

    #[cfg(feature = "mpquic")]
    use tokio::net::UdpSocket;

    use crate::{
        common::upnp::{
            reset_udp_port_mapping_attempts_for_test, udp_port_mapping_attempts_for_test,
        },
        connector::udp_hole_punch::{
            UdpHolePunchConnector, cone::PunchConeHoleClient,
            tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear, wait_route_appear_with_cost},
        proto::common::NatType,
    };

    #[cfg(feature = "mpquic")]
    use crate::connector::mp_path::CarrierKind;
    #[cfg(feature = "mpquic")]
    use crate::tunnel::common::tests::wait_for_condition;
    #[cfg(feature = "mpquic")]
    use crate::{
        connector::udp_hole_punch::common::HOLE_PUNCH_PACKET_BODY_LEN,
        tunnel::udp::new_hole_punch_packet,
    };

    /// mwan3 keeps the port and picks the WAN per connection: the punch goes
    /// to the declared address and to every other public IPv4 at that port.
    #[cfg(feature = "mpquic")]
    #[test]
    fn mp_cone_punch_also_targets_the_other_wans_at_the_same_port() {
        let mapped: std::net::SocketAddr = "198.18.0.12:41156".parse().unwrap();
        let public_ips = ["198.18.0.11", "198.18.0.12", "2001:db8::1", "198.18.0.13"]
            .map(String::from);
        let alt = super::mp_alt_public_ips(&public_ips, mapped);
        assert_eq!(
            super::mp_alt_dest_addrs(mapped, alt),
            ["198.18.0.11:41156", "198.18.0.13:41156"]
                .map(|addr| addr.parse::<std::net::SocketAddr>().unwrap())
        );

        let junk = ["0.0.0.0", "224.0.0.1", "198.18.0.12", "198.18.0.11", "198.18.0.11"]
            .map(|ip| ip.parse::<std::net::Ipv4Addr>().unwrap().into())
            .to_vec();
        assert_eq!(
            super::mp_alt_dest_addrs(mapped, junk),
            vec!["198.18.0.11:41156".parse::<std::net::SocketAddr>().unwrap()]
        );
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn server_handoff_waits_for_matched_raw_punch_and_uses_observed_endpoint() {
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let waiter = tokio::spawn({
            let listener = listener.clone();
            async move {
                crate::connector::udp_hole_punch::common::wait_for_hole_punch_packet(
                    &listener,
                    42,
                    Duration::from_secs(5),
                )
                .await
            }
        });
        sender
            .send_to(
                &new_hole_punch_packet(42, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                listener_addr,
            )
            .await
            .unwrap();
        let remote = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(remote, sender.local_addr().unwrap());
    }

    #[tokio::test]
    async fn hole_punching_cone() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        println!("{:?}", p_a.list_routes().await);

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run_as_client().await.unwrap();
        hole_punching_c.run_as_server().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
        println!("{:?}", p_a.list_routes().await);
    }

    #[cfg(feature = "mpquic")]
    #[rstest::rstest]
    #[case(true)]
    #[case(false)]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    async fn cone_hole_punch_registers_a_udp_carrier_in_one_mpquic_session(
        #[case] caller_is_tquic_server: bool,
    ) {
        let endpoint_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let endpoint_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let a_is_server = endpoint_a.my_peer_id() > endpoint_c.my_peer_id();
        let (p_a, p_c) = if a_is_server == caller_is_tquic_server {
            (endpoint_a, endpoint_c)
        } else {
            (endpoint_c, endpoint_a)
        };
        for peer in [&p_a, &p_c] {
            let mut flags = peer.get_global_ctx().get_flags();
            flags.mp.as_mut().unwrap().enabled = true;
            peer.get_global_ctx().set_flags(flags);
        }
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());
        hole_punching_c.run_as_server().await.unwrap();
        let data = hole_punching_a.client.data();
        let result = data.cone_client.do_hole_punching(p_c.my_peer_id()).await;
        assert!(
            data.handle_udp_transport_result(p_c.my_peer_id(), result, None, None)
                .await,
            "the loopback raw punch must attach its client carrier"
        );

        wait_for_condition(
            || async {
                p_a.get_mp_session_manager()
                    .has_live_carrier(p_c.my_peer_id(), CarrierKind::UdpPunch)
                    .await
                    && p_c
                        .get_mp_session_manager()
                        .has_live_carrier(p_a.my_peer_id(), CarrierKind::UdpPunch)
                        .await
            },
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(p_a.get_mp_session_manager().tracked_peer_count(), 1);
        assert_eq!(p_c.get_mp_session_manager().tracked_peer_count(), 1);
    }

    #[tokio::test]
    async fn cone_hole_punch_does_not_create_upnp_mapping_before_listener_rpc_succeeds() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_upnp = false;
        p_a.get_global_ctx().set_flags(flags);

        reset_udp_port_mapping_attempts_for_test();

        let ret = PunchConeHoleClient::new(p_a.clone(), Arc::new(timedmap::TimedMap::new()))
            .do_hole_punching(p_c.my_peer_id())
            .await;

        assert!(ret.is_err());
        assert_eq!(udp_port_mapping_attempts_for_test(), 0);
    }
}
