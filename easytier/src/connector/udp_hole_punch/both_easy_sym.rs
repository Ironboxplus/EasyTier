use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use hotpath::instant::Instant;
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{PeerId, stun::StunInfoCollectorTrait},
    connector::{
        udp_hole_punch::{
            common::{HOLE_PUNCH_PACKET_BODY_LEN, UdpHolePunchListener},
            handle_rpc_result,
        },
        udp_hole_punch_transport::{
            FinishOutcome, UdpPunchRole, attach_new_tunnel, finish_with_role, mp_udp_punch_enabled,
        },
    },
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::udp::new_hole_punch_packet,
};

use super::common::{PunchHoleServerCommon, UdpNatType, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM: usize = 25;
const DST_PORT_OFFSET: u16 = 20;
const REMOTE_WAIT_TIME_MS: u64 = 5000;

fn transport_remote_addr(
    use_mp: bool,
    observed_remote_addr: SocketAddr,
    predicted_remote_addr: SocketAddr,
) -> SocketAddr {
    if use_mp {
        observed_remote_addr
    } else {
        predicted_remote_addr
    }
}

pub(crate) struct PunchBothEasySymHoleServer {
    common: Arc<PunchHoleServerCommon>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl PunchBothEasySymHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self {
            common,
            task: Mutex::new(None),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySymRequest,
    ) -> Result<SendPunchPacketBothEasySymResponse, rpc_types::error::Error> {
        tracing::info!("send_punch_packet_both_easy_sym start");
        let busy_resp = Ok(SendPunchPacketBothEasySymResponse {
            is_busy: true,
            ..Default::default()
        });
        let Ok(mut locked_task) = self.task.try_lock() else {
            return busy_resp;
        };
        if locked_task.is_some() && !locked_task.as_ref().unwrap().is_finished() {
            return busy_resp;
        }

        let global_ctx = self.common.get_global_ctx();
        let cur_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        tracing::info!("send_punch_packet_hard_sym start");
        let socket_count = request.udp_socket_count as usize;
        let public_ips = request
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;
        let transaction_id = request.transaction_id;

        let udp_array = UdpSocketArray::new(socket_count, self.common.get_global_ctx());
        udp_array.start().await?;
        udp_array.add_intreast_tid(transaction_id);
        let peer_mgr = self.common.get_peer_mgr();
        let mp_accepted = request.use_mp && mp_udp_punch_enabled(&global_ctx.get_flags());
        let requester_peer_id = request.requester_peer_id;
        if mp_accepted && requester_peer_id == 0 {
            return Err(
                anyhow::anyhow!("MP UDP punch request is missing requester_peer_id").into(),
            );
        }

        let punch_packet =
            new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        let mut punched = vec![];
        let common = self.common.clone();

        let task = tokio::spawn(async move {
            let mut listeners = Vec::new();
            let start_time = Instant::now();
            let wait_time_ms = request.wait_time_ms.min(8000);
            while start_time.elapsed() < Duration::from_millis(wait_time_ms as u64) {
                if let Err(e) = udp_array
                    .send_with_all(
                        &punch_packet,
                        SocketAddr::V4(SocketAddrV4::new(
                            public_ips.into(),
                            request.dst_port_num as u16,
                        )),
                    )
                    .await
                {
                    tracing::error!(?e, "failed to send hole punch packet");
                    break;
                }

                tokio::time::sleep(Duration::from_millis(100)).await;

                if let Some(s) = udp_array.try_fetch_punched_socket(transaction_id) {
                    tracing::info!(?s, ?transaction_id, "got punched socket in both easy sym");
                    if mp_accepted {
                        match finish_with_role(
                            &peer_mgr,
                            requester_peer_id,
                            s.socket,
                            s.remote_addr,
                            true,
                            UdpPunchRole::Server,
                            None,
                        )
                        .await
                        {
                            Ok(FinishOutcome::NewTunnel { tunnel, mp_role }) => {
                                if let Err(error) = attach_new_tunnel(
                                    &peer_mgr,
                                    requester_peer_id,
                                    tunnel,
                                    mp_role,
                                    UdpPunchRole::Server,
                                    false,
                                )
                                .await
                                {
                                    tracing::error!(?error, "failed to add symmetric MP tunnel");
                                }
                            }
                            Ok(FinishOutcome::PathAdded) => {}
                            Err(error) => {
                                tracing::error!(?error, "failed to register symmetric MP carrier")
                            }
                        }
                        break;
                    }
                    assert!(Arc::strong_count(&s.socket) == 1);
                    let Some(port) = s.socket.local_addr().ok().map(|addr| addr.port()) else {
                        tracing::warn!("failed to get local addr from punched socket");
                        continue;
                    };
                    let remote_addr = s.remote_addr;
                    drop(s);

                    let listener =
                        match UdpHolePunchListener::new_ext(peer_mgr.clone(), false, Some(port))
                            .await
                        {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::warn!(?e, "failed to create listener");
                                continue;
                            }
                        };
                    punched.push((listener.get_socket().await, remote_addr));
                    listeners.push(listener);
                }

                // if any listener is punched, we can break the loop
                for l in &listeners {
                    if l.get_conn_count().await > 0 {
                        tracing::info!(?l, "got punched listener");
                        break;
                    }
                }

                if !punched.is_empty() {
                    tracing::debug!(?punched, "got punched socket and keep sending punch packet");
                }

                for p in &punched {
                    let (socket, remote_addr) = p;
                    let send_remote_ret = socket.send_to(&punch_packet, remote_addr).await;
                    tracing::debug!(
                        ?send_remote_ret,
                        ?socket,
                        "send hole punch packet to punched remote"
                    );
                }
            }

            for l in listeners {
                if l.get_conn_count().await > 0 {
                    common.add_listener(l).await;
                }
            }
        });

        *locked_task = Some(AbortOnDropHandle::new(task));
        return Ok(SendPunchPacketBothEasySymResponse {
            is_busy: false,
            base_mapped_addr: Some(cur_mapped_addr.into()),
            mp_accepted,
        });
    }
}

#[derive(Debug)]
pub(crate) struct PunchBothEasySymHoleClient {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchBothEasySymHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr,
            blacklist,
        }
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        my_nat_info: UdpNatType,
        peer_nat_info: UdpNatType,
        is_busy: &mut bool,
    ) -> Result<Option<FinishOutcome>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        *is_busy = false;

        let udp_array = UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM,
            self.peer_mgr.get_global_ctx(),
        );
        udp_array.start().await?;

        let global_ctx = self.peer_mgr.get_global_ctx();
        let cur_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;
        let my_public_ip = match cur_mapped_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => {
                anyhow::bail!("ipv6 is not supported");
            }
        };
        let me_is_incremental = my_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("me_is_incremental is required"))?;
        let peer_is_incremental = peer_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("peer_is_incremental is required"))?;

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let tid = rand::random();
        udp_array.add_intreast_tid(tid);
        let request_mp = mp_udp_punch_enabled(&global_ctx.get_flags());

        let remote_ret = rpc_stub
            .send_punch_packet_both_easy_sym(
                BaseController {
                    timeout_ms: 2000,
                    ..Default::default()
                },
                SendPunchPacketBothEasySymRequest {
                    transaction_id: tid,
                    public_ip: Some(my_public_ip.into()),
                    dst_port_num: if me_is_incremental {
                        cur_mapped_addr.port().saturating_add(DST_PORT_OFFSET)
                    } else {
                        cur_mapped_addr.port().saturating_sub(DST_PORT_OFFSET)
                    } as u32,
                    udp_socket_count: UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM as u32,
                    wait_time_ms: REMOTE_WAIT_TIME_MS as u32,
                    use_mp: request_mp,
                    requester_peer_id: self.peer_mgr.my_peer_id(),
                },
            )
            .await;

        let remote_ret = handle_rpc_result(remote_ret, dst_peer_id, &self.blacklist)?;

        if remote_ret.is_busy {
            *is_busy = true;
            anyhow::bail!("remote is busy");
        }
        let use_mp = request_mp && remote_ret.mp_accepted;

        let mut remote_mapped_addr = remote_ret
            .base_mapped_addr
            .ok_or(anyhow::anyhow!("remote_mapped_addr is required"))?;

        let now = Instant::now();
        remote_mapped_addr.port = if peer_is_incremental {
            remote_mapped_addr
                .port
                .saturating_add(DST_PORT_OFFSET as u32)
        } else {
            remote_mapped_addr
                .port
                .saturating_sub(DST_PORT_OFFSET as u32)
        };
        tracing::debug!(
            ?remote_mapped_addr,
            ?remote_ret,
            "start send hole punch packet for both easy sym"
        );

        while now.elapsed().as_millis() < (REMOTE_WAIT_TIME_MS + 1000).into() {
            udp_array
                .send_with_all(
                    &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                    remote_mapped_addr.into(),
                )
                .await?;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::trace!(
                    ?remote_mapped_addr,
                    ?tid,
                    "no punched socket found, send some more hole punch packets"
                );
                continue;
            };

            tracing::info!(
                ?socket,
                ?remote_mapped_addr,
                ?tid,
                "got punched socket in both easy sym"
            );

            for _ in 0..2 {
                match finish_with_role(
                    &self.peer_mgr,
                    dst_peer_id,
                    socket.socket.clone(),
                    transport_remote_addr(use_mp, socket.remote_addr, remote_mapped_addr.into()),
                    use_mp,
                    UdpPunchRole::Client,
                    None,
                )
                .await
                {
                    Ok(outcome) => {
                        return Ok(Some(outcome));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                        continue;
                    }
                }
            }
            udp_array.add_new_socket(socket.socket).await?;
        }

        Ok(None)
    }
}

#[cfg(test)]
pub mod tests {
    use std::{
        sync::{Arc, atomic::AtomicU32},
        time::Duration,
    };

    use tokio::net::UdpSocket;

    use crate::connector::udp_hole_punch::RUN_TESTING;
    use crate::{
        connector::udp_hole_punch::{
            UdpHolePunchConnector, tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear},
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };

    #[cfg(feature = "mpquic")]
    use crate::connector::mp_path::CarrierKind;

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    async fn hole_punching_easy_sym(#[values("true", "false")] is_inc: bool) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(if is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(if !is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        // 144 + DST_PORT_OFFSET = 164
        let udp1 = Arc::new(UdpSocket::bind("0.0.0.0:40164").await.unwrap());
        // 144 - DST_PORT_OFFSET = 124
        let udp2 = Arc::new(UdpSocket::bind("0.0.0.0:40124").await.unwrap());
        let udps = [udp1, udp2];

        let counter = Arc::new(AtomicU32::new(0));

        // all these sockets should receive hole punching packet
        for udp in udps.iter().map(Arc::clone) {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = udp.recv_from(&mut buf).await.unwrap();
                println!(
                    "got predictable punch packet, {:?} {:?} {:?}",
                    len,
                    addr,
                    udp.local_addr()
                );
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }

        hole_punching_a.client.run_immediately().await;
        let udp_len = udps.len();
        wait_for_condition(
            || async { counter.load(std::sync::atomic::Ordering::Relaxed) == udp_len as u32 },
            Duration::from_secs(30),
        )
        .await;
    }

    #[cfg(feature = "mpquic")]
    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    #[ignore = "the localhost mock STUN reports predicted external ports but does not translate them to UdpSocketArray's internal sockets; run this case with the real NAT harness"]
    async fn easy_symmetric_punch_registers_a_udp_mp_carrier_on_both_ends(
        #[values("true", "false")] is_inc: bool,
    ) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(if is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(if !is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        for peer in [&p_a, &p_c] {
            let mut flags = peer.get_global_ctx().get_flags();
            flags.mp.as_mut().unwrap().enabled = true;
            peer.get_global_ctx().set_flags(flags);
        }
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();
        hole_punching_a.client.run_immediately().await;

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
            Duration::from_secs(30),
        )
        .await;
    }

    #[test]
    fn mp_upgrade_uses_the_observed_punched_remote_endpoint() {
        let observed: std::net::SocketAddr = "198.51.100.8:43123".parse().unwrap();
        let predicted: std::net::SocketAddr = "198.51.100.8:43000".parse().unwrap();

        assert_eq!(
            super::transport_remote_addr(true, observed, predicted),
            observed
        );
        assert_eq!(
            super::transport_remote_addr(false, observed, predicted),
            predicted
        );
    }
}
