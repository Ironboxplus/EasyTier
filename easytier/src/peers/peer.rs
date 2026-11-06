use std::sync::Arc;

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use parking_lot::RwLock;

use tokio::{select, sync::mpsc};

use tracing::Instrument;

use super::{
    PacketRecvChan,
    peer_conn::{PeerConn, PeerConnId},
};
use crate::{common::shrink_dashmap, proto::api::instance::PeerConnInfo};
use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    proto::peer_rpc::PeerIdentityType,
    tunnel::packet_def::ZCPacket,
};
use tokio_util::task::AbortOnDropHandle;

type ArcPeerConn = Arc<PeerConn>;
/// The tunnel type of a relay MP carrier's EasyTier conn.
pub(crate) const RELAY_MP_TUNNEL_TYPE: &str = "mpquic_relay_next_hop";
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

fn conn_latency_sort_key(latency_us: u64, is_hole_punched: bool) -> (bool, u64) {
    (is_hole_punched && latency_us == 0, latency_us)
}

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn_id: Arc<AtomicCell<PeerConnId>>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    default_conn_id_clear_task: AbortOnDropHandle<()>,
}

impl Peer {
    pub fn new(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::new());
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());
        let peer_identity_type = Arc::new(AtomicCell::new(None));
        let peer_identity_type_copy = peer_identity_type.clone();
        let peer_public_key = Arc::new(RwLock::new(None));
        let peer_public_key_copy = peer_public_key.clone();

        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let global_ctx_copy = global_ctx.clone();
        let close_event_listener = AbortOnDropHandle::new(tokio::spawn(
            async move {
                loop {
                    select! {
                        ret = close_event_receiver.recv() => {
                            if ret.is_none() {
                                break;
                            }
                            let ret = ret.unwrap();
                            tracing::warn!(
                                ?peer_node_id,
                                ?ret,
                                "notified that peer conn is closed",
                            );

                            if let Some((_, conn)) = conns_copy.remove(&ret) {
                                global_ctx_copy.issue_event(GlobalCtxEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
                                shrink_dashmap(&conns_copy, Some(4));
                                if conns_copy.is_empty() {
                                    peer_identity_type_copy.store(None);
                                    *peer_public_key_copy.write() = None;
                                }
                            }
                        }

                        _ = shutdown_notifier_copy.notified() => {
                            close_event_receiver.close();
                            tracing::warn!(?peer_node_id, "peer close event listener notified");
                        }
                    }
                }
                tracing::info!("peer {} close event listener exit", peer_node_id);
            }
            .instrument(tracing::info_span!(
                "peer_close_event_listener",
                ?peer_node_id,
            )),
        ));

        let default_conn_id = Arc::new(AtomicCell::new(PeerConnId::default()));

        let conns_copy = conns.clone();
        let default_conn_id_copy = default_conn_id.clone();
        let default_conn_id_clear_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if conns_copy.len() > 1 {
                    default_conn_id_copy.store(PeerConnId::default());
                }
            }
        }));

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            global_ctx,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn_id,
            peer_identity_type,
            peer_public_key,
            default_conn_id_clear_task,
        }
    }

    pub async fn add_peer_conn(&self, mut conn: PeerConn) -> Result<(), Error> {
        let conn_identity_type = conn.get_peer_identity_type();
        let peer_identity_type = self.peer_identity_type.load();
        if let Some(peer_identity_type) = peer_identity_type {
            if peer_identity_type != conn_identity_type {
                return Err(Error::SecretKeyError(format!(
                    "peer identity type mismatch. peer: {:?}, conn: {:?}",
                    peer_identity_type, conn_identity_type
                )));
            }
        } else {
            self.peer_identity_type.store(Some(conn_identity_type));
        }

        let close_notifier = conn.get_close_notifier();
        let conn_info = conn.get_conn_info();
        let conn_pubkey = conn_info.noise_remote_static_pubkey.clone();
        {
            let mut peer_pubkey = self.peer_public_key.write();
            if let Some(existing_pubkey) = peer_pubkey.as_ref() {
                if existing_pubkey != &conn_pubkey {
                    return Err(Error::SecretKeyError(format!(
                        "peer public key mismatch. peer_id: {}, existing_len: {}, new_len: {}",
                        self.peer_node_id,
                        existing_pubkey.len(),
                        conn_pubkey.len()
                    )));
                }
            } else {
                *peer_pubkey = Some(conn_pubkey);
            }
        }

        conn.start_recv_loop(self.packet_recv_chan.clone()).await;
        conn.start_pingpong();
        #[cfg(feature = "mpquic")]
        let is_mpquic = conn
            .tunnel_type()
            .is_some_and(|kind| kind.starts_with("mpquic"));
        self.conns.insert(conn.get_conn_id(), Arc::new(conn));
        // `select_conn` prefers a live mpquic conn, but only when it picks
        // afresh: drop a native default right away instead of letting it
        // carry data until the periodic reset.
        #[cfg(feature = "mpquic")]
        if is_mpquic {
            self.default_conn_id.store(PeerConnId::default());
        }

        let close_event_sender = self.close_event_sender.clone();
        tokio::spawn(async move {
            let conn_id = close_notifier.get_conn_id();
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            if let Err(e) = close_event_sender.send(conn_id).await {
                tracing::warn!(?conn_id, "failed to send close event: {}", e);
            }
        });

        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerConnAdded(conn_info));
        Ok(())
    }

    async fn select_conn(&self) -> Option<ArcPeerConn> {
        let default_conn_id = self.default_conn_id.load();
        if let Some(conn) = self.conns.get(&default_conn_id)
            && (conn.is_answering() || !self.has_answering_conn_besides(&default_conn_id, false))
        {
            return Some(conn.clone());
        }

        let conn = self.pick_conn()?;
        self.default_conn_id.store(conn.get_conn_id());
        Some(conn)
    }

    /// Whether a live conn other than `conn_id` still answers pings (only
    /// non-mpquic ones when `non_mpquic_only`). A conn that stopped
    /// answering keeps its last latency, so without this check it would go
    /// on being chosen until the close rule ends it 45 s later (incident
    /// 2026-11-05: a relay kept forwarding into a stalled conn while a fresh
    /// one to the same peer sat idle).
    fn has_answering_conn_besides(&self, conn_id: &PeerConnId, non_mpquic_only: bool) -> bool {
        self.conns.iter().any(|entry| {
            entry.key() != conn_id
                && !entry.value().is_closed()
                && entry.value().is_answering()
                && (!non_mpquic_only || Self::is_live_non_mpquic_conn(entry.value()))
        })
    }

    /// The conn `select_conn` takes when no default is set.
    fn pick_conn(&self) -> Option<ArcPeerConn> {
        self.conns
            .iter()
            .min_by_key(|entry| Self::pick_key(entry.value()))
            .map(|entry| entry.value().clone())
    }

    /// Sort key of `pick_conn`, smallest first. A conn that still answers
    /// pings comes before one that does not; only when none answers does
    /// the choice fall back to the rest of the order.
    ///
    /// Within that, a live mpquic conn carries the data whenever there is one, so MP's
    /// paths, limits and queues are not bypassed by a lower-latency native tunnel to the
    /// same peer.
    ///
    /// Among the others, a zero latency on a hole-punched connection means the ping loop
    /// has not confirmed liveness yet. Prefer any other connection, so a freshly admitted
    /// hole-punched path cannot steal traffic before its first successful ping.
    fn pick_key(conn: &PeerConn) -> (bool, bool, (bool, u64)) {
        let latency_us = conn.get_stats().latency_us;
        #[cfg(feature = "mpquic")]
        let live_mpquic = !conn.is_closed() && !Self::is_live_non_mpquic_conn(conn);
        #[cfg(not(feature = "mpquic"))]
        let live_mpquic = false;
        let order = if live_mpquic {
            (false, latency_us)
        } else {
            conn_latency_sort_key(latency_us, conn.is_hole_punched())
        };
        (!conn.is_answering(), !live_mpquic, order)
    }

    /// `(latency_us, loss_rate)` of every live non-mpquic conn: how this peer
    /// does as a relay first hop. `latency_us` is 0 while no ping has been
    /// answered, and keeps its last value when later pings are all lost, so it
    /// means nothing without the loss rate.
    #[cfg(feature = "mpquic")]
    pub fn non_mpquic_link_quality(&self) -> Vec<(u64, f64)> {
        self.conns
            .iter()
            .filter(|entry| Self::is_live_non_mpquic_conn(entry.value()))
            .map(|entry| {
                let conn = entry.value();
                (conn.get_stats().latency_us, conn.loss_rate())
            })
            .collect()
    }

    fn is_live_non_mpquic_conn(conn: &PeerConn) -> bool {
        !conn.is_closed()
            && !conn
                .tunnel_type()
                .is_some_and(|kind| kind.starts_with("mpquic"))
    }

    async fn select_non_mpquic_conn(&self) -> Option<ArcPeerConn> {
        let default_conn_id = self.default_conn_id.load();
        if let Some(conn) = self.conns.get(&default_conn_id)
            && Self::is_live_non_mpquic_conn(conn.value())
            && (conn.is_answering() || !self.has_answering_conn_besides(&default_conn_id, true))
        {
            return Some(conn.clone());
        }

        self.conns
            .iter()
            .filter(|entry| Self::is_live_non_mpquic_conn(entry.value()))
            .min_by_key(|entry| {
                (
                    !entry.value().is_answering(),
                    entry.value().get_stats().latency_us,
                )
            })
            .map(|entry| entry.value().clone())
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Peer"))]
    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        let Some(conn) = self.select_conn().await else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        conn.send_msg(msg).await?;

        Ok(())
    }

    pub(crate) async fn send_msg_non_mpquic(&self, msg: ZCPacket) -> Result<(), Error> {
        let Some(conn) = self.select_non_mpquic_conn().await else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        conn.send_msg(msg).await?;

        Ok(())
    }

    pub async fn close_peer_conn(&self, conn_id: &PeerConnId) -> Result<(), Error> {
        let has_key = self.conns.contains_key(conn_id);
        if !has_key {
            return Err(Error::NotFound);
        }
        self.close_event_sender.send(*conn_id).await.unwrap();
        Ok(())
    }

    pub async fn list_peer_conns(&self) -> Vec<PeerConnInfo> {
        let mut conns = vec![];
        for conn in self.conns.iter() {
            // do not lock here, otherwise it will cause dashmap deadlock
            conns.push(conn.clone());
        }

        let mut ret = Vec::new();
        for conn in conns {
            let info = conn.get_conn_info();
            if !info.is_closed {
                ret.push(info);
            } else {
                let conn_id = info.conn_id.parse().unwrap();
                let _ = self.close_peer_conn(&conn_id).await;
            }
        }
        ret
    }

    pub fn has_live_conns(&self) -> bool {
        self.conns.iter().any(|entry| !entry.value().is_closed())
    }

    pub fn has_live_non_mpquic_conns(&self) -> bool {
        self.conns
            .iter()
            .any(|entry| Self::is_live_non_mpquic_conn(entry.value()))
    }

    /// Whether some live conn is a link of its own. A relay MP carrier is
    /// not: its datagrams ride a first hop and then the stock forwarding
    /// (`connector/mp_relay.rs`), so announcing it as a link lets that
    /// forwarding route the carrier's own datagrams back into it.
    pub fn has_live_link_conns(&self) -> bool {
        self.conns.iter().any(|entry| {
            !entry.value().is_closed()
                && entry.value().tunnel_type() != Some(RELAY_MP_TUNNEL_TYPE)
        })
    }

    pub fn has_directly_connected_conn(&self) -> bool {
        self.conns
            .iter()
            .any(|entry| !entry.value().is_closed() && !entry.value().is_hole_punched())
    }

    pub fn has_endpoint_mp_conn(&self) -> bool {
        self.conns.iter().any(|entry| {
            !entry.value().is_closed() && !Self::is_live_non_mpquic_conn(entry.value())
        })
    }

    pub fn get_directly_connections(&self) -> DashSet<uuid::Uuid> {
        self.conns
            .iter()
            .filter(|entry| !(entry.value()).is_hole_punched())
            .map(|entry| (entry.value()).get_conn_id())
            .collect()
    }

    /// The conn that carries data to this peer. The stored default is cleared every few seconds
    /// and re-picked on the next send; until then, report the conn that send would pick, so
    /// callers do not see an idle peer as having none.
    pub fn get_default_conn_id(&self) -> PeerConnId {
        let default_conn_id = self.default_conn_id.load();
        if self.conns.contains_key(&default_conn_id) {
            return default_conn_id;
        }
        self.pick_conn()
            .map(|conn| conn.get_conn_id())
            .unwrap_or(default_conn_id)
    }

    pub fn get_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.peer_identity_type.load()
    }

    pub fn get_peer_public_key(&self) -> Option<Vec<u8>> {
        self.peer_public_key.read().clone()
    }
}

// pritn on drop
impl Drop for Peer {
    fn drop(&mut self) {
        self.conns.retain(|_, conn| {
            self.global_ctx
                .issue_event(GlobalCtxEvent::PeerConnRemoved(conn.get_conn_info()));
            false
        });
        self.shutdown_notifier.notify_one();
        tracing::info!("peer {} drop", self.peer_node_id);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn measured_relay_precedes_unverified_hole_punch_path() {
        assert!(super::conn_latency_sort_key(20_000, false) < super::conn_latency_sort_key(0, true));
    }

    #[test]
    fn unmeasured_regular_connection_keeps_existing_priority() {
        assert!(super::conn_latency_sort_key(0, false) < super::conn_latency_sort_key(20_000, false));
    }

    #[test]
    fn verified_lower_latency_path_can_be_preferred() {
        assert!(super::conn_latency_sort_key(5_000, true) < super::conn_latency_sort_key(20_000, false));
    }

    use base64::prelude::{BASE64_STANDARD, Engine as _};
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tokio::time::timeout;

    use crate::{
        common::{
            PeerId,
            config::{NetworkIdentity, PeerConfig},
            global_ctx::{GlobalCtx, tests::get_mock_global_ctx},
            new_peer_id,
        },
        peers::{create_packet_recv_chan, peer_conn::PeerConn, peer_session::PeerSessionStore},
        proto::common::{SecureModeConfig, TunnelInfo},
        tunnel::{
            Tunnel,
            common::TunnelWrapper,
            ring::{RING_TUNNEL_CAP, RingSink, RingStream, RingTunnel, create_ring_tunnel_pair},
        },
    };

    use super::Peer;

    fn set_secure_mode_cfg(global_ctx: &GlobalCtx, enabled: bool) {
        if !enabled {
            global_ctx.config.set_secure_mode(None);
        } else {
            let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&private);
            global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }));
        }
    }

    fn create_typed_ring_tunnel_pair(tunnel_type: &str) -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
        let client = Arc::new(RingTunnel::new(RING_TUNNEL_CAP));
        let server = Arc::new(RingTunnel::new(RING_TUNNEL_CAP));
        let client_info = TunnelInfo {
            tunnel_type: tunnel_type.to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        };
        let server_info = TunnelInfo {
            tunnel_type: tunnel_type.to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        };
        (
            Box::new(TunnelWrapper::new(
                RingStream::new(client.clone()),
                RingSink::new(server.clone()),
                Some(client_info),
            )),
            Box::new(TunnelWrapper::new(
                RingStream::new(server),
                RingSink::new(client),
                Some(server_info),
            )),
        )
    }

    async fn handshake_pair(
        local_peer_id: PeerId,
        remote_peer_id: PeerId,
        local_ctx: Arc<GlobalCtx>,
        remote_ctx: Arc<GlobalCtx>,
        local_tunnel: Box<dyn Tunnel>,
        remote_tunnel: Box<dyn Tunnel>,
    ) -> (PeerConn, PeerConn) {
        let sessions = Arc::new(PeerSessionStore::new());
        let mut local_conn =
            PeerConn::new(local_peer_id, local_ctx, local_tunnel, sessions.clone());
        let mut remote_conn = PeerConn::new(remote_peer_id, remote_ctx, remote_tunnel, sessions);
        let (local_result, remote_result) = tokio::join!(
            local_conn.do_handshake_as_client(),
            remote_conn.do_handshake_as_server()
        );
        local_result.unwrap();
        remote_result.unwrap();
        (local_conn, remote_conn)
    }

    #[tokio::test]
    async fn relay_carrier_selector_excludes_mpquic_connections() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let local_ctx = get_mock_global_ctx();
        let remote_ctx = get_mock_global_ctx();
        let peer = Peer::new(remote_peer_id, packet_send, local_ctx.clone());

        let (ring_local, ring_remote) = create_typed_ring_tunnel_pair("ring");
        let (ring_local_conn, _ring_remote_conn) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx.clone(),
            remote_ctx.clone(),
            ring_local,
            ring_remote,
        )
        .await;

        let (mp_local, mp_remote) = create_typed_ring_tunnel_pair("mpquic_udp_punch");
        let (mp_local_conn, _mp_remote_conn) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx,
            remote_ctx,
            mp_local,
            mp_remote,
        )
        .await;

        peer.add_peer_conn(ring_local_conn).await.unwrap();
        let mp_conn_id = mp_local_conn.get_conn_id();
        peer.add_peer_conn(mp_local_conn).await.unwrap();
        peer.default_conn_id.store(mp_conn_id);

        let selected = peer.select_non_mpquic_conn().await.unwrap();
        assert_eq!(selected.tunnel_type(), Some("ring"));

        assert!(peer.has_live_non_mpquic_conns());
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn data_prefers_the_mpquic_conn_over_a_native_one() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let local_ctx = get_mock_global_ctx();
        let remote_ctx = get_mock_global_ctx();
        let peer = Peer::new(remote_peer_id, packet_send, local_ctx.clone());

        let (ring_local, ring_remote) = create_typed_ring_tunnel_pair("tcp");
        let (ring_local_conn, _ring_remote_conn) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx.clone(),
            remote_ctx.clone(),
            ring_local,
            ring_remote,
        )
        .await;
        peer.add_peer_conn(ring_local_conn).await.unwrap();
        assert_eq!(peer.select_conn().await.unwrap().tunnel_type(), Some("tcp"));

        let (mp_local, mp_remote) = create_typed_ring_tunnel_pair("mpquic_udp_punch");
        let (mp_local_conn, _mp_remote_conn) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx,
            remote_ctx,
            mp_local,
            mp_remote,
        )
        .await;
        // No wait for the periodic 5 s reset: a transfer that starts right
        // after the MP session comes up must already ride it.
        peer.add_peer_conn(mp_local_conn).await.unwrap();
        for _ in 0..3 {
            let selected = peer.select_conn().await.unwrap();
            assert_eq!(selected.tunnel_type(), Some("mpquic_udp_punch"));
        }
    }

    /// The incident 2026-11-05 relay: the conn carrying a peer's traffic
    /// stops answering pings but keeps its low latency; a fresh conn to the
    /// same peer must take over at once, not after the 45 s close rule.
    #[tokio::test]
    async fn a_conn_that_stops_answering_yields_to_one_that_answers() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let local_ctx = get_mock_global_ctx();
        let remote_ctx = get_mock_global_ctx();
        let peer = Peer::new(remote_peer_id, packet_send, local_ctx.clone());

        let mut conns = Vec::new();
        let mut far_ends = Vec::new();
        for tunnel_type in ["tcp", "udp"] {
            let (local, remote) = create_typed_ring_tunnel_pair(tunnel_type);
            let (local_conn, remote_conn) = handshake_pair(
                local_peer_id,
                remote_peer_id,
                local_ctx.clone(),
                remote_ctx.clone(),
                local,
                remote,
            )
            .await;
            conns.push(local_conn.get_conn_id());
            far_ends.push(remote_conn);
            peer.add_peer_conn(local_conn).await.unwrap();
        }
        let (stalled, fresh) = (conns[0], conns[1]);
        peer.default_conn_id.store(stalled);
        let stalled_conn = peer.conns.get(&stalled).unwrap().clone();
        stalled_conn.set_unanswered_pings_for_test(3);

        for _ in 0..3 {
            assert_eq!(peer.select_conn().await.unwrap().get_conn_id(), fresh);
            assert_eq!(peer.select_non_mpquic_conn().await.unwrap().get_conn_id(), fresh);
        }

        // With nothing else answering, the stalled conn is still the best
        // there is: keep sending on it rather than on nothing.
        peer.conns
            .get(&fresh)
            .unwrap()
            .set_unanswered_pings_for_test(5);
        peer.default_conn_id.store(stalled);
        assert_eq!(peer.select_conn().await.unwrap().get_conn_id(), stalled);
        assert_eq!(peer.select_non_mpquic_conn().await.unwrap().get_conn_id(), stalled);

        // Any answer brings it back first in line.
        peer.conns.get(&fresh).unwrap().set_unanswered_pings_for_test(0);
        assert_eq!(peer.select_conn().await.unwrap().get_conn_id(), fresh);
    }

    /// An MP session whose one direction is dead stops answering pings too:
    /// a native conn that still answers carries the data meanwhile.
    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn an_mpquic_conn_that_stops_answering_yields_to_a_native_one() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let local_ctx = get_mock_global_ctx();
        let remote_ctx = get_mock_global_ctx();
        let peer = Peer::new(remote_peer_id, packet_send, local_ctx.clone());

        let (tcp_local, tcp_remote) = create_typed_ring_tunnel_pair("tcp");
        let (tcp_conn, _tcp_far) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx.clone(),
            remote_ctx.clone(),
            tcp_local,
            tcp_remote,
        )
        .await;
        peer.add_peer_conn(tcp_conn).await.unwrap();
        let (mp_local, mp_remote) = create_typed_ring_tunnel_pair("mpquic_relay_next_hop");
        let (mp_conn, _mp_far) = handshake_pair(
            local_peer_id,
            remote_peer_id,
            local_ctx,
            remote_ctx,
            mp_local,
            mp_remote,
        )
        .await;
        let mp_conn_id = mp_conn.get_conn_id();
        peer.add_peer_conn(mp_conn).await.unwrap();
        assert_eq!(peer.select_conn().await.unwrap().get_conn_id(), mp_conn_id);

        peer.conns
            .get(&mp_conn_id)
            .unwrap()
            .set_unanswered_pings_for_test(3);
        assert_eq!(peer.select_conn().await.unwrap().tunnel_type(), Some("tcp"));
    }

    #[tokio::test]
    async fn close_peer() {
        let (local_packet_send, _local_packet_recv) = create_packet_recv_chan();
        let (remote_packet_send, _remote_packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer = Peer::new(new_peer_id(), local_packet_send, global_ctx.clone());
        let remote_peer = Peer::new(new_peer_id(), remote_packet_send, global_ctx.clone());

        let ps = Arc::new(PeerSessionStore::new());
        let (local_tunnel, remote_tunnel) = create_ring_tunnel_pair();
        let mut local_peer_conn = PeerConn::new(
            local_peer.peer_node_id,
            global_ctx.clone(),
            local_tunnel,
            ps.clone(),
        );
        let mut remote_peer_conn = PeerConn::new(
            remote_peer.peer_node_id,
            global_ctx.clone(),
            remote_tunnel,
            ps.clone(),
        );

        assert!(!local_peer_conn.handshake_done());
        assert!(!remote_peer_conn.handshake_done());

        let (a, b) = tokio::join!(
            local_peer_conn.do_handshake_as_client(),
            remote_peer_conn.do_handshake_as_server()
        );
        a.unwrap();
        b.unwrap();

        let local_conn_id = local_peer_conn.get_conn_id();

        local_peer.add_peer_conn(local_peer_conn).await.unwrap();
        remote_peer.add_peer_conn(remote_peer_conn).await.unwrap();

        assert_eq!(local_peer.list_peer_conns().await.len(), 1);
        assert_eq!(remote_peer.list_peer_conns().await.len(), 1);

        let close_handler =
            tokio::spawn(async move { local_peer.close_peer_conn(&local_conn_id).await });

        // wait for remote peer conn close
        timeout(std::time::Duration::from_secs(5), async {
            while !remote_peer.list_peer_conns().await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        println!("wait for close handler");
        close_handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_identity_type() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, global_ctx);

        let ps = Arc::new(PeerSessionStore::new());

        let (shared_client_tunnel, shared_server_tunnel) = create_ring_tunnel_pair();
        let shared_client_ctx = get_mock_global_ctx();
        let shared_server_ctx = get_mock_global_ctx();
        shared_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        shared_server_ctx
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "net2".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });
        set_secure_mode_cfg(&shared_client_ctx, true);
        set_secure_mode_cfg(&shared_server_ctx, true);
        let remote_url: url::Url = shared_client_tunnel
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        shared_client_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_public_key: Some(
                shared_server_ctx
                    .config
                    .get_secure_mode()
                    .unwrap()
                    .local_public_key
                    .unwrap(),
            ),
        }]);
        let mut shared_client_conn = PeerConn::new(
            local_peer_id,
            shared_client_ctx,
            Box::new(shared_client_tunnel),
            ps.clone(),
        );
        let mut shared_server_conn = PeerConn::new(
            remote_peer_id,
            shared_server_ctx,
            Box::new(shared_server_tunnel),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            shared_client_conn.do_handshake_as_client(),
            shared_server_conn.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();
        assert_eq!(
            shared_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::SharedNode
        );

        let (admin_client_tunnel, admin_server_tunnel) = create_ring_tunnel_pair();
        let admin_client_ctx = get_mock_global_ctx();
        let admin_server_ctx = get_mock_global_ctx();
        admin_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        admin_server_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        set_secure_mode_cfg(&admin_client_ctx, true);
        set_secure_mode_cfg(&admin_server_ctx, true);
        let mut admin_client_conn = PeerConn::new(
            local_peer_id,
            admin_client_ctx,
            Box::new(admin_client_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let mut admin_server_conn = PeerConn::new(
            remote_peer_id,
            admin_server_ctx,
            Box::new(admin_server_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            admin_client_conn.do_handshake_as_client(),
            admin_server_conn.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();
        assert_eq!(
            admin_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::Admin
        );

        peer.add_peer_conn(shared_client_conn).await.unwrap();
        let ret = peer.add_peer_conn(admin_client_conn).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_public_key() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, get_mock_global_ctx());
        let ps = Arc::new(PeerSessionStore::new());

        let (client_tunnel_1, server_tunnel_1) = create_ring_tunnel_pair();
        let client_ctx_1 = get_mock_global_ctx();
        let server_ctx_1 = get_mock_global_ctx();
        client_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_1, true);
        set_secure_mode_cfg(&server_ctx_1, true);
        let mut client_conn_1 = PeerConn::new(
            local_peer_id,
            client_ctx_1,
            Box::new(client_tunnel_1),
            ps.clone(),
        );
        let mut server_conn_1 = PeerConn::new(
            remote_peer_id,
            server_ctx_1,
            Box::new(server_tunnel_1),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            client_conn_1.do_handshake_as_client(),
            server_conn_1.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();

        let (client_tunnel_2, server_tunnel_2) = create_ring_tunnel_pair();
        let client_ctx_2 = get_mock_global_ctx();
        let server_ctx_2 = get_mock_global_ctx();
        client_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_2, true);
        set_secure_mode_cfg(&server_ctx_2, true);
        let mut client_conn_2 = PeerConn::new(
            local_peer_id,
            client_ctx_2,
            Box::new(client_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let mut server_conn_2 = PeerConn::new(
            remote_peer_id,
            server_ctx_2,
            Box::new(server_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            client_conn_2.do_handshake_as_client(),
            server_conn_2.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();

        let pubkey_1 = client_conn_1.get_conn_info().noise_remote_static_pubkey;
        let pubkey_2 = client_conn_2.get_conn_info().noise_remote_static_pubkey;
        assert_ne!(pubkey_1, pubkey_2);

        peer.add_peer_conn(client_conn_1).await.unwrap();
        assert_eq!(peer.get_peer_public_key(), Some(pubkey_1));
        let ret = peer.add_peer_conn(client_conn_2).await;
        assert!(ret.is_err());
    }
}
