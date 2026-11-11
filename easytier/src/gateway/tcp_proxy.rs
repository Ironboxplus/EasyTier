use anyhow::Context;
use cidr::Ipv4Inet;
use core::panic;
use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, mapref::entry::Entry};
use hotpath::instant::Instant;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, ipv4_checksum};
use socket2::{SockRef, TcpKeepalive};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;
use crate::common::log;
use crate::common::stats_manager::{LabelSet, LabelType, MetricName};
use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket};

use super::CidrSet;

#[cfg(feature = "smoltcp")]
use super::tokio_smoltcp::{self, Net, NetConfig, channel_device};

#[async_trait::async_trait]
pub(crate) trait NatDstConnector: Send + Sync + Clone + 'static {
    type DstStream: AsyncRead + AsyncWrite + Unpin + Send;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream>;
    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool;
    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Addr,
        real_dst_ip: &mut Ipv4Addr,
    ) -> bool;
    fn transport_type(&self) -> TcpProxyEntryTransportType;
}

#[derive(Debug, Clone)]
pub struct NatDstTcpConnector;

#[async_trait::async_trait]
impl NatDstConnector for NatDstTcpConnector {
    type DstStream = TcpStream;
    async fn connect(
        &self,
        _src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<Self::DstStream> {
        let socket = TcpSocket::new_v4()
            .inspect_err(|error| log::error!(?error, "create v4 socket failed"))?;

        let stream = timeout(Duration::from_secs(10), socket.connect(nat_dst))
            .await?
            .with_context(|| format!("connect to nat dst failed: {:?}", nat_dst))?;

        prepare_kernel_tcp_socket(&stream)?;

        Ok(stream)
    }

    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool {
        !cidr_set.is_empty() || global_ctx.enable_exit_node() || global_ctx.no_tun()
    }

    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Addr,
        real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        let is_exit_node = hdr.is_exit_node();

        if !(cidr_set.contains_v4(*ipv4, real_dst_ip)
            || is_exit_node
            || global_ctx.no_tun()
                && Some(*ipv4) == global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address))
        {
            return false;
        }

        true
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
    }
}

type NatDstEntryState = TcpProxyEntryState;

/// A flow as the peer addresses it. Two connections may share a source address, so the source
/// alone does not identify one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct NatFlowKey {
    src: SocketAddr,
    mapped_dst: SocketAddr,
}

#[derive(Debug)]
pub struct NatDstEntry {
    id: uuid::Uuid,
    src: SocketAddr,
    /// What the local listener sees as the peer: the source address with a port that is unique
    /// per flow. Packets towards the peer are matched on it, and the original port is restored.
    translated_src: SocketAddr,
    real_dst: SocketAddr,
    mapped_dst: SocketAddr,
    start_time: Instant,
    start_time_local: chrono::DateTime<chrono::Local>,
    tasks: Mutex<JoinSet<()>>,
    state: AtomicCell<NatDstEntryState>,
}

impl NatDstEntry {
    fn new(flow: NatFlowKey, translated_src: SocketAddr, real_dst: SocketAddr) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            src: flow.src,
            translated_src,
            real_dst,
            mapped_dst: flow.mapped_dst,
            start_time: Instant::now(),
            start_time_local: chrono::Local::now(),
            tasks: Mutex::new(JoinSet::new()),
            state: AtomicCell::new(NatDstEntryState::SynReceived),
        }
    }

    fn flow(&self) -> NatFlowKey {
        NatFlowKey {
            src: self.src,
            mapped_dst: self.mapped_dst,
        }
    }

    fn parse_as_pb(&self, transport_type: TcpProxyEntryTransportType) -> TcpProxyEntry {
        TcpProxyEntry {
            src: Some(self.src.into()),
            dst: Some(self.real_dst.into()),
            start_time: self.start_time_local.timestamp() as u64,
            state: self.state.load().into(),
            transport_type: transport_type.into(),
        }
    }
}

enum ProxyTcpStream {
    KernelTcpStream(TcpStream),
    #[cfg(feature = "smoltcp")]
    SmolTcpStream(tokio_smoltcp::TcpStream),
}

impl ProxyTcpStream {
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => stream.set_nodelay(nodelay).map_err(Into::into),
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(_stream) => {
                tracing::warn!("smol tcp stream set_nodelay not implemented");
                Ok(())
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
        }
    }

    pub async fn copy_bidirectional<D: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        dst: &mut D,
    ) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
        }
    }
}

#[cfg(feature = "smoltcp")]
type SmolTcpAcceptResult = Result<(tokio_smoltcp::TcpStream, SocketAddr)>;
#[cfg(feature = "smoltcp")]
struct SmolTcpListener {
    stream_tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
    stream_rx: mpsc::UnboundedReceiver<SmolTcpAcceptResult>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

#[cfg(feature = "smoltcp")]
impl SmolTcpListener {
    pub async fn new() -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "smoltcp listener".to_owned());

        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            stream_tx: tx,
            stream_rx: rx,
            tasks,
        }
    }

    pub async fn accept(&mut self) -> SmolTcpAcceptResult {
        self.stream_rx.recv().await.unwrap()
    }

    pub fn stream_tx(&self) -> mpsc::UnboundedSender<SmolTcpAcceptResult> {
        self.stream_tx.clone()
    }

    pub async fn add_listener(
        tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
        net: Arc<Mutex<Option<Net>>>,
        tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    ) {
        let locked_net = net.lock().await;
        let mut tcp = locked_net
            .as_ref()
            .unwrap()
            .tcp_bind("0.0.0.0:8899".parse().unwrap())
            .await
            .unwrap();
        tasks.lock().unwrap().spawn(async move {
            // High-RTT multipath (relay-next-hop via public relays) can need
            // well over 10s for the smoltcp SYN/ACK handshake to complete.
            let ret = timeout(Duration::from_secs(60), tcp.accept()).await;
            if let Ok(accept_ret) = ret {
                tx.send(accept_ret.map_err(|e| {
                    anyhow::anyhow!("smol tcp listener accept failed: {:?}", e).into()
                }))
                .unwrap();
            } else {
                tracing::error!("smol tcp listener accept timeout");
            }
        });
    }
}

enum ProxyTcpListener {
    KernelTcpListener(TcpListener),
    #[cfg(feature = "smoltcp")]
    SmolTcpListener(SmolTcpListener),
}

fn prepare_kernel_tcp_socket(stream: &TcpStream) -> Result<()> {
    const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(5);
    const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
    const TCP_KEEPALIVE_RETRIES: u32 = 2;

    let ka = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    #[cfg(not(target_os = "windows"))]
    let ka = ka.with_retries(TCP_KEEPALIVE_RETRIES);

    let sf = SockRef::from(&stream);
    sf.set_tcp_keepalive(&ka)?;
    if let Err(e) = sf.set_nodelay(true) {
        tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
    }

    Ok(())
}

/// Send and receive buffer of the kernel proxy entry, and of every connection
/// it accepts. The hop from the local application to this entry is on the
/// machine or its LAN: its bandwidth-delay product is near zero. Left alone,
/// the kernel grows both buffers toward its multi-megabyte maxima, and that
/// is queue the tunnel's own congestion signals cannot reach: 260-680 ms at a
/// 13 Mbit/s tunnel (MP_FIX_PHASES.md S-I1). Setting a size turns the
/// auto-tuning off (tcp(7) SO_RCVBUF; Windows likewise). 128 KiB is Linux's
/// initial `tcp_rmem`: 500 Mbit/s over a 2 ms LAN, at most 80 ms at 13 Mbit/s.
/// The sockets that connect out to the real destinations are left alone, their
/// path may be a wide-area one.
const KERNEL_ENTRY_BUFFER: u32 = 128 * 1024;

/// Set before `listen`, so window scaling is negotiated for the fixed size and
/// the accepted connections inherit it.
fn bind_kernel_entry(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_recv_buffer_size(KERNEL_ENTRY_BUFFER)?;
    socket.set_send_buffer_size(KERNEL_ENTRY_BUFFER)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

impl ProxyTcpListener {
    pub async fn accept(&mut self) -> Result<(ProxyTcpStream, SocketAddr)> {
        match self {
            Self::KernelTcpListener(listener) => {
                let (stream, addr) = listener.accept().await?;
                prepare_kernel_tcp_socket(&stream)?;
                Ok((ProxyTcpStream::KernelTcpStream(stream), addr))
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpListener(listener) => {
                let Ok((stream, src)) = listener.accept().await else {
                    return Err(anyhow::anyhow!("smol tcp listener closed").into());
                };
                tracing::info!(?src, "smol tcp listener accepted");
                Ok((ProxyTcpStream::SmolTcpStream(stream), src))
            }
        }
    }
}

type ArcNatDstEntry = Arc<NatDstEntry>;

/// What the proxy did with a packet from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerPacketAction {
    /// Rewritten for the local listener.
    Handled,
    /// Belongs to the proxy but cannot be served; nothing else may see it either.
    Drop,
    /// Not the proxy's packet.
    Pass,
}

// every flow, from its SYN until its entry is removed
type FlowMap = Arc<DashMap<NatFlowKey, ArcNatDstEntry>>;
// connections that were accepted by the local listener
type ConnSockMap = Arc<DashMap<uuid::Uuid, ArcNatDstEntry>>;
// translated peer addr to nat entry: the listener's accept and every packet responding to the peer
// find the entry here, and the response gets the entry's original ports back
type TranslatedSrcMap = Arc<DashMap<SocketAddr, ArcNatDstEntry>>;

/// The two maps an entry lives in besides `conn_map`, always updated together.
#[derive(Clone, Debug, Default)]
struct NatIndices {
    flow_map: FlowMap,
    translated_src_map: TranslatedSrcMap,
}

impl NatIndices {
    fn remove(&self, entry: &NatDstEntry) {
        self.flow_map
            .remove_if(&entry.flow(), |_, current| current.id == entry.id);
        self.translated_src_map
            .remove_if(&entry.translated_src, |_, current| current.id == entry.id);
    }
}

fn promote_proxy_entry(conn_map: &ConnSockMap, entry: ArcNatDstEntry) {
    entry.state.store(NatDstEntryState::ConnectingDst);
    assert!(conn_map.insert(entry.id, entry.clone()).is_none());
}

#[derive(Debug)]
pub struct TcpProxy<C: NatDstConnector> {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    local_port: AtomicU16,

    next_translated_port: AtomicU16,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    indices: NatIndices,
    conn_map: ConnSockMap,

    cidr_set: CidrSet,

    smoltcp_stack_sender: Option<mpsc::Sender<ZCPacket>>,
    smoltcp_stack_receiver: Arc<Mutex<Option<mpsc::Receiver<ZCPacket>>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_net: Arc<Mutex<Option<Net>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_listener_tx: std::sync::Mutex<Option<mpsc::UnboundedSender<SmolTcpAcceptResult>>>,
    enable_smoltcp: Arc<AtomicBool>,

    connector: C,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> PeerPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_peer(&self, mut packet: ZCPacket) -> Option<ZCPacket> {
        match self.try_handle_peer_packet(&mut packet).await {
            PeerPacketAction::Handled => {
                if self.is_smoltcp_enabled() {
                    let smoltcp_stack_sender = self.smoltcp_stack_sender.as_ref().unwrap();
                    if let Err(e) = smoltcp_stack_sender.try_send(packet) {
                        tracing::error!("send to smoltcp stack failed: {:?}", e);
                    }
                } else if let Some(peer_manager) = self.get_peer_manager()
                    && let Err(e) = peer_manager.get_nic_channel().send(packet).await
                {
                    tracing::error!("send to nic failed: {:?}", e);
                }
                None
            }
            PeerPacketAction::Drop => None,
            PeerPacketAction::Pass => Some(packet),
        }
    }
}

#[async_trait::async_trait]
impl<C: NatDstConnector> NicPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let Some(my_ipv4_inet) = self.get_local_inet() else {
            return false;
        };
        let my_ipv4 = my_ipv4_inet.address();

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_source() != my_ipv4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        if tcp_packet.get_source() != self.get_local_port() {
            return false;
        }

        let mut dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));
        let mut need_transform_dst = false;

        // for kcp proxy, the src ip of nat entry will be converted from my ip to fake ip
        // here we need to convert it back
        if !self.is_smoltcp_enabled() && dst_addr.ip() == Self::get_fake_local_ipv4(&my_ipv4_inet) {
            dst_addr.set_ip(IpAddr::V4(my_ipv4));
            need_transform_dst = true;
        }

        tracing::trace!(dst_addr = ?dst_addr, "tcp packet try find entry");
        let Some(nat_entry) = self
            .indices
            .translated_src_map
            .get(&dst_addr)
            .map(|entry| entry.clone())
        else {
            return false;
        };
        assert_eq!(nat_entry.translated_src, dst_addr);

        let IpAddr::V4(ip) = nat_entry.mapped_dst.ip() else {
            panic!("v4 nat entry src ip is not v4");
        };

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_no_proxy(true);
        if need_transform_dst {
            zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.get_my_peer_id().into();
        }

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload()).unwrap();
        ip_packet.set_source(ip);
        if need_transform_dst {
            ip_packet.set_destination(my_ipv4);
        }
        let dst = ip_packet.get_destination();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(nat_entry.real_dst.port());
        tcp_packet.set_destination(nat_entry.src.port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &ip, &dst);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(dst_addr = ?dst_addr, nat_entry = ?nat_entry, packet = ?ip_packet, "tcp packet after modified");

        true
    }
}

impl<C: NatDstConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C) -> Arc<Self> {
        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);
        let global_ctx = peer_manager.get_global_ctx();

        Arc::new(Self {
            global_ctx: global_ctx.clone(),
            peer_manager: Arc::downgrade(&peer_manager),

            local_port: AtomicU16::new(0),
            next_translated_port: AtomicU16::new(1),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),

            indices: NatIndices::default(),
            conn_map: Arc::new(DashMap::new()),

            cidr_set: CidrSet::new(global_ctx),

            smoltcp_stack_sender: Some(smoltcp_stack_sender),
            smoltcp_stack_receiver: Arc::new(Mutex::new(Some(smoltcp_stack_receiver))),

            #[cfg(feature = "smoltcp")]
            smoltcp_net: Arc::new(Mutex::new(None)),
            #[cfg(feature = "smoltcp")]
            smoltcp_listener_tx: std::sync::Mutex::new(None),

            enable_smoltcp: Arc::new(AtomicBool::new(true)),

            connector,
        })
    }

    pub fn get_peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.upgrade()
    }

    fn update_tcp_packet_checksum(
        tcp_packet: &mut MutableTcpPacket,
        ipv4_src: &Ipv4Addr,
        ipv4_dst: &Ipv4Addr,
    ) {
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.to_immutable(),
            ipv4_src,
            ipv4_dst,
        ));
    }

    fn update_ip_packet_checksum(ip_packet: &mut MutableIpv4Packet) {
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
    }

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.run_syn_map_cleaner().await?;
        self.run_listener().await?;
        if add_pipeline {
            let peer_manager = self
                .get_peer_manager()
                .ok_or_else(|| anyhow::anyhow!("peer manager is gone"))?;
            peer_manager
                .add_packet_process_pipeline(Box::new(self.clone()))
                .await;
            peer_manager
                .add_nic_packet_process_pipeline(Box::new(self.clone()))
                .await;
        }
        join_joinset_background(self.tasks.clone(), "TcpProxy".to_owned());

        Ok(())
    }

    async fn run_syn_map_cleaner(&self) -> Result<()> {
        let indices = self.indices.clone();
        let tasks = self.tasks.clone();
        let syn_map_cleaner_task = async move {
            loop {
                // Only a flow that was never accepted can expire here; an accepted one is
                // removed when its connection ends.
                indices.flow_map.retain(|_, entry| {
                    let expired = entry.start_time.elapsed() > Duration::from_secs(30)
                        && entry
                            .state
                            .compare_exchange(
                                NatDstEntryState::SynReceived,
                                NatDstEntryState::Closed,
                            )
                            .is_ok();
                    if expired {
                        tracing::warn!(entry = ?entry, "syn nat entry expired");
                        indices
                            .translated_src_map
                            .remove_if(&entry.translated_src, |_, current| current.id == entry.id);
                    }
                    !expired
                });
                indices.flow_map.shrink_to_fit();
                indices.translated_src_map.shrink_to_fit();
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        };
        tasks.lock().unwrap().spawn(syn_map_cleaner_task);

        Ok(())
    }

    async fn get_proxy_listener(&self) -> Result<ProxyTcpListener> {
        #[cfg(feature = "smoltcp")]
        if self.global_ctx.get_flags().use_smoltcp
            || self.global_ctx.no_tun()
            || cfg!(any(
                target_os = "android",
                any(
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne")
                ),
                target_env = "ohos"
            ))
        {
            // use smoltcp network stack

            use crate::gateway::tokio_smoltcp::BufferSize;
            self.local_port
                .store(8899, std::sync::atomic::Ordering::Relaxed);

            let mut cap = smoltcp::phy::DeviceCapabilities::default();
            cap.max_transmission_unit = 1280;
            cap.medium = smoltcp::phy::Medium::Ip;
            let (dev, stack_sink, mut stack_stream) = channel_device::ChannelDevice::new(cap);

            let mut smoltcp_stack_receiver =
                self.smoltcp_stack_receiver.lock().await.take().unwrap();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(packet) = smoltcp_stack_receiver.recv().await {
                    tracing::trace!(?packet, "receive from peer send to smoltcp packet");
                    if let Err(e) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                        tracing::error!("send to smoltcp stack failed: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack sink exited");
            });

            let peer_mgr = self.peer_manager.clone();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(data) = stack_stream.recv().await {
                    tracing::trace!(
                        ?data,
                        "receive from smoltcp stack and send to peer mgr packet"
                    );
                    let Some(ipv4) = Ipv4Packet::new(&data) else {
                        tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                        continue;
                    };

                    let dst = ipv4.get_destination();
                    let packet = ZCPacket::new_with_payload(&data);
                    let Some(peer_mgr) = peer_mgr.upgrade() else {
                        tracing::warn!("peer manager is gone, smoltcp sender exited");
                        return;
                    };
                    if let Err(e) = peer_mgr
                        .send_msg_by_ip(packet, IpAddr::V4(dst), false)
                        .await
                    {
                        tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack stream exited");
            });

            let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
            let net = Net::new(
                dev,
                NetConfig::new(
                    interface_config,
                    format!("{}/24", self.get_local_ip().unwrap())
                        .parse()
                        .unwrap(),
                    vec![format!("{}", self.get_local_ip().unwrap()).parse().unwrap()],
                    Some(BufferSize {
                        tcp_rx_size: 1024 * 16,
                        tcp_tx_size: 1024 * 16,
                        ..Default::default()
                    }),
                ),
            );
            net.set_any_ip(true);
            self.smoltcp_net.lock().await.replace(net);
            let tcp = SmolTcpListener::new().await;
            self.smoltcp_listener_tx
                .lock()
                .unwrap()
                .replace(tcp.stream_tx());

            self.enable_smoltcp
                .store(true, std::sync::atomic::Ordering::Relaxed);

            return Ok(ProxyTcpListener::SmolTcpListener(tcp));
        }

        {
            // use kernel network stack
            let listen_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            let net_ns = self.global_ctx.net_ns.clone();
            let tcp_listener = net_ns
                .run_async(|| async { bind_kernel_entry(listen_addr) })
                .await?;
            self.local_port.store(
                tcp_listener.local_addr()?.port(),
                std::sync::atomic::Ordering::Relaxed,
            );

            self.enable_smoltcp
                .store(false, std::sync::atomic::Ordering::Relaxed);

            Ok(ProxyTcpListener::KernelTcpListener(tcp_listener))
        }
    }

    async fn run_listener(&self) -> Result<()> {
        // bind on both v4 & v6
        let mut tcp_listener = self.get_proxy_listener().await?;

        let global_ctx = self.global_ctx.clone();
        let tasks = Arc::downgrade(&self.tasks);
        let indices = self.indices.clone();
        let conn_map = self.conn_map.clone();
        let connector = self.connector.clone();
        let accept_task = async move {
            let conn_map = conn_map.clone();
            loop {
                let accept_ret = tcp_listener.accept().await;
                let Ok((tcp_stream, mut socket_addr)) = accept_ret else {
                    tracing::error!("nat tcp listener accept failed: {:?}", accept_ret.err());
                    continue;
                };

                let my_ip_inet = global_ctx.get_ipv4();
                let my_ip = my_ip_inet
                    .as_ref()
                    .map(Ipv4Inet::address)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);

                if my_ip_inet.is_some()
                    && socket_addr.ip() == Self::get_fake_local_ipv4(&my_ip_inet.unwrap())
                {
                    socket_addr.set_ip(IpAddr::V4(my_ip));
                }

                let Some(entry_clone) = indices
                    .translated_src_map
                    .get(&socket_addr)
                    .map(|entry| entry.clone())
                else {
                    tracing::error!(
                        ?my_ip,
                        ?socket_addr,
                        "tcp connection from unknown source, ignore it"
                    );
                    continue;
                };
                tracing::info!(
                    ?socket_addr,
                    "tcp connection accepted for proxy, nat dst: {:?}",
                    entry_clone.real_dst
                );
                // The cleaner may have expired the entry while the connection was in flight.
                if entry_clone
                    .state
                    .compare_exchange(
                        NatDstEntryState::SynReceived,
                        NatDstEntryState::ConnectingDst,
                    )
                    .is_err()
                {
                    tracing::warn!(
                        ?socket_addr,
                        state = ?entry_clone.state.load(),
                        "tcp connection for a flow that is no longer waiting, ignore it"
                    );
                    if entry_clone.state.load() == NatDstEntryState::Closed {
                        indices.remove(&entry_clone);
                    }
                    continue;
                }
                promote_proxy_entry(&conn_map, entry_clone.clone());

                let Some(tasks) = tasks.upgrade() else {
                    tracing::error!("tcp proxy tasks is dropped, exit accept loop");
                    break;
                };

                tasks.lock().unwrap().spawn(Self::connect_to_nat_dst(
                    connector.clone(),
                    global_ctx.clone(),
                    tcp_stream,
                    conn_map.clone(),
                    indices.clone(),
                    entry_clone,
                ));
            }
        };
        self.tasks
            .lock()
            .unwrap()
            .spawn(accept_task.instrument(tracing::info_span!("tcp_proxy_listener")));

        Ok(())
    }

    fn remove_entry_from_all_conn_map(
        conn_map: ConnSockMap,
        indices: NatIndices,
        nat_entry: ArcNatDstEntry,
    ) {
        conn_map.remove(&nat_entry.id);
        indices.remove(&nat_entry);
        if conn_map.capacity() - conn_map.len() > 16 {
            conn_map.shrink_to_fit();
        }
        if indices.flow_map.capacity() - indices.flow_map.len() > 16 {
            indices.flow_map.shrink_to_fit();
        }
        if indices.translated_src_map.capacity() - indices.translated_src_map.len() > 16 {
            indices.translated_src_map.shrink_to_fit();
        }
    }

    async fn connect_to_nat_dst(
        connector: C,
        global_ctx: ArcGlobalCtx,
        src_tcp_stream: ProxyTcpStream,
        conn_map: ConnSockMap,
        indices: NatIndices,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        if global_ctx.should_deny_proxy(&nat_entry.real_dst, false) {
            tracing::error!(
                ?nat_entry,
                "nat dst port {} is in running listeners, ignore it",
                nat_entry.real_dst.port()
            );
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, indices, nat_entry);
            return;
        }

        let nat_dst = if global_ctx.is_ip_local_virtual_ip(&nat_entry.real_dst.ip()) {
            format!("127.0.0.1:{}", nat_entry.real_dst.port())
                .parse()
                .unwrap()
        } else {
            nat_entry.real_dst
        };

        global_ctx
            .stats_manager()
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(
                        connector.transport_type().as_str_name().to_string(),
                    ))
                    .with_label_type(LabelType::DstIp(nat_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(
                        nat_entry.mapped_dst.ip().to_string(),
                    )),
            )
            .inc();

        let _guard = global_ctx.net_ns.guard();
        let Ok(dst_tcp_stream) = connector.connect(nat_entry.src, nat_dst).await else {
            tracing::error!("connect to dst failed: {:?}", nat_entry);
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, indices, nat_entry);
            return;
        };
        drop(_guard);

        tracing::info!(?nat_entry, ?nat_dst, "tcp connection to dst established");

        assert_eq!(nat_entry.state.load(), NatDstEntryState::ConnectingDst);
        nat_entry.state.store(NatDstEntryState::Connected);

        Self::handle_nat_connection(
            src_tcp_stream,
            dst_tcp_stream,
            conn_map,
            indices,
            nat_entry,
        )
        .await;
    }

    async fn handle_nat_connection(
        mut src_tcp_stream: ProxyTcpStream,
        mut dst_tcp_stream: C::DstStream,
        conn_map: ConnSockMap,
        indices: NatIndices,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        nat_entry.tasks.lock().await.spawn(async move {
            let ret = src_tcp_stream.copy_bidirectional(&mut dst_tcp_stream).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");

            nat_entry_clone.state.store(NatDstEntryState::ClosingSrc);
            let ret = timeout(Duration::from_secs(10), src_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "src tcp stream shutdown");

            nat_entry_clone.state.store(NatDstEntryState::ClosingDst);
            let ret = timeout(Duration::from_secs(10), dst_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "dst tcp stream shutdown");

            drop(src_tcp_stream);
            drop(dst_tcp_stream);

            nat_entry_clone.state.store(NatDstEntryState::Closed);
            // sleep later so the fin packet can be processed
            tokio::time::sleep(Duration::from_secs(10)).await;

            Self::remove_entry_from_all_conn_map(conn_map, indices, nat_entry_clone);
        });
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_my_peer_id(&self) -> u32 {
        self.peer_manager
            .upgrade()
            .map(|pm| pm.my_peer_id())
            .unwrap_or_default()
    }

    pub fn get_local_ip(&self) -> Option<Ipv4Addr> {
        self.get_local_inet().map(|inet| inet.address())
    }

    pub fn get_local_inet(&self) -> Option<Ipv4Inet> {
        if self.is_smoltcp_enabled() {
            Some(Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24).unwrap())
        } else {
            self.global_ctx.get_ipv4().as_ref().cloned()
        }
    }

    pub fn get_global_ctx(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn is_smoltcp_enabled(&self) -> bool {
        self.enable_smoltcp
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_fake_local_ipv4(local_ip: &Ipv4Inet) -> Ipv4Addr {
        local_ip.first_address()
    }

    async fn try_handle_peer_packet(&self, packet: &mut ZCPacket) -> PeerPacketAction {
        if !self
            .connector
            .check_packet_from_peer_fast(&self.cidr_set, &self.global_ctx)
        {
            return PeerPacketAction::Pass;
        }

        let Some(ipv4_inet) = self.get_local_inet() else {
            return PeerPacketAction::Pass;
        };
        let ipv4_addr = ipv4_inet.address();
        {
            let hdr = packet.peer_manager_header().unwrap();
            if (hdr.packet_type != PacketType::Data as u8
                && hdr.packet_type != PacketType::DataWithKcpSrcModified as u8
                && hdr.packet_type != PacketType::DataWithQuicSrcModified as u8)
                || hdr.is_no_proxy()
            {
                return PeerPacketAction::Pass;
            };
        }

        let origin_ip = {
            let payload_bytes = packet.mut_payload();
            let Some(ipv4) = Ipv4Packet::new(payload_bytes) else {
                return PeerPacketAction::Pass;
            };
            if ipv4.get_version() != 4
                || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
            {
                return PeerPacketAction::Pass;
            }

            ipv4.get_destination()
        };
        let mut real_dst_ip = origin_ip;
        let hdr = packet.mut_peer_manager_header().unwrap();

        if !self.connector.check_packet_from_peer(
            &self.cidr_set,
            &self.global_ctx,
            hdr,
            &origin_ip,
            &mut real_dst_ip,
        ) {
            return PeerPacketAction::Pass;
        }

        // restore to data packet
        hdr.packet_type = PacketType::Data as u8;

        tracing::trace!(ipv4 = ?origin_ip, cidr_set = ?self.cidr_set, "proxy tcp packet received");

        let payload_bytes = packet.mut_payload();
        let ip_packet = Ipv4Packet::new(payload_bytes).unwrap();
        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

        let source_ip = ip_packet.get_source();
        let source_port = tcp_packet.get_source();
        let src = SocketAddr::V4(SocketAddrV4::new(source_ip, source_port));
        let dest_ip = ip_packet.get_destination();
        let dest_port = tcp_packet.get_destination();
        let flow = NatFlowKey {
            src,
            mapped_dst: SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port)),
        };

        let is_tcp_syn = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0;
        let is_tcp_ack = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::ACK != 0;
        let nat_entry = if is_tcp_syn && !is_tcp_ack {
            let real_dst = SocketAddr::V4(SocketAddrV4::new(real_dst_ip, dest_port));
            let Some((entry, new_syn)) = self.entry_for_syn(flow, real_dst) else {
                tracing::error!(?flow, "tcp proxy translated source ports exhausted");
                // Not passed on either: the host stack would answer it, not the proxy.
                return PeerPacketAction::Drop;
            };
            if new_syn {
                tracing::info!(
                    ?src,
                    translated_src = ?entry.translated_src,
                    ?real_dst,
                    mapped_dst = ?entry.mapped_dst,
                    "tcp syn received"
                );
            }

            // if smoltcp is enabled, add the listener to the net
            #[cfg(feature = "smoltcp")]
            if new_syn && self.is_smoltcp_enabled() {
                let smoltcp_listener_tx = self.smoltcp_listener_tx.lock().unwrap().clone().unwrap();
                SmolTcpListener::add_listener(
                    smoltcp_listener_tx,
                    self.smoltcp_net.clone(),
                    self.tasks.clone(),
                )
                .await;
                tracing::info!("smol tcp listener added for src: {:?}", src);
            }
            entry
        } else if let Some(entry) = self.indices.flow_map.get(&flow) {
            entry.clone()
        } else {
            // not a flow of this proxy, may forwarding n2n packet
            return PeerPacketAction::Pass;
        };

        let mut ip_packet = MutableIpv4Packet::new(payload_bytes).unwrap();
        if !self.is_smoltcp_enabled() && source_ip == ipv4_addr {
            // modify the source so the response packet can be handled by tun device
            ip_packet.set_source(Self::get_fake_local_ipv4(&ipv4_inet));
        }
        ip_packet.set_destination(ipv4_addr);
        let source = ip_packet.get_source();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(nat_entry.translated_src.port());
        tcp_packet.set_destination(self.get_local_port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &source, &ipv4_addr);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(?source, ?ipv4_addr, ?packet, "tcp packet after modified");

        PeerPacketAction::Handled
    }

    /// The entry of the flow, created by its SYN. A flow whose connection is already ending gets
    /// a new entry, so a reused source port never inherits the old one's state.
    fn entry_for_syn(
        &self,
        flow: NatFlowKey,
        real_dst: SocketAddr,
    ) -> Option<(ArcNatDstEntry, bool)> {
        match self.indices.flow_map.entry(flow) {
            Entry::Occupied(mut slot) => {
                let entry = slot.get();
                if !matches!(
                    entry.state.load(),
                    NatDstEntryState::ClosingSrc
                        | NatDstEntryState::ClosingDst
                        | NatDstEntryState::Closed
                ) {
                    return Some((entry.clone(), false));
                }
                let entry = self.allocate_entry(flow, real_dst)?;
                slot.insert(entry.clone());
                Some((entry, true))
            }
            Entry::Vacant(slot) => {
                let entry = self.allocate_entry(flow, real_dst)?;
                slot.insert(entry.clone());
                Some((entry, true))
            }
        }
    }

    /// A new entry under a source port nobody else of this source address holds, never the
    /// listener's own port. `None` when all 65535 are taken.
    fn allocate_entry(&self, flow: NatFlowKey, real_dst: SocketAddr) -> Option<ArcNatDstEntry> {
        let local_port = self.get_local_port();
        for _ in 0..u16::MAX {
            let translated_port = self
                .next_translated_port
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |port| Some(if port == u16::MAX { 1 } else { port + 1 }),
                )
                .expect("translated port counter update cannot fail");
            if translated_port == local_port {
                continue;
            }
            let translated_src = SocketAddr::new(flow.src.ip(), translated_port);
            let Entry::Vacant(slot) = self.indices.translated_src_map.entry(translated_src) else {
                continue;
            };
            let entry = Arc::new(NatDstEntry::new(flow, translated_src, real_dst));
            slot.insert(entry.clone());
            return Some(entry);
        }
        None
    }

    /// Whether a packet of the flow from this source to this destination belongs to a proxied
    /// connection.
    pub fn is_tcp_proxy_flow(&self, src: SocketAddr, mapped_dst: SocketAddr) -> bool {
        self.indices
            .flow_map
            .contains_key(&NatFlowKey { src, mapped_dst })
    }

    pub fn list_proxy_entries(&self) -> Vec<TcpProxyEntry> {
        let mut entries: Vec<TcpProxyEntry> = Vec::new();
        let transport_type = self.connector.transport_type();
        for entry in self.indices.flow_map.iter() {
            // an accepted flow is listed from `conn_map`
            if entry.state.load() == NatDstEntryState::SynReceived {
                entries.push(entry.value().as_ref().parse_as_pb(transport_type));
            }
        }
        for entry in self.conn_map.iter() {
            entries.push(entry.value().as_ref().parse_as_pb(transport_type));
        }
        entries
    }

    pub fn get_transport_type(&self) -> TcpProxyEntryTransportType {
        self.connector.transport_type()
    }
}

#[derive(Clone)]
pub struct TcpProxyRpcService<C: NatDstConnector> {
    tcp_proxy: Weak<TcpProxy<C>>,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> TcpProxyRpc for TcpProxyRpcService<C> {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.tcp_proxy.upgrade() {
            reply.entries = tcp_proxy.list_proxy_entries();
        }
        Ok(reply)
    }
}

impl<C: NatDstConnector> TcpProxyRpcService<C> {
    pub fn new(tcp_proxy: Arc<TcpProxy<C>>) -> Self {
        Self {
            tcp_proxy: Arc::downgrade(&tcp_proxy),
        }
    }
}

#[cfg(test)]
mod kernel_entry_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn accepting_a_proxy_connection_never_loses_its_packet_mapping() {
        let indices = NatIndices::default();
        let all = ConnSockMap::default();
        let (tx, rx) = std::sync::mpsc::sync_channel::<(NatFlowKey, SocketAddr, Arc<AtomicBool>)>(0);
        std::thread::scope(|scope| {
            let indices = &indices;
            let all = &all;
            scope.spawn(move || {
                for i in 1..=10_000 {
                    let src = SocketAddr::from(([127, 0, 0, 1], i));
                    let dst = "192.0.2.1:443".parse().unwrap();
                    let flow = NatFlowKey { src, mapped_dst: dst };
                    let entry = Arc::new(NatDstEntry::new(flow, src, dst));
                    indices.flow_map.insert(flow, entry.clone());
                    indices.translated_src_map.insert(src, entry.clone());
                    let done = Arc::new(AtomicBool::new(false));
                    if tx.send((flow, src, done.clone())).is_err() { return; }
                    promote_proxy_entry(all, entry);
                    done.store(true, std::sync::atomic::Ordering::Release);
                }
            });
            for (flow, translated_src, done) in rx {
                loop {
                    assert!(indices.flow_map.contains_key(&flow)
                        && indices.translated_src_map.contains_key(&translated_src),
                        "an accepted connection's packet escaped the proxy during promotion");
                    if done.load(std::sync::atomic::Ordering::Acquire) { break; }
                    std::hint::spin_loop();
                }
            }
        });
    }

    /// Receive and send buffer sizes of `stream`, as the kernel reports them.
    fn buffers(stream: &TcpStream) -> (usize, usize) {
        let socket = SockRef::from(stream);
        (
            socket.recv_buffer_size().unwrap(),
            socket.send_buffer_size().unwrap(),
        )
    }

    /// Moves `bytes` through a loopback connection to `listener`'s accepted
    /// socket, with the reader draining as fast as it can, and returns the
    /// accepted socket's buffer sizes afterwards.
    async fn buffers_after_bulk_transfer(listener: TcpListener, bytes: usize) -> (usize, usize) {
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let chunk = vec![0u8; 64 * 1024];
            let mut sent = 0;
            while sent < bytes {
                client.write_all(&chunk).await.unwrap();
                sent += chunk.len();
            }
        });
        let (mut accepted, _) = listener.accept().await.unwrap();
        let mut sink = vec![0u8; 256 * 1024];
        let mut received = 0;
        while received < bytes {
            let n = accepted.read(&mut sink).await.unwrap();
            assert!(n > 0, "connection closed early");
            received += n;
        }
        writer.await.unwrap();
        buffers(&accepted)
    }

    /// The kernel proxy entry keeps its connections' buffers where it set
    /// them. A plain listener's connections grow theirs during a bulk
    /// transfer, which is the queue this entry must not add.
    #[tokio::test]
    async fn kernel_entry_connections_keep_a_fixed_buffer() {
        const BULK: usize = 64 * 1024 * 1024;
        let entry = bind_kernel_entry("127.0.0.1:0".parse().unwrap()).unwrap();
        let (recv, send) = buffers_after_bulk_transfer(entry, BULK).await;
        // Linux reports twice the value set (it reserves room for overhead);
        // other systems report it as set.
        let fixed = KERNEL_ENTRY_BUFFER as usize;
        assert!(
            (fixed..=2 * fixed).contains(&recv) && (fixed..=2 * fixed).contains(&send),
            "recv {recv} send {send} after {BULK} bytes"
        );

        // The control: without the fixed size the same transfer is not capped.
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (recv, send) = buffers_after_bulk_transfer(plain, BULK).await;
        assert!(
            recv > 2 * fixed || send > 2 * fixed,
            "the control did not grow: recv {recv} send {send}; the test proves nothing here"
        );
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::peers::tests::create_mock_peer_manager;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    /// Admits every packet and never reaches a destination; the tests only look at the NAT
    /// table and at the packets it rewrites.
    #[derive(Clone)]
    struct AllowAll;

    #[async_trait::async_trait]
    impl NatDstConnector for AllowAll {
        type DstStream = tokio::io::DuplexStream;

        async fn connect(&self, _: SocketAddr, _: SocketAddr) -> anyhow::Result<Self::DstStream> {
            anyhow::bail!("not used")
        }

        fn check_packet_from_peer_fast(&self, _: &CidrSet, _: &GlobalCtx) -> bool {
            true
        }

        fn check_packet_from_peer(
            &self,
            _: &CidrSet,
            _: &GlobalCtx,
            _: &PeerManagerHeader,
            _: &Ipv4Addr,
            _: &mut Ipv4Addr,
        ) -> bool {
            true
        }

        fn transport_type(&self) -> TcpProxyEntryTransportType {
            TcpProxyEntryTransportType::Tcp
        }
    }

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 144, 144, 2);
    const LOCAL_PORT: u16 = 8899;

    async fn kernel_proxy() -> (Arc<PeerManager>, Arc<TcpProxy<AllowAll>>) {
        let peer_manager = create_mock_peer_manager().await;
        peer_manager
            .get_global_ctx()
            .set_ipv4(Some(Ipv4Inet::new(LOCAL_IP, 24).unwrap()));
        let proxy = TcpProxy::new(peer_manager.clone(), AllowAll);
        proxy.local_port.store(LOCAL_PORT, Ordering::Relaxed);
        proxy.enable_smoltcp.store(false, Ordering::Relaxed);
        (peer_manager, proxy)
    }

    fn tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, flags: u16) -> ZCPacket {
        let mut buf = vec![0u8; 40];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(*src.ip());
            ip.set_destination(*dst.ip());
            let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
            tcp.set_source(src.port());
            tcp.set_destination(dst.port());
            tcp.set_data_offset(5);
            tcp.set_window(1000);
            tcp.set_flags(flags as _);
        }
        let mut packet = ZCPacket::new_with_payload(&buf);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn addrs(packet: &ZCPacket) -> (SocketAddrV4, SocketAddrV4) {
        let ip = Ipv4Packet::new(packet.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        (
            SocketAddrV4::new(ip.get_source(), tcp.get_source()),
            SocketAddrV4::new(ip.get_destination(), tcp.get_destination()),
        )
    }

    const SYN: u16 = pnet::packet::tcp::TcpFlags::SYN as u16;
    const ACK: u16 = pnet::packet::tcp::TcpFlags::ACK as u16;
    const SYN_ACK: u16 = SYN | ACK;

    /// Sends a SYN of the flow through the proxy as a peer's packet and returns what the local
    /// listener would see: the source address of the rewritten packet.
    async fn syn_from_peer(
        proxy: &TcpProxy<AllowAll>,
        src: SocketAddrV4,
        dst: SocketAddrV4,
    ) -> SocketAddrV4 {
        let mut syn = tcp_packet(src, dst, SYN);
        assert_eq!(
            proxy.try_handle_peer_packet(&mut syn).await,
            PeerPacketAction::Handled
        );
        let (seen_src, seen_dst) = addrs(&syn);
        assert_eq!(seen_dst, SocketAddrV4::new(LOCAL_IP, LOCAL_PORT));
        seen_src
    }

    /// The local listener answers `to`; returns the packet as the proxy sends it back.
    async fn reply_from_listener(
        proxy: &TcpProxy<AllowAll>,
        to: SocketAddrV4,
    ) -> (SocketAddrV4, SocketAddrV4) {
        let mut reply = tcp_packet(SocketAddrV4::new(LOCAL_IP, LOCAL_PORT), to, SYN_ACK);
        let handled = proxy.try_process_packet_from_nic(&mut reply).await;
        assert!(handled, "the reply of a tracked flow must be rewritten");
        addrs(&reply)
    }

    #[tokio::test]
    async fn flows_sharing_a_source_port_are_tracked_apart() {
        let (_pm, proxy) = kernel_proxy().await;
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 144, 144, 9), 5000);
        let dst_a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
        let dst_b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 8080);

        let seen_a = syn_from_peer(&proxy, src, dst_a).await;
        let seen_b = syn_from_peer(&proxy, src, dst_b).await;

        assert_ne!(
            seen_a, seen_b,
            "the listener cannot tell two flows apart by a shared source address"
        );
        assert_eq!(proxy.list_proxy_entries().len(), 2);

        // Each reply goes back to its own flow: the source's original port, the server's own
        // address and port.
        assert_eq!(reply_from_listener(&proxy, seen_a).await, (dst_a, src));
        assert_eq!(reply_from_listener(&proxy, seen_b).await, (dst_b, src));
    }

    #[tokio::test]
    async fn a_retransmitted_syn_keeps_its_flow() {
        let (_pm, proxy) = kernel_proxy().await;
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 144, 144, 9), 5000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);

        let first = syn_from_peer(&proxy, src, dst).await;
        let second = syn_from_peer(&proxy, src, dst).await;

        assert_eq!(first, second);
        assert_eq!(proxy.list_proxy_entries().len(), 1);
    }

    fn flow(src_port: u16) -> NatFlowKey {
        NatFlowKey {
            src: SocketAddr::from(([10, 144, 144, 9], src_port)),
            mapped_dst: SocketAddr::from(([192, 0, 2, 1], 80)),
        }
    }

    #[tokio::test]
    async fn translated_ports_skip_the_listener_port_and_wrap() {
        let (_pm, proxy) = kernel_proxy().await;
        let dst = SocketAddr::from(([192, 0, 2, 1], 80));
        proxy.local_port.store(5, Ordering::Relaxed);
        proxy.next_translated_port.store(u16::MAX - 1, Ordering::Relaxed);

        let ports: Vec<u16> = (0..6)
            .map(|i| {
                proxy
                    .allocate_entry(flow(1000 + i), dst)
                    .unwrap()
                    .translated_src
                    .port()
            })
            .collect();

        // 65534, 65535, then around to 1, 2, 3, 4 and past the listener's 5 would be 6
        assert_eq!(ports, [65534, 65535, 1, 2, 3, 4]);
        let next = proxy.allocate_entry(flow(2000), dst).unwrap();
        assert_eq!(next.translated_src.port(), 6);
    }

    #[tokio::test]
    async fn exhausted_translated_ports_drop_the_syn_and_free_ones_are_reused() {
        let (_pm, proxy) = kernel_proxy().await;
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 144, 144, 9), 5000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
        let flow_of = |dst_port: u16| NatFlowKey {
            src: SocketAddr::V4(src),
            mapped_dst: SocketAddr::from(([192, 0, 2, 1], dst_port)),
        };
        // every port but the listener's belongs to some flow
        let mut held = Vec::new();
        for i in 1..=u16::MAX - 1 {
            held.push(proxy.allocate_entry(flow_of(i), dst.into()).unwrap());
        }
        assert!(proxy.allocate_entry(flow_of(0), dst.into()).is_none());

        let mut syn = tcp_packet(src, SocketAddrV4::new(*dst.ip(), 65535), SYN);
        assert_eq!(
            proxy.try_handle_peer_packet(&mut syn).await,
            PeerPacketAction::Drop
        );

        let freed = held.pop().unwrap();
        proxy.indices.remove(&freed);
        assert!(proxy.allocate_entry(flow_of(0), dst.into()).is_some());
    }

    #[tokio::test]
    async fn a_syn_replaces_an_ending_flow_without_the_old_cleanup_touching_the_new_one() {
        let (_pm, proxy) = kernel_proxy().await;
        let dst = SocketAddr::from(([192, 0, 2, 1], 80));
        let (old, new_syn) = proxy.entry_for_syn(flow(5000), dst).unwrap();
        assert!(new_syn);
        let (same, new_syn) = proxy.entry_for_syn(flow(5000), dst).unwrap();
        assert!(!new_syn && same.id == old.id);

        old.state.store(NatDstEntryState::Closed);
        let (replacement, new_syn) = proxy.entry_for_syn(flow(5000), dst).unwrap();
        assert!(new_syn && replacement.id != old.id);
        assert_ne!(replacement.translated_src, old.translated_src);

        // The old connection's delayed cleanup must leave the replacement in place.
        proxy.indices.remove(&old);
        assert!(
            proxy
                .indices
                .flow_map
                .get(&flow(5000))
                .is_some_and(|entry| entry.id == replacement.id)
        );
        assert!(
            proxy
                .indices
                .translated_src_map
                .contains_key(&replacement.translated_src)
        );
        assert!(
            !proxy
                .indices
                .translated_src_map
                .contains_key(&old.translated_src)
        );
    }

    #[tokio::test]
    async fn packets_of_an_unknown_flow_are_not_proxied() {
        let (_pm, proxy) = kernel_proxy().await;
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 144, 144, 9), 5000);
        let dst_a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
        let dst_b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 80);
        syn_from_peer(&proxy, src, dst_a).await;

        // Same source, other destination, and no SYN: nothing tracks this flow.
        let mut ack = tcp_packet(src, dst_b, ACK);
        assert_eq!(
            proxy.try_handle_peer_packet(&mut ack).await,
            PeerPacketAction::Pass
        );
    }

    /// A relay between a real TCP stream, as the kernel proxy entry accepts, and an in-memory
    /// destination. `server_closes_first` picks which side reaches EOF before the other has
    /// sent anything at all.
    async fn kernel_relay_after_half_close(server_closes_first: bool, request_size: usize) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut client = client.unwrap();
        let mut src = ProxyTcpStream::KernelTcpStream(accepted.unwrap().0);
        // Small buffers force the relay to make progress in both directions; the response is
        // deliberately larger than either buffer.
        let (mut dst, mut server) = tokio::io::duplex(64);
        let request = vec![0x35; request_size];
        let response = vec![0xa7; 64 * 1024];

        let relay = async {
            src.copy_bidirectional(&mut dst).await.unwrap();
        };
        let requester = async {
            if server_closes_first {
                let mut received = Vec::new();
                client.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, response);
                client.write_all(&request).await.unwrap();
                client.shutdown().await.unwrap();
            } else {
                client.write_all(&request).await.unwrap();
                client.shutdown().await.unwrap();
                let mut received = Vec::new();
                client.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, response);
            }
        };
        let responder = async {
            if server_closes_first {
                server.write_all(&response).await.unwrap();
                server.shutdown().await.unwrap();
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, request);
            } else {
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, request);
                server.write_all(&response).await.unwrap();
                server.shutdown().await.unwrap();
            }
        };
        timeout(Duration::from_secs(10), async {
            tokio::join!(relay, requester, responder);
        })
        .await
        .expect("half-closed relay did not finish");
    }

    #[tokio::test]
    async fn source_half_close_preserves_response() {
        for request_size in [0, 32 * 1024] {
            kernel_relay_after_half_close(false, request_size).await;
        }
    }

    #[tokio::test]
    async fn destination_half_close_preserves_request() {
        for request_size in [0, 32 * 1024] {
            kernel_relay_after_half_close(true, request_size).await;
        }
    }
}
