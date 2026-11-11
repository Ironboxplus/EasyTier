use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use rand::{Rng, SeedableRng};
use zerocopy::{AsBytes, FromBytes};

use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender},
        watch,
    },
    task::JoinSet,
    time::Instant,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, instrument};

use super::{
    FromUrl, IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelInfo, TunnelListener,
    TunnelUrl,
    common::wait_for_connect_futures,
    packet_def::{UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, V4HolePunchPacket, V6HolePunchPacket},
    ring::{RingSink, RingStream},
};
use crate::tunnel::common::bind;
use crate::{
    common::{join_joinset_background, shrink_dashmap},
    tunnel::{
        build_url_from_socket_addr,
        common::{TunnelWrapper, reserve_buf},
        packet_def::{UdpPacketType, ZCPacket, ZCPacketType},
        ring::RingTunnel,
    },
};

pub const UDP_DATA_MTU: usize = 2000;

type UdpCloseEventSender = UnboundedSender<(SocketAddr, Option<TunnelError>)>;
type UdpCloseEventReceiver = UnboundedReceiver<(SocketAddr, Option<TunnelError>)>;

fn new_udp_packet<F>(f: F, udp_body: Option<&[u8]>) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(
        UDP_TUNNEL_HEADER_SIZE + udp_body.as_ref().map(|v| v.len()).unwrap_or(0),
        0,
    );
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body.unwrap());

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&magic.to_le_bytes()),
    )
}

fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&magic.to_le_bytes()),
    )
}

pub fn new_hole_punch_packet(tid: u32, buf_len: u16) -> ZCPacket {
    // generate a 128 bytes vec with random data
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut buf = vec![0u8; buf_len as usize];
    rng.fill(&mut buf[..]);
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::HolePunch as u8;
            header.conn_id.set(tid);
            header.len.set(buf_len);
        },
        Some(&buf),
    )
}

pub fn new_v6_hole_punch_packet(dst: &SocketAddrV6) -> ZCPacket {
    // generate a 128 bytes vec with random data
    let mut body = V6HolePunchPacket::default();
    body.dst_ipv6.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V6HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V6HolePunchPacket>() as u16);
        },
        Some(body.as_bytes()),
    )
}

pub fn new_v4_hole_punch_packet(dst: &SocketAddrV4) -> ZCPacket {
    let mut body = V4HolePunchPacket::default();
    body.dst_ipv4.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V4HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V4HolePunchPacket>() as u16);
        },
        Some(body.as_bytes()),
    )
}

fn extract_dst_addr_from_v4_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV4> {
    let body = V4HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv4Addr::from(body.dst_ipv4);
    Some(SocketAddrV4::new(ip, body.dst_port.get()))
}

fn extrace_dst_addr_from_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV6> {
    let body = V6HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv6Addr::from(body.dst_ipv6);
    Some(SocketAddrV6::new(ip, body.dst_port.get(), 0, 0))
}

fn is_stun_packet(b: &[u8]) -> bool {
    // stun has following pattern:
    // 1. first two bits are 0b00
    // 2. magic cookie between 32-64 bits: 0x2112A442
    b[4..8] == [0x21, 0x12, 0xA4, 0x42] && b[0] & 0xC0 == 0
}

pub async fn send_v6_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV6,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("[::1]:0").await?;
    let udp_packet = new_v6_hole_punch_packet(&dst_addr);
    let remote_addr = format!("[::1]:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

pub async fn send_v4_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV4,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_packet = new_v4_hole_punch_packet(&dst_addr);
    let remote_addr = format!("127.0.0.1:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

async fn respond_stun_packet(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    req_buf: Vec<u8>,
) -> Result<(), anyhow::Error> {
    use crate::common::stun_codec_ext::*;
    use bytecodec::{DecodeExt as _, EncodeExt as _};
    use stun_codec::{
        Message, MessageClass, MessageDecoder, MessageEncoder,
        rfc5389::{attributes::XorMappedAddress, methods::BINDING},
    };

    let mut decoder = MessageDecoder::<Attribute>::new();
    let req_msg = decoder
        .decode_from_bytes(&req_buf)
        .map_err(|e| anyhow::anyhow!("stun decode error: {:?}", e))?
        .map_err(|e| anyhow::anyhow!("stun decode broken message error: {:?}", e))?;

    let tid = req_msg.transaction_id();
    // we only respond easytier stun req, whose tid has 0xdeadbeef prefix
    if tid.as_bytes()[0..4] != [0xde, 0xad, 0xbe, 0xef] {
        anyhow::bail!("stun req tid not from easytier");
    }

    let mut resp_msg = Message::<Attribute>::new(
        MessageClass::SuccessResponse,
        BINDING,
        // we discard the prefix, make sure our implementation is not compatible with other stun client
        u32_to_tid(tid_to_u32(&tid)),
    );
    resp_msg.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

    let mut encoder = MessageEncoder::new();
    let rsp_buf = encoder
        .encode_into_bytes(resp_msg.clone())
        .map_err(|e| anyhow::anyhow!("stun encode error: {:?}", e))?;

    let change_req = req_msg
        .get_attribute::<ChangeRequest>()
        .map(|r| r.ip() || r.port())
        .unwrap_or(false);

    if !change_req {
        socket
            .send_to(&rsp_buf, addr)
            .await
            .with_context(|| "send stun response error")?;
    } else {
        // send from a new udp socket
        let socket = if addr.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0").await?
        } else {
            UdpSocket::bind("[::]:0").await?
        };
        socket.send_to(&rsp_buf, addr).await?;
    }

    tracing::debug!(?addr, ?req_msg, ?change_req, "udp respond stun packet done");
    Ok(())
}

fn get_zcpacket_from_buf(buf: BytesMut, allow_stun: bool) -> Result<ZCPacket, TunnelError> {
    let dg_size = buf.len();
    if dg_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "udp packet size too small: {:?}, packet: {:?}",
            dg_size, buf
        )));
    }

    if allow_stun && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]) {
        return Ok(ZCPacket::new_from_buf(buf, ZCPacketType::UDP));
    }

    let zc_packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = zc_packet.udp_tunnel_header().unwrap();
    let payload_len = header.len.get() as usize;
    if payload_len != dg_size - UDP_TUNNEL_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "udp packet payload len not match: header len: {:?}, real len: {:?}",
            payload_len, dg_size
        )));
    }

    Ok(zc_packet)
}

#[instrument]
async fn forward_from_ring_to_udp(
    mut ring_recv: RingStream,
    socket: &Arc<UdpSocket>,
    addr: &SocketAddr,
    conn_id: u32,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from ring to udp");
    loop {
        let buf = ring_recv.next().await?;
        let packet = match buf {
            Ok(v) => v,
            Err(e) => {
                return Some(e);
            }
        };

        let mut packet = packet.convert_type(ZCPacketType::UDP);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.len.set(udp_payload_len as u16);
        header.msg_type = UdpPacketType::Data as u8;

        let buf = packet.into_bytes();
        tracing::trace!(?udp_payload_len, ?buf, "udp forward from ring to udp");
        let ret = socket.send_to(&buf, &addr).await;
        if ret.is_err() {
            return Some(TunnelError::IOError(ret.unwrap_err()));
        } else if ret.unwrap() == 0 {
            return None;
        }
    }
}

async fn udp_recv_from_socket_forward_task(
    socket: &UdpSocket,
    buf: &mut BytesMut,
    allow_stun: bool,
) -> Result<(ZCPacket, SocketAddr), TunnelError> {
    loop {
        reserve_buf(buf, UDP_DATA_MTU, UDP_DATA_MTU * 4);
        let (dg_size, addr) = match socket.recv_buf_from(buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(?e, "udp recv from socket error");
                return Err(e.into());
            }
        };
        tracing::trace!(
            "udp recv packet: {:?}, buf: {:?}, size: {}",
            addr,
            buf,
            dg_size
        );

        let zc_packet = match get_zcpacket_from_buf(buf.split(), allow_stun) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "udp get zc packet from buf error");
                continue;
            }
        };

        return Ok((zc_packet, addr));
    }
}

struct UdpConnection {
    socket: Arc<UdpSocket>,
    conn_id: u32,
    dst_addr: SocketAddr,

    ring_sender: RingSink,
    forward_task: AbortOnDropHandle<()>,
}

impl UdpConnection {
    pub fn new(
        socket: Arc<UdpSocket>,
        conn_id: u32,
        dst_addr: SocketAddr,
        ring_sender: RingSink,
        ring_recv: RingStream,
        close_event_sender: UdpCloseEventSender,
    ) -> Self {
        let s = socket.clone();
        let forward_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let close_event_sender = close_event_sender;
            let err = forward_from_ring_to_udp(ring_recv, &s, &dst_addr, conn_id).await;
            if let Err(e) = close_event_sender.send((dst_addr, err)) {
                tracing::error!(?e, "udp send close event error");
            }
        }));
        Self {
            socket,
            conn_id,
            dst_addr,
            ring_sender,
            forward_task,
        }
    }

    pub async fn handle_packet_from_remote(
        &mut self,
        zc_packet: ZCPacket,
    ) -> Result<(), TunnelError> {
        let header = zc_packet.udp_tunnel_header().unwrap();
        let conn_id = header.conn_id.get();

        if header.msg_type != UdpPacketType::Data as u8 {
            return Err(TunnelError::InvalidPacket("not data packet".to_owned()));
        }

        if self.conn_id != conn_id {
            return Err(TunnelError::ConnIdNotMatch(self.conn_id, conn_id));
        }

        self.ring_sender.send(zc_packet).await?;

        Ok(())
    }
}

/// Body length of a hole punch packet (the header's `conn_id` is its transaction id).
pub const HOLE_PUNCH_PACKET_BODY_LEN: u16 = 16;

struct UdpHolePunchObserverEntry {
    source: Arc<watch::Sender<Option<SocketAddr>>>,
    // Only a registration nobody has claimed expires here. Once an RPC took the observer, its guard
    // owns the cleanup, through completion or cancellation.
    expires_at: Option<Instant>,
}

/// Where a hole punch transaction's first packet came from, observed on the listener's own receive
/// loop (no second receiver on the socket). Cloning shares the table.
#[derive(Clone, Default)]
pub struct UdpHolePunchObserverRegistry {
    observers: Arc<DashMap<u32, UdpHolePunchObserverEntry>>,
    closed: Arc<AtomicBool>,
}

impl Debug for UdpHolePunchObserverRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHolePunchObserverRegistry")
            .field("observers", &self.observers.len())
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl UdpHolePunchObserverRegistry {
    fn ensure_running(&self) -> std::io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "UDP listener closed",
            ));
        }
        Ok(())
    }

    /// Keeps the first source of `transaction_id` even when its packet arrives before the RPC that
    /// sends the punch packets claims it with [`Self::observe`].
    pub fn prepare(&self, transaction_id: u32, timeout: Duration) -> std::io::Result<()> {
        self.ensure_running()?;
        match self.observers.entry(transaction_id) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(UdpHolePunchObserverEntry {
                    source: Arc::new(watch::channel(None).0),
                    expires_at: Some(Instant::now() + timeout),
                });
                Ok(())
            }
            dashmap::mapref::entry::Entry::Occupied(_) => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "UDP hole-punch transaction already observed",
            )),
        }
    }

    /// Drops the registrations nobody claimed in time.
    pub fn expire_prepared(&self) {
        let now = Instant::now();
        self.observers
            .retain(|_, entry| entry.expires_at.is_none_or(|deadline| deadline > now));
    }

    /// Claims `transaction_id`: the registration made by [`Self::prepare`], or a new one for a
    /// requester that does not prepare. Dropping the observer unregisters it.
    pub fn observe(&self, transaction_id: u32) -> std::io::Result<UdpHolePunchObserver> {
        self.ensure_running()?;
        let sender = match self.observers.entry(transaction_id) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let Some(deadline) = entry.get_mut().expires_at.take() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "UDP hole-punch transaction already observed",
                    ));
                };
                if deadline <= Instant::now() {
                    entry.remove();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "UDP hole-punch registration expired",
                    ));
                }
                entry.get().source.clone()
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let sender = Arc::new(watch::channel(None).0);
                entry.insert(UdpHolePunchObserverEntry {
                    source: sender.clone(),
                    expires_at: None,
                });
                sender
            }
        };
        Ok(UdpHolePunchObserver {
            transaction_id,
            observers: self.observers.clone(),
            sender: Arc::downgrade(&sender),
            source: sender.subscribe(),
        })
    }

    fn record(&self, transaction_id: u32, source: SocketAddr) {
        if let Some(entry) = self.observers.get(&transaction_id) {
            entry.source.send_if_modified(|current| {
                if current.is_some() {
                    return false;
                }
                *current = Some(source);
                true
            });
        }
    }

    /// The listener stopped receiving: nothing will be observed any more.
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.observers.clear();
    }
}

/// The first source of one hole punch transaction's packets.
pub struct UdpHolePunchObserver {
    transaction_id: u32,
    observers: Arc<DashMap<u32, UdpHolePunchObserverEntry>>,
    sender: Weak<watch::Sender<Option<SocketAddr>>>,
    source: watch::Receiver<Option<SocketAddr>>,
}

impl UdpHolePunchObserver {
    pub fn source_addr(&self) -> Option<SocketAddr> {
        *self.source.borrow()
    }

    pub async fn wait_for_source_addr(&mut self) -> std::io::Result<SocketAddr> {
        loop {
            if let Some(addr) = self.source_addr() {
                return Ok(addr);
            }
            self.source.changed().await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "UDP hole-punch observer closed",
                )
            })?;
        }
    }
}

impl Drop for UdpHolePunchObserver {
    fn drop(&mut self) {
        self.observers.remove_if(&self.transaction_id, |_, entry| {
            self.sender.ptr_eq(&Arc::downgrade(&entry.source))
        });
    }
}

#[derive(Clone)]
struct UdpTunnelListenerData {
    local_url: url::Url,
    socket: Option<Arc<UdpSocket>>,
    sock_map: Arc<DashMap<SocketAddr, UdpConnection>>,
    conn_send: Sender<Box<dyn Tunnel>>,
    close_event_sender: UdpCloseEventSender,
    hole_punch_observers: UdpHolePunchObserverRegistry,
}

impl UdpTunnelListenerData {
    pub fn new(
        local_url: url::Url,
        conn_send: Sender<Box<dyn Tunnel>>,
        close_event_sender: UdpCloseEventSender,
    ) -> Self {
        Self {
            local_url,
            socket: None,
            sock_map: Arc::new(DashMap::new()),
            conn_send,
            close_event_sender,
            hole_punch_observers: UdpHolePunchObserverRegistry::default(),
        }
    }

    async fn handle_new_connect(self, remote_addr: SocketAddr, zc_packet: ZCPacket) {
        let udp_payload = zc_packet.udp_payload();
        if udp_payload.len() != 8 {
            tracing::warn!(
                "udp syn packet payload len not match: {:?}, packet: {:?}",
                udp_payload.len(),
                zc_packet,
            );
            return;
        }
        let magic = u64::from_le_bytes(udp_payload[..8].try_into().unwrap());
        let conn_id = zc_packet.udp_tunnel_header().unwrap().conn_id.get();

        tracing::info!(?conn_id, ?remote_addr, "udp connection accept handling",);
        let socket = self.socket.as_ref().unwrap().clone();

        let sack_buf = new_sack_packet(conn_id, magic).into_bytes();
        if let Err(e) = socket.send_to(&sack_buf, remote_addr).await {
            tracing::error!(?e, "udp send sack packet error");
            return;
        }

        let ring_for_send_udp = Arc::new(RingTunnel::new(128));
        let ring_for_recv_udp = Arc::new(RingTunnel::new(128));
        tracing::debug!(
            ?ring_for_send_udp,
            ?ring_for_recv_udp,
            "udp build tunnel for listener"
        );

        let internal_conn = UdpConnection::new(
            socket.clone(),
            conn_id,
            remote_addr,
            RingSink::new(ring_for_recv_udp.clone()),
            RingStream::new(ring_for_send_udp.clone()),
            self.close_event_sender.clone(),
        );
        self.sock_map.insert(remote_addr, internal_conn);

        let conn = Box::new(TunnelWrapper::new(
            Box::new(RingStream::new(ring_for_recv_udp)),
            Box::new(RingSink::new(ring_for_send_udp)),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(self.local_url.clone().into()),
                remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
            }),
        ));

        tracing::info!(info = ?conn.info().unwrap().remote_addr, "udp connection accept done");

        if let Err(e) = self.conn_send.send(conn).await {
            tracing::warn!(?e, "udp send conn to accept channel error");
        }
    }

    async fn do_forward_one_packet_to_conn(&self, zc_packet: ZCPacket, addr: SocketAddr) {
        let header = zc_packet.udp_tunnel_header().unwrap();
        if header.msg_type == UdpPacketType::Syn as u8 {
            tokio::spawn(Self::handle_new_connect(self.clone(), addr, zc_packet));
        } else if is_stun_packet(header.as_bytes()) {
            // ignore stun packet
            tracing::debug!("udp forward packet ignore stun packet");
            let socket = self.socket.as_ref().unwrap().clone();
            tokio::spawn(async move {
                let ret = respond_stun_packet(socket, addr, zc_packet.inner().to_vec()).await;
                if let Err(e) = ret {
                    tracing::error!(?e, "udp respond stun packet error");
                }
            });
        } else if header.msg_type == UdpPacketType::V4HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v4 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv4() {
                tracing::warn!(?addr, "v4 hole punch packet should be sent from ipv4");
                return;
            }
            let Some(dst_addr) =
                extract_dst_addr_from_v4_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v4 hole punch packet");
                return;
            };
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            if let Err(e) = socket.try_send_to(&udp_packet.into_bytes(), SocketAddr::V4(dst_addr)) {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(?dst_addr, "udp forward packet send hole punch packet");
        } else if header.msg_type == UdpPacketType::V6HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v6 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv6() {
                tracing::warn!(?addr, "v6 hole punch packet should be sent from ipv6");
                return;
            }
            let Some(dst_addr) = extrace_dst_addr_from_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v6 hole punch packet");
                return;
            };
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            if let Err(e) = socket.try_send_to(&udp_packet.into_bytes(), SocketAddr::V6(dst_addr)) {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(?dst_addr, "udp forward packet send hole punch packet");
        } else if header.msg_type != UdpPacketType::HolePunch as u8 {
            let Some(mut conn) = self.sock_map.get_mut(&addr) else {
                tracing::trace!(?header, "udp forward packet error, connection not found");
                return;
            };
            if let Err(e) = conn.handle_packet_from_remote(zc_packet).await {
                tracing::trace!(?e, "udp forward packet error");
            }
        } else {
            // A punch packet of an active transaction tells where the peer's NAT really sends from.
            if zc_packet.udp_payload().len() == HOLE_PUNCH_PACKET_BODY_LEN as usize {
                self.hole_punch_observers
                    .record(header.conn_id.get(), addr);
            }
            tracing::trace!(?header, "udp forward packet ignore hole punch packet");
        }
    }

    async fn do_forward_task(self) {
        let socket = self.socket.as_ref().unwrap().clone();
        let mut buf = BytesMut::new();
        loop {
            match udp_recv_from_socket_forward_task(&socket, &mut buf, true).await {
                Ok((zc_packet, addr)) => self.do_forward_one_packet_to_conn(zc_packet, addr).await,
                Err(e) => {
                    tracing::error!(?e, "udp recv packet error");
                    break;
                }
            }
        }
        self.hole_punch_observers.close();
    }
}

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,

    conn_recv: Receiver<Box<dyn Tunnel>>,
    data: UdpTunnelListenerData,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    close_event_recv: Option<UdpCloseEventReceiver>,
    socket_mark: Option<u32>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (close_event_send, close_event_recv) =
            hotpath::channel!(tokio::sync::mpsc::unbounded_channel());
        let (conn_send, conn_recv) = hotpath::channel!(tokio::sync::mpsc::channel(100));
        Self {
            addr: addr.clone(),
            socket: None,
            conn_recv,
            data: UdpTunnelListenerData::new(addr, conn_send, close_event_send),
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            close_event_recv: Some(close_event_recv),
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let mut listener = Self::new(addr);
        listener.socket = Some(socket);
        listener
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    pub fn hole_punch_observers(&self) -> UdpHolePunchObserverRegistry {
        self.data.hole_punch_observers.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        if self.socket.is_none() {
            let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
            let tunnel_url: TunnelUrl = self.addr.clone().into();
            self.socket = Some(Arc::new(
                bind()
                    .addr(addr)
                    .only_v6(true)
                    .maybe_dev(tunnel_url.bind_dev())
                    .maybe_socket_mark(self.socket_mark)
                    .call()?,
            ));
        }
        self.data.socket = self.socket.clone();

        self.addr
            .set_port(Some(self.socket.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(self.data.clone().do_forward_task());

        let sock_map = Arc::downgrade(&self.data.sock_map.clone());
        let mut close_recv = self.close_event_recv.take().unwrap();
        self.forward_tasks.lock().unwrap().spawn(async move {
            while let Some((dst_addr, err)) = close_recv.recv().await {
                if let Some(err) = err {
                    tracing::error!(?err, "udp close event error");
                }
                if let Some(sock_map) = sock_map.upgrade() {
                    sock_map.remove(&dst_addr);
                    shrink_dashmap(&sock_map, None);
                }
            }
        });

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::info!("start udp accept: {:?}", self.addr);
        if let Some(conn) = self.conn_recv.recv().await {
            return Ok(conn);
        }
        return Err(super::TunnelError::InternalError(
            "udp accept error".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        struct UdpTunnelConnCounter {
            sock_map: Weak<DashMap<SocketAddr, UdpConnection>>,
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                self.sock_map.upgrade().map(|x| x.len() as u32)
            }
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("sock_map_len", &self.get())
                    .finish()
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            sock_map: Arc::downgrade(&self.data.sock_map.clone()),
        }))
    }
}

#[derive(Debug)]
pub struct UdpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
        }
    }

    async fn wait_sack(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, TunnelError> {
        let mut buf = BytesMut::new();
        buf.reserve(UDP_DATA_MTU);

        let (usize, recv_addr) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            socket.recv_buf_from(&mut buf),
        )
        .await??;
        let zc_packet = get_zcpacket_from_buf(buf.split(), false)?;
        if recv_addr != addr {
            tracing::warn!(?recv_addr, ?addr, ?usize, "udp wait sack addr not match");
        }

        let header = zc_packet.udp_tunnel_header().unwrap();

        if header.conn_id.get() != conn_id {
            return Err(super::TunnelError::ConnIdNotMatch(
                header.conn_id.get(),
                conn_id,
            ));
        }

        if header.msg_type != UdpPacketType::Sack as u8 {
            return Err(TunnelError::InvalidPacket("not sack packet".to_owned()));
        }

        let payload = zc_packet.udp_payload();
        if payload.len() != 8 {
            return Err(TunnelError::InvalidPacket(
                "udp sack packet payload len not match".to_owned(),
            ));
        }

        let sack_magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if sack_magic != magic {
            return Err(TunnelError::InvalidPacket(
                "udp sack magic not match".to_owned(),
            ));
        }

        Ok(recv_addr)
    }

    async fn wait_sack_loop(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, super::TunnelError> {
        loop {
            let ret = Self::wait_sack(socket, addr, conn_id, magic).await;
            if ret.is_err() {
                tracing::debug!(?ret, "udp wait sack error");
                continue;
            } else {
                return ret;
            }
        }
    }

    async fn build_tunnel(
        &self,
        socket: Arc<UdpSocket>,
        dst_addr: SocketAddr,
        conn_id: u32,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let ring_for_send_udp = Arc::new(RingTunnel::new(128));
        let ring_for_recv_udp = Arc::new(RingTunnel::new(128));
        tracing::debug!(
            ?ring_for_send_udp,
            ?ring_for_recv_udp,
            "udp build tunnel for connector"
        );

        let (close_event_sender, mut close_event_recv) =
            hotpath::channel!(tokio::sync::mpsc::unbounded_channel());

        let ring_recv = RingStream::new(ring_for_send_udp.clone());
        let ring_sender = RingSink::new(ring_for_recv_udp.clone());
        let mut udp_conn = UdpConnection::new(
            socket.clone(),
            conn_id,
            dst_addr,
            ring_sender,
            ring_recv,
            close_event_sender,
        );

        let socket_clone = socket.clone();

        let recv_loop = async move {
            let mut buf = BytesMut::new();
            loop {
                match udp_recv_from_socket_forward_task(&socket_clone, &mut buf, false).await {
                    Ok((zc_packet, addr)) => {
                        tracing::trace!(?addr, "connector udp forward task done");
                        if let Err(e) = udp_conn.handle_packet_from_remote(zc_packet).await {
                            tracing::trace!(?e, ?addr, "udp forward packet error");
                        }
                    }
                    Err(e) => {
                        tracing::trace!(?e, "udp forward task error");
                        break;
                    }
                }
            }
        };
        tokio::spawn(
            async move {
                tokio::select! {
                    _ = close_event_recv.recv() => {
                        tracing::debug!("connector udp close event");
                    }
                    _ = recv_loop => {
                        tracing::debug!("connector udp forward task done");
                    }
                }
            }
            .instrument(tracing::info_span!(
                "udp forward from udp to ring",
                ?conn_id,
                ?dst_addr,
            )),
        );

        Ok(Box::new(TunnelWrapper::new(
            Box::new(RingStream::new(ring_for_recv_udp)),
            Box::new(RingSink::new(ring_for_send_udp)),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(
                    build_url_from_socket_addr(&socket.local_addr()?.to_string(), "udp").into(),
                ),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&dst_addr.to_string(), "udp").into(),
                ),
            }),
        )))
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("udp connect: {:?}", self.addr);

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.as_ref())?;

        // send syn
        let conn_id = rand::random();
        let magic = rand::random();
        let udp_packet = new_syn_packet(conn_id, magic).into_bytes();
        let ret = socket.send_to(&udp_packet, &addr).await?;
        tracing::warn!(?udp_packet, ?ret, "udp send syn");

        // wait sack
        let recv_addr = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            Self::wait_sack_loop(&socket, addr, conn_id, magic),
        )
        .await??;

        if recv_addr != addr {
            tracing::debug!(?recv_addr, ?addr, "udp connect addr not match");
        }

        self.build_tunnel(socket, addr, conn_id).await
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // Route through bind() so socket_mark is applied consistently for
        // both the None (no-op) and Some(_) paths.
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        return self.try_connect_with_socket(Arc::new(socket), addr).await;
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(self.try_connect_with_socket(Arc::new(socket), addr)),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use futures::SinkExt;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{
            TunnelConnector,
            common::{
                get_interface_name_by_ip,
                tests::{_tunnel_bench, _tunnel_echo_server, _tunnel_pingpong, wait_for_condition},
            },
        },
    };

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn udp_bench() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5555".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5555".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench_with_bind() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5554".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5554".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn udp_bench_with_bind_fail() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5553".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5553".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    async fn send_random_data_to_socket(remote_url: url::Url) {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket
            .connect(format!(
                "{}:{}",
                remote_url.host().unwrap(),
                remote_url.port().unwrap()
            ))
            .await
            .unwrap();

        // get a random 100-len buf
        loop {
            let mut buf = vec![0u8; 100];
            rand::thread_rng().fill(&mut buf[..]);
            socket.send(&buf).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn udp_multiple_conns() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5557".parse().unwrap());
        listener.listen().await.unwrap();

        let _lis = tokio::spawn(async move {
            loop {
                let ret = listener.accept().await.unwrap();
                assert_eq!(
                    ret.info()
                        .unwrap()
                        .local_addr
                        .unwrap_or_default()
                        .to_string(),
                    listener.local_url().to_string()
                );
                tokio::spawn(async move { _tunnel_echo_server(ret, false).await });
            }
        });

        let mut connector1 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());
        let mut connector2 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());

        let t1 = connector1.connect().await.unwrap();
        let t2 = connector2.connect().await.unwrap();

        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().local_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().remote_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t2.info().unwrap().remote_addr.unwrap().into()),
        ));

        let sender1 = tokio::spawn(async move {
            let (mut stream, mut sink) = t1.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello1".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t1 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello1".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let sender2 = tokio::spawn(async move {
            let (mut stream, mut sink) = t2.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t2 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello2".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let _ = tokio::join!(sender1, sender2);
    }

    #[tokio::test]
    async fn bind_multi_ip_to_same_dev() {
        let global_ctx = get_mock_global_ctx();
        let ips = global_ctx
            .get_ip_collector()
            .collect_ip_addrs()
            .await
            .interface_ipv4s;
        if ips.is_empty() {
            return;
        }
        let bind_dev = get_interface_name_by_ip(&IpAddr::V4(ips[0].into()));

        for ip in ips {
            println!("bind to ip: {}, {:?}", ip, bind_dev);
            let addr = SocketAddr::from_url(
                format!("udp://{}:11111", ip).parse().unwrap(),
                IpVersion::Both,
            )
            .await
            .unwrap();
            let _ = bind::<UdpSocket>()
                .addr(addr)
                .maybe_dev(bind_dev.clone())
                .only_v6(true)
                .call()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn bind_same_port() {
        println!("{}", "[::]:8888".parse::<SocketAddr>().unwrap());
        let mut listener = UdpTunnelListener::new("udp://[::]:31014".parse().unwrap());
        let mut listener2 = UdpTunnelListener::new("udp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31015".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = UdpTunnelListener::new("udp://127.0.0.1:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_conn_counter() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let _c1 = connector.connect().await.unwrap();
            let _c2 = connector.connect().await.unwrap();
        });

        let conn_counter = listener.get_conn_counter();

        listener.listen().await.unwrap();
        let c1 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(1));
        let c2 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(2));

        drop(c2);
        wait_for_condition(
            || async { conn_counter.get() == Some(1) },
            Duration::from_secs(1),
        )
        .await;

        drop(c1);
        wait_for_condition(
            || async { conn_counter.get().unwrap_or(0) == 0 },
            Duration::from_secs(1),
        )
        .await;
    }

    #[tokio::test]
    async fn test_v6_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        lis.listen().await.unwrap();

        // a socket to receive forwarded hole punch packets
        let socket = Arc::new(UdpSocket::bind("[::]:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tracing::info!("lis local addr: {:?}", lis.local_url());
        tracing::info!("socket local addr: {:?}", socket.local_addr().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // a socket to send v6 hole punch packets
        send_v6_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V6(addr_v6) => addr_v6,
                _ => panic!("Expected an IPv6 address"),
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v6 hole punch packet")
            .unwrap();
    }

    #[tokio::test]
    async fn test_v4_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        lis.listen().await.unwrap();

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        send_v4_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V4(addr_v4) => addr_v4,
                _ => panic!("Expected an IPv4 address"),
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v4 hole punch packet")
            .unwrap();
    }

    async fn punch_listener() -> (UdpTunnelListener, SocketAddr) {
        let mut lis = UdpTunnelListener::new("udp://127.0.0.1:0".parse().unwrap());
        lis.listen().await.unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], lis.local_url().port().unwrap()));
        (lis, addr)
    }

    async fn send_punch(from: &UdpSocket, to: SocketAddr, tid: u32, body_len: u16) {
        from.send_to(&new_hole_punch_packet(tid, body_len).into_bytes(), to)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn hole_punch_observer_matches_transaction_and_packet_shape() {
        let (lis, addr) = punch_listener().await;
        let registry = lis.hole_punch_observers();
        let mut observer = registry.observe(7).unwrap();
        let mut other = registry.observe(8).unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // another transaction, a wrong body length, and a concurrent transaction come first
        send_punch(&first, addr, 9, HOLE_PUNCH_PACKET_BODY_LEN).await;
        send_punch(&first, addr, 7, 32).await;
        send_punch(&second, addr, 8, HOLE_PUNCH_PACKET_BODY_LEN).await;
        send_punch(&first, addr, 7, HOLE_PUNCH_PACKET_BODY_LEN).await;
        let wait = Duration::from_secs(2);
        assert_eq!(
            timeout(wait, observer.wait_for_source_addr()).await.unwrap().unwrap(),
            first.local_addr().unwrap()
        );
        assert_eq!(
            timeout(wait, other.wait_for_source_addr()).await.unwrap().unwrap(),
            second.local_addr().unwrap()
        );
        // the first source stays
        send_punch(&second, addr, 7, HOLE_PUNCH_PACKET_BODY_LEN).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(observer.source_addr(), Some(first.local_addr().unwrap()));

        assert_eq!(
            registry.observe(7).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        drop(observer);
        assert_eq!(registry.observe(7).unwrap().source_addr(), None);
    }

    #[tokio::test]
    async fn prepared_hole_punch_keeps_its_source_until_the_rpc_claims_it() {
        let (lis, addr) = punch_listener().await;
        let registry = lis.hole_punch_observers();
        registry.prepare(0, Duration::from_secs(30)).unwrap();
        assert_eq!(
            registry.prepare(0, Duration::from_secs(30)).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_punch(&peer, addr, 0, HOLE_PUNCH_PACKET_BODY_LEN).await;

        wait_for_condition(
            || async {
                registry
                    .observers
                    .get(&0)
                    .is_some_and(|e| *e.source.borrow() == Some(peer.local_addr().unwrap()))
            },
            Duration::from_secs(2),
        )
        .await;
        let observer = registry.observe(0).unwrap();
        assert_eq!(observer.source_addr(), Some(peer.local_addr().unwrap()));
        assert_eq!(
            registry.observe(0).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        drop(observer);
        assert!(registry.observers.is_empty());
    }

    #[tokio::test]
    async fn prepared_hole_punch_expires_without_removing_an_active_one() {
        let registry = UdpHolePunchObserverRegistry::default();
        for tid in [7, 8, 9] {
            registry.prepare(tid, Duration::from_millis(200)).unwrap();
        }
        let observer = registry.observe(8).unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            registry.observe(7).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::TimedOut)
        );
        registry.expire_prepared();
        assert!(!registry.observers.contains_key(&9));
        assert!(registry.observers.contains_key(&8));
        registry.prepare(9, Duration::from_secs(1)).unwrap();
        drop(observer);
        assert!(!registry.observers.contains_key(&8));
    }

    #[tokio::test]
    async fn stopped_listener_ends_hole_punch_observation() {
        let registry = UdpHolePunchObserverRegistry::default();
        let mut observer = registry.observe(7).unwrap();
        registry.prepare(8, Duration::from_secs(30)).unwrap();
        registry.close();
        assert_eq!(
            registry.observe(8).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(
            registry.prepare(9, Duration::from_secs(30)).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(
            observer.wait_for_source_addr().await.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
    }
}
