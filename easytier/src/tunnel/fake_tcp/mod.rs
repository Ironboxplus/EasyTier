mod netfilter;
mod packet;
mod stack;

use bytes::BytesMut;
use futures::{Sink, Stream};
use network_interface::NetworkInterfaceConfig;
use pnet::util::MacAddr;
#[cfg(feature = "mpquic")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{io::AsyncReadExt, net::TcpStream};

use crate::tunnel::{
    FromUrl, IpVersion, SinkError, SinkItem, StreamItem, Tunnel, TunnelConnector, TunnelError,
    TunnelInfo, TunnelListener,
    common::TunnelWrapper,
    fake_tcp::netfilter::create_tun,
    packet_def::{PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType},
};

use futures::Future;
use tokio_util::task::AbortOnDropHandle;

use dashmap::DashMap;

struct IpToIfNameCache {
    ip_to_ifname: DashMap<IpAddr, (String, Option<MacAddr>)>,
}

impl IpToIfNameCache {
    fn new() -> Self {
        Self {
            ip_to_ifname: DashMap::new(),
        }
    }

    fn reload_ip_to_ifname(&self) {
        self.ip_to_ifname.clear();
        let Ok(interfaces) = network_interface::NetworkInterface::show() else {
            tracing::warn!("failed to enumerate interfaces when reloading faketcp ip cache");
            return;
        };
        for iface in interfaces {
            let mac = iface.mac_addr.as_deref().and_then(|mac| {
                mac.parse::<MacAddr>().map_err(|e| {
                    tracing::debug!(iface = %iface.name, mac, ?e, "failed to parse interface mac")
                }).ok()
            });
            for ip in iface.addr.iter() {
                self.ip_to_ifname.insert(ip.ip(), (iface.name.clone(), mac));
            }
        }
    }

    fn get_ifname(&self, ip: &IpAddr) -> Option<(String, Option<MacAddr>)> {
        if let Some(ifname) = self.ip_to_ifname.get(ip) {
            Some(ifname.clone())
        } else {
            self.reload_ip_to_ifname();
            self.ip_to_ifname.get(ip).map(|s| s.clone())
        }
    }
}

fn get_faketcp_tunnel_type_str(driver_type: &str) -> String {
    format!("faketcp_{}", driver_type)
}

async fn create_tun_off_runtime(
    interface_name: String,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> Result<Arc<dyn stack::Tun>, TunnelError> {
    tokio::task::spawn_blocking(move || create_tun(&interface_name, src_addr, dst_addr))
        .await
        .map_err(|e| TunnelError::InternalError(format!("faketcp create_tun task failed: {e}")))?
        .map_err(Into::into)
}

pub struct FakeTcpTunnelListener {
    addr: url::Url,
    os_listener: Option<tokio::net::TcpListener>,
    // interface_name -> fake tcp stack
    stack_map: DashMap<String, Arc<stack::Stack>>,
    // a cache from ip addr to interface name
    ip_to_ifname: IpToIfNameCache,
}

impl FakeTcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        // Define filter: Capture all packets (or refine this if needed)
        // For FakeTCP, we probably want to capture packets destined to us?
        // But `stack::Stack` handles IP/TCP logic.
        // Maybe we just capture everything for now as a raw tunnel?
        // Or better, filter based on some criteria?
        // The user said "satisfy filter function".
        // Let's create a filter that accepts everything for now, or maybe only IP packets?
        FakeTcpTunnelListener {
            addr,
            os_listener: None,
            stack_map: DashMap::new(),
            ip_to_ifname: IpToIfNameCache::new(),
        }
    }

    async fn do_accept(&mut self) -> Result<AcceptResult, TunnelError> {
        loop {
            match self.os_listener.as_mut().unwrap().accept().await {
                Ok((s, remote_addr)) => {
                    let Ok(local_addr) = s.local_addr() else {
                        tracing::warn!("accept fail with local_addr error");
                        continue;
                    };
                    let Some((interface_name, mac)) =
                        self.ip_to_ifname.get_ifname(&local_addr.ip())
                    else {
                        tracing::warn!("accept fail with interface_name error");
                        continue;
                    };
                    return Ok(AcceptResult {
                        socket: s,
                        local_addr,
                        remote_addr,
                        interface_name,
                        mac,
                    });
                }
                Err(e) => {
                    use std::io::ErrorKind::*;
                    if matches!(
                        e.kind(),
                        NotConnected | ConnectionAborted | ConnectionRefused | ConnectionReset
                    ) {
                        tracing::warn!(?e, "accept fail with retryable error: {:?}", e);
                        continue;
                    }
                    tracing::warn!(?e, "accept fail");
                    return Err(e.into());
                }
            }
        }
    }

    async fn get_stack(
        &self,
        accept_result: &AcceptResult,
    ) -> Result<Arc<stack::Stack>, TunnelError> {
        let local_socket_addr = accept_result.local_addr;

        let interface_name = &accept_result.interface_name;

        let (local_ip, local_ip6) = match local_socket_addr.ip() {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        if let Some(entry) = self.stack_map.get(interface_name) {
            let stack = entry.clone();
            drop(entry);

            if !stack.is_closed() {
                return Ok(stack);
            }

            tracing::warn!(
                interface_name,
                "fake_tcp stack reader_task finished, recreating stack"
            );
            self.stack_map.remove(interface_name);
        }

        let tun =
            create_tun_off_runtime(interface_name.to_string(), None, local_socket_addr).await?;
        tracing::info!(
            ?local_socket_addr,
            "create new stack with interface_name: {:?}",
            interface_name
        );
        let stack = Arc::new(stack::Stack::new(
            tun,
            local_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            local_ip6,
            accept_result.mac,
        ));
        self.stack_map
            .insert(interface_name.to_string(), stack.clone());

        Ok(stack)
    }
}

fn build_os_socket_reader_task(mut socket: TcpStream) -> AbortOnDropHandle<()> {
    AbortOnDropHandle::new(tokio::spawn(async move {
        // read the os socket until it's closed
        let mut buf = [0u8; 1024];
        while let Ok(size) = socket.read(&mut buf).await {
            tracing::trace!("read {} bytes from os socket", size);
            if size == 0 {
                break;
            }
        }
        tracing::info!("FakeTcpTunnelListener os socket closed");
    }))
}

#[cfg(feature = "mpquic")]
pub(crate) struct FakeTcpMpPathError {
    pub(crate) error: TunnelError,
}

/// Hold the native port reservation and the tuple guard together. Aborting
/// the kernel socket while the guard is still alive prevents a late FIN/RST
/// or retransmission from reintroducing the kernel into the raw connection.
#[cfg(feature = "mpquic")]
struct KernelTcpReservation {
    stream: Option<TcpStream>,
    _tun: Arc<dyn stack::Tun>,
}

#[cfg(feature = "mpquic")]
impl KernelTcpReservation {
    fn new(stream: TcpStream, tun: Arc<dyn stack::Tun>) -> std::io::Result<Self> {
        // Configure abortive close before any raw takeover, while an error can
        // still close an ordinary native TCP connection safely.
        #[cfg(windows)]
        socket2::SockRef::from(&stream).set_linger(Some(std::time::Duration::ZERO))?;
        Ok(Self {
            stream: Some(stream),
            _tun: tun,
        })
    }
}

#[cfg(feature = "mpquic")]
impl Drop for KernelTcpReservation {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }
    }
}

/// How long (in 100 ms ticks) a committed path keeps its learning keepalive
/// while the peer has not been heard; past that the path is dead anyway.
#[cfg(all(feature = "mpquic", not(windows)))]
const COMMIT_WAIT_TICKS: u32 = 300;

#[cfg(feature = "mpquic")]
fn is_synthetic_sack_fill(payload: &[u8]) -> bool {
    !payload.is_empty() && payload[0] == 0 && payload.iter().all(|byte| *byte == 0)
}

#[cfg(feature = "mpquic")]
fn fits_one_segment(len: usize, remote: SocketAddr, mtu: usize) -> bool {
    len as u64 + crate::tunnel::datagram_carrier::tcp_ip_header_overhead(remote) <= mtu as u64
}

#[cfg(feature = "mpquic")]
pub(crate) struct FakeTcpMpDatagramPath {
    socket: Arc<stack::Socket>,
    _stack: Arc<stack::Stack>,
    interface_name: String,
    // The socket reserves the native tuple. On Windows it is isolated before
    // the path is exposed to QUIC; it must close before the guard is released.
    os_stream: std::sync::Mutex<Option<KernelTcpReservation>>,
    #[cfg(not(windows))]
    os_reader: std::sync::Mutex<Option<AbortOnDropHandle<()>>>,
    dropped_sack_fills: AtomicU64,
    /// Interface MTU; a segment is this minus the TCP/IP headers at most.
    mtu: usize,
    dropped_oversize: AtomicU64,
    /// Segments held back because the peer had not been heard yet, see
    /// `try_send_to`.
    dropped_unlearned: AtomicU64,
}

#[cfg(feature = "mpquic")]
impl Drop for FakeTcpMpDatagramPath {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(feature = "mpquic")]
impl FakeTcpMpDatagramPath {
    pub(crate) fn close(&self) {
        self.socket.close();
        // A failed offer may still be held by the dead-candidate table. Close
        // endpoints immediately; the guard remains pinned through retirement.
        drop(self.os_stream.lock().unwrap().take());
        #[cfg(not(windows))]
        drop(self.os_reader.lock().unwrap().take());
    }

    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.socket.remote_addr()
    }

    pub(crate) fn egress_device(&self) -> &str {
        &self.interface_name
    }

    /// Finish registration. Windows paths already own their tuple before they
    /// can be registered; other backends retain their existing drain lifecycle.
    pub(crate) fn commit(self: &Arc<Self>) {
        // Windows takeover is complete before registration, including paths
        // added to an existing session. No deferred drain/learning task is needed.
        #[cfg(windows)]
        return;
        #[cfg(not(windows))]
        self.commit_sniffed_path();
    }

    #[cfg(not(windows))]
    fn commit_sniffed_path(self: &Arc<Self>) {
        if self.socket.has_heard_peer() {
            self.hand_over_os_stream();
            return;
        }
        let path = Arc::downgrade(self);
        tokio::spawn(async move {
            for _ in 0..COMMIT_WAIT_TICKS {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let Some(path) = path.upgrade() else {
                    return;
                };
                if path.socket.has_heard_peer() {
                    path.hand_over_os_stream();
                    return;
                }
            }
            if let Some(path) = path.upgrade() {
                path.hand_over_os_stream();
            }
        });
    }

    #[cfg(not(windows))]
    fn hand_over_os_stream(&self) {
        let Some(mut reservation) = self.os_stream.lock().unwrap().take() else {
            return;
        };
        if let Err(error) = set_mac_learning_keepalive(reservation.stream.as_ref().unwrap(), false)
        {
            tracing::warn!(?error, "failed to disable FakeTCP learning keepalive");
        }
        *self.os_reader.lock().unwrap() = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let stream = reservation.stream.as_mut().unwrap();
            while let Ok(size) = stream.read(&mut buf).await {
                if size == 0 {
                    break;
                }
            }
        })));
    }
}

/// A socket made from an already established stream starts without the next-hop
/// MAC and with seq/ack 0; unlike connect/accept, nothing arrives to learn them
/// from while both ends wait for each other. A 1 s keepalive makes each peer
/// kernel answer on the punched tuple, which the stack sees and learns from.
#[cfg(feature = "mpquic")]
fn set_mac_learning_keepalive(stream: &TcpStream, enabled: bool) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(stream);
    if enabled {
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(1))
                .with_interval(std::time::Duration::from_secs(1)),
        )
    } else {
        socket.set_keepalive(false)
    }
}

#[cfg(feature = "mpquic")]
#[async_trait::async_trait]
impl crate::tunnel::mpquic::MpDatagramPath for FakeTcpMpDatagramPath {
    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
        if remote != self.socket.remote_addr() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "FakeTCP path is connected to {}, not {remote}",
                    self.socket.remote_addr()
                ),
            ));
        }
        // A socket made from an established stream starts with seq 0, ack 0
        // and an all-zero next-hop MAC; none of it is the connection's. Until
        // a segment from the peer has taught it the real numbers and MAC, such
        // a segment is wrong on the wire: a middlebox tracking the TCP window
        // sees one outside it. Phantun and udp2raw send nothing before their
        // numbers are agreed either. QUIC resends the lost packet, and the
        // keepalive on the kernel socket (`set_mac_learning_keepalive`) is what
        // makes the peer answer so that the numbers get learned.
        if !self.socket.has_heard_peer() {
            let dropped = self.dropped_unlearned.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped <= 8 || dropped.is_power_of_two() {
                tracing::debug!(
                    target: "mpq",
                    len = payload.len(),
                    dropped,
                    "held back a FakeTCP segment: the peer has not been heard yet"
                );
            }
            return Ok(payload.len());
        }
        // TQUIC sizes datagrams for UDP (DPLPMTUD probes up to 1472), and a
        // TCP header is 12 bytes bigger: the packet socket refuses such a
        // frame outright. Drop it as the network would, so the probe is
        // declared lost and the path keeps working at the size that fits.
        if !fits_one_segment(payload.len(), remote, self.mtu) {
            let dropped = self.dropped_oversize.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped <= 8 || dropped.is_power_of_two() {
                tracing::debug!(
                    target: "mpq",
                    len = payload.len(),
                    mtu = self.mtu,
                    dropped,
                    "dropped a datagram too large for the FakeTCP path"
                );
            }
            return Ok(payload.len());
        }
        self.socket.try_send(payload).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "FakeTCP path is closed")
        })?;
        Ok(payload.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let mut payload = BytesMut::new();
            let n = self.socket.recv(&mut payload).await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "FakeTCP path is closed")
            })?;
            if is_synthetic_sack_fill(&payload[..n]) {
                let dropped = self.dropped_sack_fills.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped <= 8 || dropped.is_power_of_two() {
                    tracing::debug!(
                        target: "mpq",
                        n,
                        dropped,
                        "dropped synthetic FakeTCP SACK fill before TQUIC"
                    );
                }
                continue;
            }
            if n > buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "FakeTCP datagram size {n} exceeds receive buffer {}",
                        buf.len()
                    ),
                ));
            }
            buf[..n].copy_from_slice(&payload[..n]);
            return Ok((n, self.socket.remote_addr()));
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    /// A FakeTCP path's wire encapsulation is a real OS TCP socket, not a
    /// raw UDP datagram (MP_SQM_PLAN.md S1.2): inheriting the trait's default
    /// `udp_ip_header_overhead` would under-account every send by the
    /// TCP-vs-UDP header difference (12 bytes for IPv4, also 12 for IPv6).
    fn per_packet_overhead(&self, remote: SocketAddr) -> u64 {
        crate::tunnel::datagram_carrier::tcp_ip_header_overhead(remote)
    }
}

#[cfg(feature = "mpquic")]
pub(crate) async fn mp_datagram_path_from_tcp_stream(
    stream: TcpStream,
) -> Result<Arc<FakeTcpMpDatagramPath>, FakeTcpMpPathError> {
    let local_addr = match stream.local_addr() {
        Ok(addr) => addr,
        Err(error) => {
            return Err(FakeTcpMpPathError {
                error: error.into(),
            });
        }
    };
    let remote_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(error) => {
            return Err(FakeTcpMpPathError {
                error: error.into(),
            });
        }
    };
    let cache = IpToIfNameCache::new();
    let (interface_name, mac) = match cache.get_ifname(&local_addr.ip()) {
        Some(value) => value,
        None => {
            return Err(FakeTcpMpPathError {
                error: TunnelError::InternalError(format!(
                    "no interface found for punched TCP local address {local_addr}"
                )),
            });
        }
    };
    let (local_ip, local_ip6) = match local_addr.ip() {
        IpAddr::V4(ip) => (ip, None),
        IpAddr::V6(ip) => (Ipv4Addr::UNSPECIFIED, Some(ip)),
    };
    let tun_interface = interface_name.clone();
    let tun = tokio::task::spawn_blocking(move || {
        netfilter::create_mp_tun(&tun_interface, remote_addr, local_addr)
    })
    .await
    .map_err(|error| FakeTcpMpPathError {
        error: TunnelError::InternalError(format!("FakeTCP MP capture task failed: {error}")),
    })?
    .map_err(|error| FakeTcpMpPathError {
        error: error.into(),
    })?;
    let reservation =
        KernelTcpReservation::new(stream, tun.clone()).map_err(|error| FakeTcpMpPathError {
            error: error.into(),
        })?;
    let stream = reservation.stream.as_ref().unwrap();
    let stack = Arc::new(stack::Stack::new(tun.clone(), local_ip, local_ip6, mac));
    let Some(socket) =
        stack.try_alloc_established_socket(local_addr, remote_addr, stack::State::Established)
    else {
        return Err(FakeTcpMpPathError {
            error: TunnelError::InternalError(
                "FakeTCP stack closed while upgrading punched TCP stream".into(),
            ),
        });
    };
    set_mac_learning_keepalive(stream, true).map_err(|error| FakeTcpMpPathError {
        error: error.into(),
    })?;
    #[cfg(windows)]
    {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            socket.learn_for_takeover(),
        )
        .await
        .map_err(|_| FakeTcpMpPathError {
            error: TunnelError::InternalError("FakeTCP sequence learning timed out".into()),
        })?
        .map_err(|error| FakeTcpMpPathError {
            error: error.into(),
        })?;
        tokio::task::spawn_blocking(move || tun.isolate_kernel_tcp())
            .await
            .map_err(|error| FakeTcpMpPathError {
                error: TunnelError::InternalError(format!("FakeTCP takeover task failed: {error}")),
            })?
            .map_err(|error| FakeTcpMpPathError {
                error: error.into(),
            })?;
        set_mac_learning_keepalive(stream, false).map_err(|error| FakeTcpMpPathError {
            error: error.into(),
        })?;
    }
    let mtu = crate::common::ifcfg::interface_mtu(&interface_name).unwrap_or(1500) as usize;

    Ok(Arc::new(FakeTcpMpDatagramPath {
        socket: Arc::new(socket),
        _stack: stack,
        interface_name,
        os_stream: std::sync::Mutex::new(Some(reservation)),
        #[cfg(not(windows))]
        os_reader: std::sync::Mutex::new(None),
        dropped_sack_fills: AtomicU64::new(0),
        mtu,
        dropped_oversize: AtomicU64::new(0),
        dropped_unlearned: AtomicU64::new(0),
    }))
}

#[derive(Debug)]
struct AcceptResult {
    socket: TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    interface_name: String,
    mac: Option<MacAddr>,
}

#[async_trait::async_trait]
impl TunnelListener for FakeTcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let port = self.addr.port().unwrap_or(0);
        let bind_addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let os_listener = tokio::net::TcpListener::bind(bind_addr).await?;
        tracing::info!(port, "FakeTcpTunnelListener listening");
        self.os_listener = Some(os_listener);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::debug!("FakeTcpTunnelListener waiting for accept");
        let (res, stack, socket) = loop {
            let res = self.do_accept().await?;
            let stack = self.get_stack(&res).await?;
            let socket = stack.try_alloc_established_socket(
                res.local_addr,
                res.remote_addr,
                stack::State::Established,
            );
            let Some(socket) = socket else {
                tracing::warn!(
                    interface_name = res.interface_name,
                    "fake_tcp stack closed while accepting connection, dropping accepted socket"
                );
                self.stack_map.remove(&res.interface_name);
                continue;
            };
            break (res, stack, socket);
        };

        tracing::info!(
            ?res,
            remote = socket.remote_addr().to_string(),
            "FakeTcpTunnelListener accepted connection"
        );

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(stack.driver_type()),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
            resolved_remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
        };

        // We treat the fake tcp socket as a datagram tunnel directly
        // The reader/writer will interface with the socket using recv_bytes/send
        // We need to adapt the socket to ZCPacketStream and ZCPacketSink

        // Since FakeTcpTunnel is a datagram tunnel, we don't need FramedReader/Writer (which are for stream based tunnels like TCP)
        // We should wrap the socket into something that produces/consumes ZCPacket directly.

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(Box::new(build_os_socket_reader_task(res.socket))),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct FakeTcpTunnelConnector {
    addr: url::Url,
    ip_to_if_name: IpToIfNameCache,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl FakeTcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        FakeTcpTunnelConnector {
            addr,
            ip_to_if_name: IpToIfNameCache::new(),
            resolved_addr: None,
            socket_mark: None,
        }
    }
}

fn get_local_ip_for_destination(destination: IpAddr) -> Option<IpAddr> {
    // 使用一个不可路由的、私有的、或回环地址创建一个临时的 socket，让内核自动选择源接口。
    // 对于 IPv4，使用 0.0.0.0; 对于 IPv6，使用 ::
    let bind_addr = if destination.is_ipv4() {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    };

    // 绑定到一个临时端口 (0)
    let socket = UdpSocket::bind((bind_addr, 0)).ok()?;

    // 尝试连接到目标地址。这不会真正发送数据包，只是让内核确定路由。
    socket.connect((destination, 80)).ok()?; // 使用一个常见的端口，例如 80

    // 获取 socket 的本地地址信息
    socket.local_addr().map(|addr| addr.ip()).ok()
}

#[async_trait::async_trait]
impl TunnelConnector for FakeTcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let remote_addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?,
        };
        let local_ip = get_local_ip_for_destination(remote_addr.ip())
            .ok_or(TunnelError::InternalError("Failed to get local ip".into()))?;

        let os_socket = tokio::net::TcpSocket::new_v4()?;
        // SO_MARK applies only to the kernel-visible "decoy" socket below.
        // The actual FakeTCP payload travels via crafted segments written
        // straight to the TUN device, which the kernel doesn't tag with
        // SO_MARK. Operators relying on fwmark for FakeTCP must mark the
        // TUN device's traffic with a separate nftables/iptables rule.
        crate::tunnel::common::apply_socket_mark(
            &socket2::SockRef::from(&os_socket),
            self.socket_mark,
        )?;
        os_socket.bind("0.0.0.0:0".parse().unwrap())?;
        let local_port = os_socket.local_addr()?.port();
        let local_addr = SocketAddr::new(local_ip, local_port);

        let (interface_name, mac) =
            self.ip_to_if_name
                .get_ifname(&local_ip)
                .ok_or(TunnelError::InternalError(
                    "Failed to get interface name".into(),
                ))?;

        let (local_ip, local_ip6) = match local_ip {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        let tun =
            create_tun_off_runtime(interface_name.clone(), Some(remote_addr), local_addr).await?;
        let local_ip = local_ip.unwrap_or("0.0.0.0".parse().unwrap());
        let stack = stack::Stack::new(tun, local_ip, local_ip6, mac);
        let driver_type = stack.driver_type();

        let socket = stack
            .try_alloc_established_socket(local_addr, remote_addr, stack::State::SynSent)
            .ok_or(TunnelError::InternalError(
                "FakeTCP stack closed while allocating socket".into(),
            ))?;

        let os_stream = os_socket.connect(remote_addr).await?;

        tracing::info!(?remote_addr, "FakeTcpTunnelConnector connecting");

        let mut buf = BytesMut::new();
        socket
            .recv(&mut buf)
            .await
            .ok_or(TunnelError::InternalError(
                "Failed to recv bytes to establish connection".into(),
            ))?;

        tracing::info!(local_addr = ?socket.local_addr(), "FakeTcpTunnelConnector connected");

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(driver_type),
            local_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.local_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(&remote_addr.to_string(), "faketcp")
                    .into(),
            ),
        };

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(Box::new((build_os_socket_reader_task(os_stream), stack))),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

type RecvFut = Pin<Box<dyn Future<Output = Option<(BytesMut, usize)>> + Send + Sync>>;

enum FakeTcpStreamState {
    ConsumingBuf(BytesMut),
    PollFuture(RecvFut),
    Closed,
}

struct FakeTcpStream {
    socket: Arc<stack::Socket>,
    state: FakeTcpStreamState,
}

impl FakeTcpStream {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self {
            socket,
            state: FakeTcpStreamState::ConsumingBuf(BytesMut::new()),
        }
    }
}

impl Stream for FakeTcpStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        loop {
            let state = std::mem::replace(&mut s.state, FakeTcpStreamState::Closed);
            match state {
                FakeTcpStreamState::ConsumingBuf(buf) => {
                    let buf_len = buf.len();
                    // check peer manager header and split buf out
                    let packet = ZCPacket::new_from_buf(buf, ZCPacketType::TCP);
                    if let Some(tcp_hdr) = packet.tcp_tunnel_header() {
                        let expected_payload_len = tcp_hdr.len.get() as usize;
                        let min_packet_len = TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE;
                        if expected_payload_len < min_packet_len {
                            tracing::warn!(
                                "drop fake tcp packet with invalid length: expected_payload_len={}, min_required={}",
                                expected_payload_len,
                                min_packet_len
                            );
                            s.state = FakeTcpStreamState::Closed;
                            return Poll::Ready(None);
                        }

                        if expected_payload_len <= buf_len {
                            let mut buf = packet.inner();
                            let new_inner = buf.split_to(expected_payload_len);
                            s.state = FakeTcpStreamState::ConsumingBuf(buf);
                            return Poll::Ready(Some(Ok(ZCPacket::new_from_buf(
                                new_inner,
                                ZCPacketType::TCP,
                            ))));
                        }
                    }

                    let mut buf = packet.inner();
                    buf.truncate(0);

                    let socket = s.socket.clone();
                    s.state = FakeTcpStreamState::PollFuture(Box::pin(async move {
                        let ret = socket.recv(&mut buf).await;
                        ret.map(|s| (buf, s))
                    }));
                }
                FakeTcpStreamState::PollFuture(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Some((buf, _sz))) => {
                        s.state = FakeTcpStreamState::ConsumingBuf(buf);
                    }
                    Poll::Ready(None) => {
                        s.state = FakeTcpStreamState::Closed;
                    }
                    Poll::Pending => {
                        s.state = FakeTcpStreamState::PollFuture(fut);
                        return Poll::Pending;
                    }
                },
                FakeTcpStreamState::Closed => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

struct FakeTcpSink {
    socket: Arc<stack::Socket>,
}

impl FakeTcpSink {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self { socket }
    }
}

impl Sink<SinkItem> for FakeTcpSink {
    type Error = SinkError;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        // We need to send the packet as bytes
        // The item is ZCPacket, which has into_bytes() method
        let mut packet = item.convert_type(ZCPacketType::TCP);
        let len = packet.buf_len();
        packet.mut_tcp_tunnel_header().unwrap().len.set(len as u32);
        self.socket.try_send(&packet.into_bytes());

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.socket.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::_tunnel_pingpong;

    use super::*;

    #[cfg(feature = "mpquic")]
    #[test]
    fn mp_path_rejects_synthetic_sack_fill_payloads() {
        assert!(is_synthetic_sack_fill(&[0, 0]));
        assert!(is_synthetic_sack_fill(&vec![0; 832]));
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn mp_path_keeps_non_synthetic_quic_payloads() {
        assert!(!is_synthetic_sack_fill(&[]));
        assert!(!is_synthetic_sack_fill(&[0x40, 0, 0]));
        assert!(!is_synthetic_sack_fill(&[0, 0, 1]));
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn a_udp_sized_probe_does_not_fit_a_fake_tcp_segment() {
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        // 1472 fills a 1500 MTU as UDP but is 12 bytes too big as TCP.
        assert!(!fits_one_segment(1472, v4, 1500));
        assert!(fits_one_segment(1460, v4, 1500));
        assert!(!fits_one_segment(1441, v6, 1500));
        assert!(fits_one_segment(1440, v6, 1500));
        assert!(fits_one_segment(1200, v4, 1280));
    }

    /// Run the same production carrier against a peer on another OS. The
    /// fixture supplies an isolated TCP listener and captures its tuple.
    #[cfg(feature = "mpquic")]
    #[tokio::test]
    #[ignore = "requires paired privileged processes and ET_FAKETCP_TEST_ROLE/ADDR"]
    async fn mp_carrier_against_external_peer() {
        use crate::tunnel::mpquic::MpDatagramPath;
        use tokio::time::{Duration, timeout};

        let role = std::env::var("ET_FAKETCP_TEST_ROLE").unwrap();
        let address = std::env::var("ET_FAKETCP_TEST_ADDR").unwrap();
        let stream = match role.as_str() {
            "server" => {
                let listener = tokio::net::TcpListener::bind(&address).await.unwrap();
                println!("FAKETCP_LISTEN {}", listener.local_addr().unwrap());
                timeout(Duration::from_secs(30), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0
            }
            "client" => timeout(Duration::from_secs(10), TcpStream::connect(&address))
                .await
                .unwrap()
                .unwrap(),
            _ => panic!("unknown carrier test role: {role}"),
        };
        println!(
            "FAKETCP_TUPLE {} {}",
            stream.local_addr().unwrap(),
            stream.peer_addr().unwrap()
        );
        let path = mp_datagram_path_from_tcp_stream(stream)
            .await
            .unwrap_or_else(|failure| panic!("carrier takeover failed: {}", failure.error));
        path.commit();
        let remote = path.remote_addr();
        let mut received = vec![0u8; 2048];
        for round in 0..32u8 {
            let size = [32usize, 512, 1200][round as usize % 3];
            let mut expected = vec![round.wrapping_add(1); size];
            expected[0] = 0x40;
            expected[1] = round;
            if role == "client" {
                assert_eq!(path.try_send_to(&expected, remote).unwrap(), size);
            }
            let (count, from) = timeout(Duration::from_secs(10), path.recv_from(&mut received))
                .await
                .unwrap_or_else(|_| panic!("carrier round {round} timed out"))
                .unwrap();
            assert_eq!(from, remote);
            assert_eq!(&received[..count], &expected, "carrier round {round}");
            if role == "server" {
                assert_eq!(path.try_send_to(&expected, remote).unwrap(), size);
            }
        }
        println!("FAKETCP_TRANSFER_OK {role} 32");
        // Keep receiving during idle: this exercises the path's ACK handling
        // rather than leaving the capture queue unread. The fixture counts
        // all wire TCP ACKs, including packets consumed internally here.
        if role == "client" {
            assert!(
                timeout(Duration::from_secs(3), path.recv_from(&mut received))
                    .await
                    .is_err()
            );
            println!("FAKETCP_IDLE_OK {role}");
        } else {
            let closed = timeout(Duration::from_secs(10), path.recv_from(&mut received))
                .await
                .expect("peer close was not delivered");
            assert_eq!(closed.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
            println!("FAKETCP_PEER_CLOSE_OK {role}");
        }
        path.close();
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn mp_upgrade_keepalive_is_one_second_and_can_be_turned_off() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let socket = socket2::SockRef::from(&client);

        set_mac_learning_keepalive(&client, true).unwrap();
        assert!(socket.keepalive().unwrap());
        // socket2 can read the idle time back only on Unix.
        #[cfg(unix)]
        assert_eq!(
            socket.keepalive_time().unwrap(),
            std::time::Duration::from_secs(1)
        );

        set_mac_learning_keepalive(&client, false).unwrap();
        assert!(!socket.keepalive().unwrap());
    }

    #[cfg(all(feature = "mpquic", windows))]
    #[tokio::test]
    async fn takeover_reservation_closes_native_socket_before_releasing_guard() {
        use std::os::windows::io::AsRawSocket;
        use std::sync::atomic::AtomicBool;
        use windows::Win32::Networking::WinSock::{
            SO_TYPE, SOCKET, SOCKET_ERROR, SOL_SOCKET, getsockopt,
        };
        struct CloseGuard {
            socket: SOCKET,
            checked: Arc<AtomicBool>,
        }
        impl Drop for CloseGuard {
            fn drop(&mut self) {
                let mut kind = 0i32;
                let mut len = std::mem::size_of_val(&kind) as i32;
                // Inspect the borrowed numeric handle; do not construct an
                // owning socket or attempt to close it a second time.
                let result = unsafe {
                    getsockopt(
                        self.socket,
                        SOL_SOCKET,
                        SO_TYPE,
                        windows::core::PSTR((&mut kind as *mut i32).cast()),
                        &mut len,
                    )
                };
                assert_eq!(
                    result, SOCKET_ERROR,
                    "guard retired before native socket closed"
                );
                self.checked.store(true, Ordering::Relaxed);
            }
        }
        #[async_trait::async_trait]
        impl stack::Tun for CloseGuard {
            async fn recv(&self, _: &mut BytesMut) -> std::io::Result<usize> {
                std::future::pending().await
            }
            fn try_send(&self, _: &bytes::Bytes) -> std::io::Result<()> {
                Ok(())
            }
            fn driver_type(&self) -> &'static str {
                "close-order"
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let checked = Arc::new(AtomicBool::new(false));
        let guard = Arc::new(CloseGuard {
            socket: SOCKET(stream.as_raw_socket() as usize),
            checked: checked.clone(),
        });
        let reservation = KernelTcpReservation::new(stream, guard).unwrap();
        assert_eq!(
            socket2::SockRef::from(reservation.stream.as_ref().unwrap())
                .linger()
                .unwrap(),
            Some(std::time::Duration::ZERO)
        );
        drop(reservation);
        assert!(checked.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn faketcp_pingpong() {
        #[cfg(target_family = "unix")]
        {
            if unsafe { nix::libc::geteuid() } != 0 {
                return;
            }
        }

        let listener = FakeTcpTunnelListener::new("faketcp://0.0.0.0:31011".parse().unwrap());
        let connector = FakeTcpTunnelConnector::new("faketcp://127.0.0.1:31011".parse().unwrap());

        _tunnel_pingpong(listener, connector).await
    }
}
