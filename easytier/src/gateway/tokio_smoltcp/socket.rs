use super::{reactor::Reactor, socket_allocator::SocketHandle};
use futures::future::{self, poll_fn};
use futures::{Stream, ready};
pub use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::mem::replace;
use std::net::IpAddr;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A TCP socket server, listening for connections.
///
/// You can accept a new connection by using the accept method.
pub struct TcpListener {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

fn map_err<E: std::error::Error>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

impl TcpListener {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<TcpListener> {
        let handle = reactor.socket_allocator().new_tcp_socket();
        {
            let mut socket = reactor.get_socket::<tcp::Socket>(*handle);
            socket.listen(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);
        Ok(TcpListener {
            handle,
            reactor,
            local_addr,
        })
    }
    pub fn poll_accept(&mut self, cx: &Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.state() == tcp::State::Established {
            drop(socket);
            return Poll::Ready(Ok(TcpStream::accept(self)?));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
    pub fn incoming(self) -> Incoming {
        Incoming(self)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn relisten(&self) {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        let local_endpoint = socket.local_endpoint().unwrap();
        socket.abort();
        socket.listen(local_endpoint).unwrap();
        self.reactor.notify();
    }

    pub fn is_listening(&self) -> bool {
        let socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        socket.is_listening()
    }
}

pub struct Incoming(TcpListener);

impl Stream for Incoming {
    type Item = io::Result<TcpStream>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (tcp, _) = ready!(self.0.poll_accept(cx))?;
        Poll::Ready(Some(Ok(tcp)))
    }
}

fn ep2sa(ep: &IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(v6), ep.port),
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpStream {
    pub(super) async fn connect(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
        remote_endpoint: IpEndpoint,
    ) -> io::Result<TcpStream> {
        let handle = reactor.socket_allocator().new_tcp_socket();

        // see https://github.com/spacemeowx2/tokio-smoltcp/pull/12
        let connect_result = {
            // Issue #11. We must lock the context before we call connect to
            // avoid lock inversion deadlocks, but drop it before constructing
            // the TcpStream to avoid a second mutable borror of the reactor.
            let mut context = reactor.context();
            reactor.get_socket::<tcp::Socket>(*handle).connect(
                &mut context,
                remote_endpoint,
                local_endpoint,
            )
        };
        connect_result.map_err(map_err)?;

        let local_addr = ep2sa(&local_endpoint);
        let peer_addr = ep2sa(&remote_endpoint);
        let tcp = TcpStream {
            handle,
            reactor,
            local_addr,
            peer_addr,
        };

        tcp.reactor.notify();
        future::poll_fn(|cx| tcp.poll_connected(cx)).await?;

        Ok(tcp)
    }

    fn accept(listener: &mut TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
        let reactor = listener.reactor.clone();
        let new_handle = reactor.socket_allocator().new_tcp_socket();
        {
            let mut new_socket = reactor.get_socket::<tcp::Socket>(*new_handle);
            new_socket.listen(listener.local_addr).map_err(map_err)?;
        }
        let (peer_addr, local_addr) = {
            let socket = reactor.get_socket::<tcp::Socket>(*listener.handle);
            match (socket.remote_endpoint(), socket.local_endpoint()) {
                (Some(remote_endpoint), Some(local_endpoint)) => (
                    // should be Some, because the state is Established
                    ep2sa(&remote_endpoint),
                    ep2sa(&local_endpoint),
                ),
                _ => return Err(io::ErrorKind::NotConnected.into()),
            }
        };

        Ok((
            TcpStream {
                handle: replace(&mut listener.handle, new_handle),
                reactor,
                local_addr,
                peer_addr,
            },
            peer_addr,
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
    pub fn poll_connected(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if socket.state() == tcp::State::Established {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        if socket.can_recv() {
            let read = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(map_err)?;
            self.reactor.notify();
            buf.advance(read);
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            let r = socket.send_slice(buf).map_err(map_err)?;
            self.reactor.notify();
            return Poll::Ready(Ok(r));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.is_open() {
            socket.close();
            self.reactor.notify();
        }
        if socket.state() == tcp::State::Closed {
            return Poll::Ready(Ok(()));
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

/// A UDP socket.
pub struct UdpSocket {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

impl UdpSocket {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<UdpSocket> {
        let handle = reactor.socket_allocator().new_udp_socket();
        {
            let mut socket = reactor.get_socket::<udp::Socket>(*handle);
            socket.bind(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);

        Ok(UdpSocket {
            handle,
            reactor,
            local_addr,
        })
    }
    /// Note that on multiple calls to a poll_* method in the send direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_send_to(
        &self,
        cx: &Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);
        let target_ip: IpEndpoint = target.into();

        match socket.send_slice(buf, target_ip) {
            // the buffer is full
            Err(udp::SendError::BufferFull) => {}
            r => {
                r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok(buf.len()));
            }
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_send_to`
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
    /// Note that on multiple calls to a poll_* method in the recv direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_recv_from(
        &self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);

        match socket.recv_slice(buf) {
            // the buffer is empty
            Err(udp::RecvError::Exhausted) => {}
            r => {
                let (size, metadata) = r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok((size, ep2sa(&metadata.endpoint))));
            }
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_recv_from`
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use smoltcp::{
        iface::Config,
        phy::{DeviceCapabilities, Medium},
        wire::{HardwareAddress, Ipv4Packet, TcpPacket},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
        time::timeout,
    };
    use tokio_util::task::AbortOnDropHandle;

    use super::super::{Net, NetConfig, channel_device::ChannelDevice};
    use super::{TcpListener, TcpStream};

    const A_ADDR: &str = "10.126.126.1";
    const B_ADDR: &str = "10.126.126.2";
    const PORT: u16 = 34569;

    fn is_fin(packet: &[u8]) -> bool {
        Ipv4Packet::new_checked(packet)
            .ok()
            .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok().map(|tcp| tcp.fin()))
            .unwrap_or(false)
    }

    /// Carries what one stack sends to the other; `drop_first_fin` loses the first FIN on the way.
    fn pump(
        mut from: mpsc::Receiver<Vec<u8>>,
        to: mpsc::Sender<io::Result<Vec<u8>>>,
        mut drop_first_fin: bool,
    ) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = from.recv().await {
                if drop_first_fin && is_fin(&packet) {
                    drop_first_fin = false;
                    continue;
                }
                if to.send(Ok(packet)).await.is_err() {
                    break;
                }
            }
        }))
    }

    struct Pair {
        a: Net,
        b: Net,
        _pumps: [AbortOnDropHandle<()>; 2],
    }

    /// Two stacks wired back to back; what `a` sends can lose its first FIN.
    fn pair(lose_first_fin_from_a: bool) -> Pair {
        let net = |addr: &str| {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1280;
            caps.medium = Medium::Ip;
            let (device, to_stack, from_stack) = ChannelDevice::new(caps);
            let config = NetConfig::new(
                Config::new(HardwareAddress::Ip),
                format!("{addr}/24").parse().unwrap(),
                vec![],
                None,
            );
            (Net::new(device, config), to_stack, from_stack)
        };
        let (a, a_in, a_out) = net(A_ADDR);
        let (b, b_in, b_out) = net(B_ADDR);
        Pair {
            a,
            b,
            _pumps: [
                pump(a_out, b_in, lose_first_fin_from_a),
                pump(b_out, a_in, false),
            ],
        }
    }

    /// `b` connects to a listener of `a`; returns the stream `a` accepted and the one `b` holds.
    async fn connect(pair: &Pair) -> (TcpStream, TcpStream, TcpListener) {
        let mut listener = pair
            .a
            .tcp_bind(format!("{A_ADDR}:{PORT}").parse().unwrap())
            .await
            .unwrap();
        let (accepted, connected) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                listener.accept(),
                pair.b
                    .tcp_connect(format!("{A_ADDR}:{PORT}").parse().unwrap(), 40000)
            )
        })
        .await
        .expect("the connection was not established");
        (accepted.unwrap().0, connected.unwrap(), listener)
    }

    async fn read_to_end(mut stream: TcpStream) -> io::Result<usize> {
        let mut buf = vec![0; 4096];
        let mut total = 0;
        loop {
            match stream.read(&mut buf).await? {
                0 => return Ok(total),
                n => total += n,
            }
        }
    }

    /// Dropping a stream used to remove its socket silently: the peer was never told, and read
    /// on until its keepalive got a reset ten seconds later.
    #[tokio::test]
    async fn dropped_stream_sends_fin_so_the_peer_reads_eof() {
        let pair = pair(false);
        let (accepted, connected, _listener) = connect(&pair).await;

        drop(accepted);

        let read = timeout(Duration::from_secs(5), read_to_end(connected))
            .await
            .expect("the peer never saw the FIN of the dropped stream");
        assert_eq!(read.unwrap(), 0);
    }

    /// What the application wrote before the drop is still queued in the socket; it must reach
    /// the peer ahead of the FIN.
    #[tokio::test]
    async fn data_written_before_the_drop_reaches_the_peer_ahead_of_the_fin() {
        let pair = pair(false);
        let (mut accepted, connected, _listener) = connect(&pair).await;
        let reader = tokio::spawn(timeout(Duration::from_secs(10), read_to_end(connected)));

        // Far more than the 8 KiB send buffer, so the tail is still queued when write_all returns.
        accepted.write_all(&vec![7; 64 * 1024]).await.unwrap();
        drop(accepted);

        let total = reader
            .await
            .unwrap()
            .expect("the peer never saw the end of the stream")
            .unwrap();
        assert_eq!(total, 64 * 1024);
    }

    /// With the application handle gone, the stack itself must keep retransmitting a lost FIN.
    #[tokio::test]
    async fn lost_fin_of_a_dropped_stream_is_retransmitted() {
        let pair = pair(true);
        let (accepted, connected, _listener) = connect(&pair).await;

        drop(accepted);

        let read = timeout(Duration::from_secs(8), read_to_end(connected))
            .await
            .expect("the lost FIN was never retransmitted");
        assert_eq!(read.unwrap(), 0);
    }

    /// A peer that ACKs our FIN but never closes its own half would leave the socket in
    /// FIN-WAIT-2 for good; the absolute deadline (2 s under test) resets and releases it.
    #[tokio::test]
    async fn a_peer_that_never_closes_is_reset_at_the_deadline() {
        let pair = pair(false);
        let (accepted, mut connected, listener) = connect(&pair).await;
        let reactor = pair.a.reactor.clone();
        drop(listener);

        drop(accepted);
        let mut buf = [0; 16];
        let read = timeout(Duration::from_secs(1), connected.read(&mut buf))
            .await
            .expect("the peer never saw the FIN");
        assert_eq!(read.unwrap(), 0);

        // `connected` keeps its half open: the socket stays for its teardown, not removed at once.
        assert_eq!(reactor.socket_allocator().sockets().lock().iter().count(), 1);
        timeout(Duration::from_secs(6), async {
            while reactor.socket_allocator().sockets().lock().iter().count() != 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the closing socket was never released at its deadline");
    }

    /// Stopping the stack releases every socket, closing ones included.
    #[tokio::test]
    async fn stopping_the_stack_releases_closing_sockets() {
        let pair = pair(false);
        let (accepted, _connected, listener) = connect(&pair).await;
        let reactor = pair.a.reactor.clone();

        drop(accepted);
        drop(listener);
        let Pair { a, b, _pumps } = pair;
        drop(a);
        drop(b);

        timeout(Duration::from_secs(2), async {
            while reactor.socket_allocator().sockets().lock().iter().count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("sockets outlived the stopped stack");
    }
}
