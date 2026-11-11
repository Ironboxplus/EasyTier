use parking_lot::Mutex;
use smoltcp::{
    iface::{SocketHandle as InnerSocketHandle, SocketSet},
    socket::{tcp, udp},
    time::{Duration, Instant},
};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::mpsc;

/// `BufferSize` is used to configure the size of the socket buffer.
#[derive(Debug, Clone, Copy)]
pub struct BufferSize {
    pub tcp_rx_size: usize,
    pub tcp_tx_size: usize,

    pub udp_rx_size: usize,
    pub udp_tx_size: usize,
    pub udp_rx_meta_size: usize,
    pub udp_tx_meta_size: usize,
}

impl Default for BufferSize {
    fn default() -> Self {
        BufferSize {
            tcp_rx_size: 8192,
            tcp_tx_size: 8192,

            udp_rx_size: 8192,
            udp_tx_size: 8192,
            udp_rx_meta_size: 32,
            udp_tx_meta_size: 32,
        }
    }
}

type SharedSocketSet = Arc<Mutex<SocketSet<'static>>>;

/// How long a socket released by its application may take to finish closing, however many
/// ACKs keep the ordinary inactivity timeout from firing. The same as that timeout.
#[cfg(not(test))]
pub(super) const TCP_TIMEOUT: Duration = Duration::from_secs(60);
/// Short under test, so a peer that never closes its half can be seen reset in seconds.
#[cfg(test)]
pub(super) const TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// A TCP socket whose application is gone. The reactor finishes its teardown: FIN
/// retransmissions, the peer's FIN, TIME-WAIT. Dropping the handle removes the socket.
pub(super) struct ClosingTcpSocket {
    pub(super) handle: SocketHandle,
    pub(super) deadline: Instant,
}

pub(super) type ClosingTcpSender = mpsc::UnboundedSender<ClosingTcpSocket>;

#[derive(Clone)]
pub struct SocketAlloctor {
    sockets: SharedSocketSet,
    buffer_size: BufferSize,
    closing_tcp: Option<ClosingTcpSender>,
}

impl SocketAlloctor {
    pub(crate) fn new(buffer_size: BufferSize) -> SocketAlloctor {
        let sockets = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        SocketAlloctor {
            sockets,
            buffer_size,
            closing_tcp: None,
        }
    }
    /// Hands TCP sockets that are dropped while still open to `closing_tcp`'s receiver.
    pub(super) fn with_closing_tcp(mut self, closing_tcp: ClosingTcpSender) -> SocketAlloctor {
        self.closing_tcp = Some(closing_tcp);
        self
    }
    pub(crate) fn sockets(&self) -> &SharedSocketSet {
        &self.sockets
    }
    pub fn new_tcp_socket(&self) -> SocketHandle {
        let mut set = self.sockets.lock();
        let handle = set.add(self.alloc_tcp_socket());
        SocketHandle::new_tcp(handle, self.sockets.clone(), self.closing_tcp.clone())
    }
    fn alloc_tcp_socket(&self) -> tcp::Socket<'static> {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_rx_size]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_tx_size]);
        let mut tcp = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp.set_nagle_enabled(false);
        tcp.set_keep_alive(Some(Duration::from_secs(10)));
        tcp.set_timeout(Some(Duration::from_secs(60)));

        tcp
    }

    pub fn new_udp_socket(&self) -> SocketHandle {
        let mut set = self.sockets.lock();
        let handle = set.add(self.alloc_udp_socket());
        SocketHandle(handle, self.sockets.clone(), None)
    }

    fn alloc_udp_socket(&self) -> udp::Socket<'static> {
        let rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_rx_meta_size],
            vec![0; self.buffer_size.udp_rx_size],
        );
        let tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_tx_meta_size],
            vec![0; self.buffer_size.udp_tx_size],
        );

        udp::Socket::new(rx_buffer, tx_buffer)
    }
}

/// The third field is set for TCP sockets only: where to hand the socket over when it is
/// dropped before its connection has closed.
pub struct SocketHandle(InnerSocketHandle, SharedSocketSet, Option<ClosingTcpSender>);

impl SocketHandle {
    fn new_tcp(
        inner: InnerSocketHandle,
        set: SharedSocketSet,
        closing_tcp: Option<ClosingTcpSender>,
    ) -> SocketHandle {
        SocketHandle(inner, set, closing_tcp)
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        if let Some(closing_tcp) = self.2.take() {
            // Removing an open connection's socket sends nothing: the peer never gets the
            // FIN, and what is still queued for it is lost. Close it and let the reactor
            // see the teardown through.
            let teardown_pending = {
                let mut sockets = self.1.lock();
                let socket = sockets.get_mut::<tcp::Socket>(self.0);
                socket.close();
                socket.state() != tcp::State::Closed
            };
            if teardown_pending {
                // Not under the lock: a handle that is dropped unsent removes its socket.
                let _ = closing_tcp.send(ClosingTcpSocket {
                    handle: SocketHandle(self.0, self.1.clone(), None),
                    deadline: Instant::now() + TCP_TIMEOUT,
                });
                return;
            }
        }
        let mut iface = self.1.lock();
        iface.remove(self.0);
    }
}

impl Deref for SocketHandle {
    type Target = InnerSocketHandle;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SocketHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
