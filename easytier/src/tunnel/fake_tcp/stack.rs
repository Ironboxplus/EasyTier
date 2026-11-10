//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

use super::packet::*;
use bytes::{Bytes, BytesMut};
use crossbeam::atomic::AtomicCell;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::{Packet, tcp};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info, trace, warn};

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

#[async_trait::async_trait]
pub trait Tun: Send + Sync + 'static {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error>;
    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error>;
    fn driver_type(&self) -> &'static str;

    /// MP takeover backends also copy native outbound headers for the kernel's
    /// receive sequence. Ordinary sniff-only carriers keep inbound dispatch.
    fn captures_outbound_tcp(&self) -> bool {
        false
    }

    /// Stop the host TCP stack from processing this already-punched tuple.
    /// Sniff-only backends must never silently report a successful takeover.
    fn isolate_kernel_tcp(&self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this packet backend cannot isolate kernel TCP",
        ))
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

#[derive(Default)]
struct StackState {
    tuples: HashMap<AddrTuple, flume::Sender<Bytes>>,
    closed: bool,
}

struct Shared {
    state: RwLock<StackState>,
    listening: RwLock<HashSet<u16>>,
    tun: Arc<dyn Tun>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

impl Shared {
    fn is_closed(&self) -> bool {
        self.state.read().unwrap().closed
    }

    fn mark_closed_and_clear_tuples(&self) -> usize {
        let mut state = self.state.write().unwrap();
        state.closed = true;
        let len = state.tuples.len();
        state.tuples.clear();
        len
    }
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    local_mac: MacAddr,
    reader_task: AbortOnDropHandle<()>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<dyn Tun>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: AtomicCell<Option<MacAddr>>,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: AtomicCell<State>,
    owns_sequence: AtomicBool,
    initial_packets: std::sync::Mutex<VecDeque<Bytes>>,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    #[allow(clippy::too_many_arguments)]
    fn new(
        shared: Arc<Shared>,
        tun: Arc<dyn Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        local_mac: MacAddr,
        remote_mac: Option<MacAddr>,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = hotpath::channel!(flume::bounded(MPMC_BUFFER_LEN));

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                local_mac,
                remote_mac: AtomicCell::new(remote_mac),
                seq: AtomicU32::new(0),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state: AtomicCell::new(state),
                owns_sequence: AtomicBool::new(false),
                initial_packets: std::sync::Mutex::new(VecDeque::new()),
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or(MacAddr::zero()),
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub fn try_send(&self, payload: &[u8]) -> Option<()> {
        match self.state.load() {
            State::Established => {
                let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                let buf = build_tcp_packet(
                    self.local_mac,
                    self.remote_mac.load().unwrap_or(MacAddr::zero()),
                    self.local_addr,
                    self.remote_addr,
                    seq,
                    self.ack.load(Ordering::Relaxed),
                    tcp::TcpFlags::ACK,
                    Some(payload),
                );
                self.tun.try_send(&buf).ok().and(Some(()))
            }
            _ => None,
        }
    }

    pub fn close(&self) {
        if self.state.swap(State::Idle) != State::Idle && self.has_heard_peer() {
            let buf = self.build_tcp_packet(tcp::TcpFlags::RST, None);
            let _ = self.tun.try_send(&buf);
        }
    }

    /// Snapshot SND.NXT from the peer's ACK and RCV.NXT from the kernel's ACK.
    /// A peer's SEG.SEQ alone is ambiguous: keepalive probes use SND.NXT-1.
    /// Preserve inbound packets while waiting for both halves of the snapshot.
    pub async fn learn_for_takeover(&self) -> std::io::Result<()> {
        let mut send_next = None;
        let mut receive_next = None;
        let mut remote_mac = None;
        let mut pending = VecDeque::new();
        loop {
            let packet = self.incoming.recv_async().await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "FakeTCP capture closed")
            })?;
            let Some((src_mac, _, ip, tcp)) = parse_ip_packet(&packet) else {
                continue;
            };
            if tcp.get_flags() & (tcp::TcpFlags::RST | tcp::TcpFlags::FIN) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "punched TCP connection closed during takeover",
                ));
            }
            if tcp.get_flags() & tcp::TcpFlags::ACK == 0
                || tcp.get_flags() & tcp::TcpFlags::SYN != 0
            {
                continue;
            }
            if ip.get_source() == self.local_addr.ip() && tcp.get_source() == self.local_addr.port()
            {
                // The kernel's ACK is RCV.NXT even when this packet is a
                // keepalive with SEG.SEQ=SND.NXT-1 (RFC 9293 section 3.8.4).
                receive_next = Some(tcp.get_acknowledgement());
            } else {
                send_next = Some(tcp.get_acknowledgement());
                remote_mac = Some(src_mac);
                if pending.len() == MPMC_BUFFER_LEN {
                    return Err(std::io::Error::other(
                        "FakeTCP takeover packet queue is full",
                    ));
                }
                pending.push_back(packet);
            }
            if let (Some(seq), Some(ack)) = (send_next, receive_next) {
                self.seq.store(seq, Ordering::Relaxed);
                self.ack.store(ack, Ordering::Relaxed);
                self.remote_mac.store(remote_mac);
                *self.initial_packets.lock().unwrap() = pending;
                self.owns_sequence.store(true, Ordering::Relaxed);
                return Ok(());
            }
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut BytesMut) -> Option<usize> {
        tracing::trace!(
            "Socket recv called, local_addr: {:?}, remote_addr: {:?}",
            self.local_addr,
            self.remote_addr
        );
        loop {
            match self.state.load() {
                State::Established => {
                    let initial = self.initial_packets.lock().unwrap().pop_front();
                    let raw_buf = match initial {
                        Some(packet) => packet,
                        None => match self.incoming.recv_async().await {
                            Ok(packet) => packet,
                            Err(_) => {
                                info!("Connection {} recv error", self);
                                return None;
                            }
                        },
                    };

                    let Some((src_mac, dst_mac, ip_packet, tcp_packet)) = parse_ip_packet(&raw_buf)
                    else {
                        trace!("Dropping malformed fake tcp packet for established socket");
                        continue;
                    };

                    // Native packets copied during learning can still be in
                    // the queue when the full ownership guard is installed.
                    if ip_packet.get_source() == self.local_addr.ip()
                        && tcp_packet.get_source() == self.local_addr.port()
                    {
                        continue;
                    }

                    tracing::trace!(
                        "Socket received TCP packet from {}({:?}) to {}({:?}): {:?}",
                        self.remote_addr,
                        src_mac,
                        self.local_addr,
                        dst_mac,
                        tcp_packet
                    );

                    self.remote_mac.store(Some(src_mac));

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    if self.owns_sequence.load(Ordering::Relaxed)
                        && tcp_packet.get_flags() & tcp::TcpFlags::FIN != 0
                    {
                        return None;
                    }

                    if (tcp_packet.get_flags() & tcp::TcpFlags::ACK) != 0
                        && tcp_packet.payload().is_empty()
                        && !self.owns_sequence.load(Ordering::Relaxed)
                    {
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                    }

                    let payload = tcp_packet.payload();

                    if self.owns_sequence.load(Ordering::Relaxed)
                        && tcp_packet.get_flags() & tcp::TcpFlags::ACK != 0
                        && tcp_packet.get_flags() & tcp::TcpFlags::SYN == 0
                        && payload.len() <= 1
                        && tcp_packet.get_sequence()
                            == self.ack.load(Ordering::Relaxed).wrapping_sub(1)
                    {
                        // Only an out-of-window keepalive probe needs this
                        // response. ACKing ordinary ACKs would create a loop.
                        self.try_send(&[])?;
                        continue;
                    }

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    if self.owns_sequence.load(Ordering::Relaxed) {
                        // RFC 9293 serial arithmetic, including wraparound. A
                        // reordered datagram must not move the advertised ACK back.
                        let _ =
                            self.ack
                                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                                    ((new_ack.wrapping_sub(old) as i32) > 0).then_some(new_ack)
                                });
                    } else {
                        self.ack.store(new_ack, Ordering::Relaxed);
                    }

                    for opt in tcp_packet.get_options_iter() {
                        if self.owns_sequence.load(Ordering::Relaxed) {
                            // QUIC owns recovery. Kernel SACK filler belongs only
                            // to the legacy shared-kernel FakeTCP transport.
                            break;
                        }
                        if opt.get_number() == TcpOptionNumbers::SACK {
                            // SACK 选项类型为 5
                            let payload = opt.payload();
                            for chunk in payload.chunks(8) {
                                if chunk.len() != 8 {
                                    continue;
                                }
                                let left = tcp_packet.get_acknowledgement();
                                let right = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
                                let len = right.wrapping_sub(left);

                                let sack_end = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
                                if len == 0 || sack_end <= left {
                                    continue;
                                }

                                let send_len = std::cmp::min(len, 1400) as usize;
                                let data = vec![0u8; send_len];

                                let buf = build_tcp_packet(
                                    self.local_mac,
                                    self.remote_mac.load().unwrap_or(MacAddr::zero()),
                                    self.local_addr,
                                    self.remote_addr,
                                    left,
                                    self.ack.load(Ordering::Relaxed),
                                    tcp::TcpFlags::ACK,
                                    Some(&data),
                                );

                                if let Err(e) = self.tun.try_send(&buf) {
                                    tracing::error!("Failed to send SACK response: {}", e);
                                }
                                break;
                            }
                        }
                    }

                    if payload.is_empty() {
                        continue;
                    }

                    buf.extend_from_slice(payload);

                    return Some(payload.len());
                }
                State::SynSent => {
                    let Ok(Ok(buf)) = time::timeout(TIMEOUT, self.incoming.recv_async()).await
                    else {
                        info!("Waiting for client SYN + ACK timed out");
                        return None;
                    };
                    let Some((src_mac, _dst_mac, _v4_packet, tcp_packet)) = parse_ip_packet(&buf)
                    else {
                        trace!("Dropping malformed fake tcp packet during handshake");
                        continue;
                    };

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        tracing::trace!("Connection {} reset by peer", self);
                        return None;
                    }

                    let expected_flag = tcp::TcpFlags::SYN | tcp::TcpFlags::ACK;
                    if (tcp_packet.get_flags() & expected_flag) == expected_flag {
                        // found our SYN + ACK
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                        self.ack
                            .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);
                        self.remote_mac.store(Some(src_mac));
                        self.state.store(State::Established);
                        return Some(0);
                    }
                }

                _ => return None,
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Whether a segment from the peer has arrived, teaching this socket the
    /// next-hop MAC and the sequence numbers its own segments must carry.
    pub fn has_heard_peer(&self) -> bool {
        self.remote_mac.load().is_some()
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        let (removed, closed) = {
            let mut state = self.shared.state.write().unwrap();
            (state.tuples.remove(&tuple).is_some(), state.closed)
        };
        if !removed {
            if closed {
                trace!(?tuple, "Fake TCP tuple already removed after stack closed");
            } else {
                warn!(?tuple, "Fake TCP tuple missing while dropping socket");
            }
        }
        // purge cache
        let _ = self.shared.tuples_purge.send(tuple);

        self.close();

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(
        tun: Arc<dyn Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        local_mac: Option<MacAddr>,
    ) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            state: RwLock::new(StackState::default()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            tuples_purge: tuples_purge_tx.clone(),
        });

        let t = tokio::spawn(Stack::reader_task(
            tun,
            shared.clone(),
            tuples_purge_tx.subscribe(),
        ));

        Stack {
            shared,
            local_ip,
            local_ip6,
            local_mac: local_mac.unwrap_or(MacAddr::zero()),
            reader_task: AbortOnDropHandle::new(t),
        }
    }

    /// Returns the driver type of the stack.
    pub fn driver_type(&self) -> &'static str {
        self.shared.tun.driver_type()
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed() || self.reader_task.is_finished()
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    pub fn try_alloc_established_socket(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: State,
    ) -> Option<Socket> {
        let tuple = AddrTuple::new(local_addr, remote_addr);
        let mut stack_state = self.shared.state.write().unwrap();
        if stack_state.closed || self.reader_task.is_finished() {
            stack_state.closed = true;
            warn!(
                ?tuple,
                "fake_tcp stack is closed, refusing to allocate socket"
            );
            return None;
        }
        let (sock, incoming) = Socket::new(
            self.shared.clone(),
            // self.shared.tun.choose(&mut rng).unwrap().clone(),
            self.shared.tun.clone(), // Simplification: just use the first tun
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            Some(0), // Initial ACK
            state,
        );
        assert!(stack_state.tuples.insert(tuple, incoming).is_none());
        Some(sock)
    }

    async fn reader_task(
        tun: Arc<dyn Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::new();

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = match size {
                        Ok(size) => size,
                        Err(e) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            error!(
                                ?e,
                                driver_type = tun.driver_type(),
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tun recv failed, reader_task exiting"
                            );
                            break;
                        }
                    };
                    tracing::trace!(len = size, ?buf, "PnetTun received packet");
                    let buf = buf.split().freeze();

                    match parse_ip_packet(&buf) {
                        Some((_src_mac, _dst_mac, ip_packet, tcp_packet)) => {
                            let local_addr = SocketAddr::new(
                                ip_packet.get_destination(),
                                tcp_packet.get_destination(),
                            );
                            let remote_addr = SocketAddr::new(
                                ip_packet.get_source(),
                                tcp_packet.get_source(),
                            );

                            let mut tuple = AddrTuple::new(local_addr, remote_addr);
                            if tun.captures_outbound_tcp() && !tuples.contains_key(&tuple) {
                                let reverse = AddrTuple::new(remote_addr, local_addr);
                                let state = shared.state.read().unwrap();
                                if !state.tuples.contains_key(&tuple)
                                    && state.tuples.contains_key(&reverse)
                                {
                                    tuple = reverse;
                                }
                            }
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let state = shared.state.read().unwrap();
                                    state.tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    if let Err(e) = c.send_async(buf).await {
                                        trace!("Error sending packet to connection: {:?}", e);
                                    }
                                    continue;
                                }
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                trace!(?tcp_packet, "Received SYN packet for port {}, ignoring", tcp_packet.get_destination());
                                continue;
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                info!("Unknown RST TCP packet from {}, ignoring", remote_addr);
                                continue;
                            } else {
                                trace!("Unknown TCP packet from {}, ignoring", remote_addr);
                                continue;
                            }
                        }
                        None => {
                            trace!("Dropping packet with no IP/TCP header");
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    match tuple {
                        Ok(tuple) => {
                            tuples.remove(&tuple);
                            trace!("Removed cached tuple: {:?}", tuple);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                skipped,
                                cached_tuple_count,
                                "fake_tcp tuples purge receiver lagged, cleared local cache"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tuples purge channel closed, reader_task exiting"
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::{
        sync::Notify,
        time::{Duration, timeout},
    };

    #[derive(Default)]
    struct RecordingTun(std::sync::Mutex<Vec<Bytes>>);

    #[async_trait::async_trait]
    impl Tun for RecordingTun {
        async fn recv(&self, _: &mut BytesMut) -> io::Result<usize> {
            std::future::pending().await
        }
        fn try_send(&self, packet: &Bytes) -> io::Result<()> {
            self.0.lock().unwrap().push(packet.clone());
            Ok(())
        }
        fn driver_type(&self) -> &'static str {
            "recording"
        }
    }

    fn recording_socket() -> (Stack, Arc<RecordingTun>, Socket, flume::Sender<Bytes>) {
        let tun = Arc::new(RecordingTun::default());
        let stack = Stack::new(tun.clone(), Ipv4Addr::LOCALHOST, None, None);
        let local: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let remote: SocketAddr = "192.0.2.1:20000".parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(local, remote, State::Established)
            .unwrap();
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .unwrap()
            .clone();
        (stack, tun, socket, tx)
    }

    fn peer_packet(socket: &Socket, seq: u32, ack: u32, payload: &[u8]) -> Bytes {
        build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            socket.remote_addr,
            socket.local_addr,
            seq,
            ack,
            tcp::TcpFlags::ACK,
            Some(payload),
        )
    }

    fn kernel_ack(socket: &Socket, receive_next: u32) -> Bytes {
        build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            socket.local_addr,
            socket.remote_addr,
            99,
            receive_next,
            tcp::TcpFlags::ACK,
            Some(&[0]),
        )
    }

    #[tokio::test]
    async fn takeover_waits_for_kernel_snapshot_and_preserves_queued_datagrams() {
        let (_stack, _, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, 399, 100, b"")).unwrap();
        let learning = socket.learn_for_takeover();
        tokio::pin!(learning);
        assert!(
            timeout(Duration::from_millis(10), &mut learning)
                .await
                .is_err()
        );
        tx.send(peer_packet(&socket, 400, 100, b"first")).unwrap();
        tx.send(peer_packet(&socket, 405, 100, b"second")).unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        learning.await.unwrap();
        assert_eq!(
            socket.ack.load(Ordering::Relaxed),
            400,
            "an empty keepalive is not RCV.NXT"
        );
        let mut received = BytesMut::new();
        assert_eq!(socket.recv(&mut received).await, Some(5));
        assert_eq!(&received[..], b"first");
        received.clear();
        assert_eq!(socket.recv(&mut received).await, Some(6));
        assert_eq!(&received[..], b"second");
        assert_eq!(socket.ack.load(Ordering::Relaxed), 411);
    }

    struct BidirectionalTun(flume::Receiver<Bytes>);

    #[async_trait::async_trait]
    impl Tun for BidirectionalTun {
        async fn recv(&self, packet: &mut BytesMut) -> io::Result<usize> {
            let bytes = self.0.recv_async().await.map_err(io::Error::other)?;
            packet.extend_from_slice(&bytes);
            Ok(bytes.len())
        }
        fn try_send(&self, _: &Bytes) -> io::Result<()> {
            Ok(())
        }
        fn driver_type(&self) -> &'static str {
            "bidirectional-test"
        }
        fn captures_outbound_tcp(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn takeover_routes_outbound_kernel_headers_to_the_punched_socket() {
        let (tx, rx) = flume::bounded(8);
        let stack = Stack::new(
            Arc::new(BidirectionalTun(rx)),
            Ipv4Addr::LOCALHOST,
            None,
            None,
        );
        let socket = stack
            .try_alloc_established_socket(
                "127.0.0.1:10000".parse().unwrap(),
                "192.0.2.1:20000".parse().unwrap(),
                State::Established,
            )
            .unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        tx.send(peer_packet(&socket, 399, 100, &[0])).unwrap();
        timeout(Duration::from_secs(1), socket.learn_for_takeover())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(socket.seq.load(Ordering::Relaxed), 100);
        assert_eq!(socket.ack.load(Ordering::Relaxed), 400);
    }

    #[tokio::test]
    async fn takeover_answers_keepalive_probes_without_acknowledging_ordinary_acks() {
        for probe_payload in [&[][..], &[0][..], &[0x7f][..]] {
            let (_stack, tun, socket, tx) = recording_socket();
            tx.send(peer_packet(&socket, 400, 100, b"")).unwrap();
            tx.send(kernel_ack(&socket, 400)).unwrap();
            socket.learn_for_takeover().await.unwrap();
            tx.send(peer_packet(&socket, 399, 100, probe_payload))
                .unwrap();
            tx.send(peer_packet(&socket, 400, 100, b"")).unwrap();
            tx.send(peer_packet(&socket, 400, 100, b"ready")).unwrap();
            let mut received = BytesMut::new();
            assert_eq!(socket.recv(&mut received).await, Some(5));
            assert_eq!(&received[..], b"ready");
            let sent = tun.0.lock().unwrap();
            assert_eq!(
                sent.len(),
                1,
                "exactly the out-of-window probe needs an ACK"
            );
            let (_, _, _, ack) = parse_ip_packet(&sent[0]).unwrap();
            assert!(ack.payload().is_empty());
            assert_eq!(ack.get_sequence(), 100);
            assert_eq!(ack.get_acknowledgement(), 400);
        }
    }

    #[tokio::test]
    async fn takeover_preserves_a_peer_first_datagram_and_does_not_follow_stale_acks() {
        let (_stack, tun, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, 400, 100, b"first")).unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        socket.learn_for_takeover().await.unwrap();
        assert_eq!(socket.seq.load(Ordering::Relaxed), 100);
        let mut received = BytesMut::new();
        assert_eq!(socket.recv(&mut received).await, Some(5));
        assert_eq!(&received[..], b"first");
        socket.try_send(b"abc").unwrap();
        tx.send(peer_packet(&socket, 405, 50, b"")).unwrap();
        tx.send(peer_packet(&socket, 390, 50, b"late")).unwrap();
        received.clear();
        assert_eq!(socket.recv(&mut received).await, Some(4));
        socket.try_send(b"next").unwrap();
        let sent = tun.0.lock().unwrap();
        let (_, _, _, tcp) = parse_ip_packet(&sent[1]).unwrap();
        assert_eq!(
            tcp.get_sequence(),
            103,
            "a stale kernel ACK rewound raw sequence"
        );
        assert_eq!(
            tcp.get_acknowledgement(),
            405,
            "reordered payload rewound ACK"
        );
        assert_eq!(
            sent.len(),
            2,
            "receiving ACKs must not generate extra traffic"
        );
    }

    #[tokio::test]
    async fn takeover_ack_progress_handles_sequence_wraparound() {
        let (_stack, _, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, u32::MAX - 3, 100, b"ab"))
            .unwrap();
        tx.send(kernel_ack(&socket, u32::MAX - 3)).unwrap();
        socket.learn_for_takeover().await.unwrap();
        let mut received = BytesMut::new();
        socket.recv(&mut received).await.unwrap();
        tx.send(peer_packet(&socket, 1, 100, b"abc")).unwrap();
        socket.recv(&mut received).await.unwrap();
        assert_eq!(socket.ack.load(Ordering::Relaxed), 4);
        tx.send(peer_packet(&socket, u32::MAX - 2, 100, b"a"))
            .unwrap();
        socket.recv(&mut received).await.unwrap();
        assert_eq!(socket.ack.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn takeover_repeated_idle_acks_do_not_rewrite_sequence_or_emit_packets() {
        let (_stack, tun, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, 400, 100, b"")).unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        socket.learn_for_takeover().await.unwrap();
        socket.try_send(b"abc").unwrap();
        let old_ack = peer_packet(&socket, 400, 100, b"");
        let end = peer_packet(&socket, 400, 100, b"probe");
        let producer = tokio::spawn(async move {
            for _ in 0..4096 {
                tx.send_async(old_ack.clone()).await.unwrap();
            }
            tx.send_async(end).await.unwrap();
        });
        let mut received = BytesMut::new();
        assert_eq!(
            timeout(Duration::from_secs(2), socket.recv(&mut received))
                .await
                .unwrap(),
            Some(5)
        );
        producer.await.unwrap();
        assert_eq!(&received[..], b"probe");
        assert_eq!(socket.seq.load(Ordering::Relaxed), 103);
        assert_eq!(
            tun.0.lock().unwrap().len(),
            1,
            "idle ACKs caused raw transmissions"
        );
    }

    #[tokio::test]
    async fn takeover_concurrent_sends_reserve_distinct_sequence_ranges() {
        let (_stack, tun, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, 400, 100, b"")).unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        socket.learn_for_takeover().await.unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let socket = &socket;
                scope.spawn(move || {
                    for _ in 0..64 {
                        socket.try_send(b"x").unwrap();
                    }
                });
            }
        });
        let mut sequences: Vec<_> = tun
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|packet| parse_ip_packet(packet).unwrap().3.get_sequence())
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (100..612).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn takeover_close_emits_one_reset_and_never_sends_an_unlearned_reset() {
        let (_stack, tun, socket, tx) = recording_socket();
        drop(socket);
        assert!(tun.0.lock().unwrap().is_empty());
        drop(tx);
        let (_stack, tun, socket, tx) = recording_socket();
        tx.send(peer_packet(&socket, 400, 100, b"")).unwrap();
        tx.send(kernel_ack(&socket, 400)).unwrap();
        socket.learn_for_takeover().await.unwrap();
        socket.close();
        socket.close();
        assert!(socket.try_send(b"late QUIC packet").is_none());
        assert_eq!(socket.recv(&mut BytesMut::new()).await, None);
        drop(socket);
        let sent = tun.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            parse_ip_packet(&sent[0]).unwrap().3.get_flags(),
            tcp::TcpFlags::RST
        );
    }

    #[tokio::test]
    async fn sniff_only_backend_cannot_claim_kernel_tcp_ownership() {
        let (_, tun, _, _) = recording_socket();
        assert_eq!(
            tun.isolate_kernel_tcp().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[derive(Default)]
    struct FailingTun {
        fail: Notify,
    }

    impl FailingTun {
        fn fail(&self) {
            self.fail.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl Tun for FailingTun {
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
            self.fail.notified().await;
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test tun closed"))
        }

        fn try_send(&self, _packet: &Bytes) -> Result<(), io::Error> {
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn reader_task_closes_sockets_on_tun_recv_error() {
        let tun = Arc::new(FailingTun::default());
        let mut stack = Stack::new(tun.clone(), Ipv4Addr::LOCALHOST, None, None);
        let socket = stack
            .try_alloc_established_socket(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_000),
                State::Established,
            )
            .expect("socket allocation should succeed before tun failure");

        tun.fail();

        let join_result = timeout(Duration::from_secs(1), &mut stack.reader_task)
            .await
            .expect("reader task should exit after tun recv error");
        assert!(join_result.is_ok());
        assert!(stack.is_closed());

        let mut buf = BytesMut::new();
        let recv_result = timeout(Duration::from_secs(1), socket.recv(&mut buf))
            .await
            .expect("socket recv should not hang after reader task exits");
        assert_eq!(recv_result, None);

        let new_socket = stack.try_alloc_established_socket(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_001),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_001),
            State::Established,
        );
        assert!(new_socket.is_none());

        drop(socket);
    }
}
