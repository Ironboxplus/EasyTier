use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use tokio::sync::Mutex;
use windivert::error::WinDivertError;
use windivert::packet::WinDivertPacket;
use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windivert::{WinDivert, layer};

use crate::tunnel::fake_tcp::stack;

// Copies reach the raw stack first. Kernel isolation is below capture, and raw
// injection is below both, so native ACK/FIN/RST are blocked but raw sends pass.
const CAPTURE_PRIORITY: i16 = 0;
const LEARNING_PRIORITY: i16 = -100;
const OWNERSHIP_PRIORITY: i16 = -101;
const INJECT_PRIORITY: i16 = -200;

struct PacketGuard(WinDivert<layer::NetworkLayer>);

impl Drop for PacketGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.close(windivert::CloseAction::Nothing) {
            tracing::error!(?error, "FakeTCP tuple guard close failed");
        }
    }
}

struct TcpOwnership {
    filter: String,
    guard: PacketGuard,
    isolated: bool,
}

fn ownership_filters(remote: SocketAddr, local: SocketAddr) -> io::Result<(String, String)> {
    let inbound = build_filter(Some(remote), local)?;
    let outbound = build_filter(Some(local), remote)?;
    Ok((
        format!("({inbound}) and tcp.PayloadLength > 0"),
        format!("({inbound}) or ({outbound})"),
    ))
}

impl TcpOwnership {
    fn new(remote: SocketAddr, local: SocketAddr) -> io::Result<Self> {
        let (learning, filter) = ownership_filters(remote, local)?;
        // A peer can finish learning first and send raw QUIC before we do.
        // Copy it to the raw stack, but never admit it to the native stream.
        let guard = PacketGuard(
            WinDivert::network(
                learning,
                LEARNING_PRIORITY,
                WinDivertFlags::default().set_drop(),
            )
            .map_err(io::Error::other)?,
        );
        Ok(Self {
            filter,
            guard,
            isolated: false,
        })
    }

    fn isolate(&mut self) -> io::Result<()> {
        if self.isolated {
            return Ok(());
        }
        // Install the full guard before retiring the learning guard. Different
        // priorities make this overlap deterministic; both only affect one tuple.
        let guard = PacketGuard(
            WinDivert::network(
                &self.filter,
                OWNERSHIP_PRIORITY,
                WinDivertFlags::default().set_drop(),
            )
            .map_err(io::Error::other)?,
        );
        self.guard = guard;
        self.isolated = true;
        Ok(())
    }
}

struct WinDivertReader {
    inner: UnsafeCell<WinDivert<layer::NetworkLayer>>,
}

unsafe impl Send for WinDivertReader {}
unsafe impl Sync for WinDivertReader {}

impl WinDivertReader {
    fn new(inner: WinDivert<layer::NetworkLayer>) -> Self {
        Self {
            inner: UnsafeCell::new(inner),
        }
    }

    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::NetworkLayer>, WinDivertError> {
        let inner = unsafe { &*self.inner.get() };
        inner.recv(buffer)
    }

    fn shutdown(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .shutdown(WinDivertShutdownMode::Recv)
            .with_context(|| "WinDivertReader shutdown failed")?;
        Ok(())
    }

    fn close(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .close(windivert::CloseAction::Nothing)
            .with_context(|| "WinDivertReader close failed")?;
        Ok(())
    }
}

impl Drop for WinDivertReader {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            tracing::error!("WinDivertReader close failed: {:?}", e);
        }
    }
}

pub struct WinDivertTun {
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    sender: Arc<std::sync::Mutex<WinDivert<layer::NetworkLayer>>>,
    reader: Arc<WinDivertReader>,
    ownership: Option<std::sync::Mutex<TcpOwnership>>,
}

impl Drop for WinDivertTun {
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock()
            && let Err(e) = sender.close(windivert::CloseAction::Nothing)
        {
            tracing::error!("WinDivertSender close failed: {:?}", e);
        }
        if let Err(e) = self.reader.shutdown() {
            tracing::error!("WinDivertReader shutdown failed: {:?}", e);
        }
    }
}

impl WinDivertTun {
    pub fn new(src_addr: Option<SocketAddr>, dst_addr: SocketAddr) -> io::Result<Self> {
        Self::new_inner(src_addr, dst_addr, false)
    }

    pub fn new_for_mp(remote: SocketAddr, local: SocketAddr) -> io::Result<Self> {
        Self::new_inner(Some(remote), local, true)
    }

    fn new_inner(
        src_addr: Option<SocketAddr>,
        dst_addr: SocketAddr,
        own_tcp: bool,
    ) -> io::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        let filter = if own_tcp {
            ownership_filters(
                src_addr.expect("MP capture requires a remote tuple"),
                dst_addr,
            )?
            .1
        } else {
            build_filter(src_addr, dst_addr)?
        };
        tracing::debug!(%filter, "WinDivertTun created with filter");

        // Sniff mode: 1 (WINDIVERT_FLAG_SNIFF)
        // Layer: Network (0)
        // Priority: 0
        let flags = WinDivertFlags::default().set_sniff();
        let reader =
            WinDivert::network(&filter, CAPTURE_PRIORITY, flags).map_err(io::Error::other)?;
        let reader = Arc::new(WinDivertReader::new(reader));
        let reader_clone = reader.clone();

        let ownership = if own_tcp {
            Some(std::sync::Mutex::new(TcpOwnership::new(
                src_addr.expect("MP capture requires an exact remote tuple"),
                dst_addr,
            )?))
        } else {
            None
        };
        // Create every fallible handle before starting the capture thread.
        let sender = WinDivert::network("false", INJECT_PRIORITY, WinDivertFlags::default())
            .map_err(io::Error::other)?;

        std::thread::spawn(move || {
            let reader = reader_clone;
            let mut buffer = vec![0u8; 65536];
            loop {
                match reader.recv(Some(&mut buffer)) {
                    Ok(packet) => {
                        let data = &packet.data;

                        let mut eth_data = vec![0u8; 14 + data.len()];
                        // Set EtherType
                        if !data.is_empty() && data[0] >> 4 == 4 {
                            eth_data[12] = 0x08;
                            eth_data[13] = 0x00;
                        } else {
                            eth_data[12] = 0x86;
                            eth_data[13] = 0xDD;
                        }
                        eth_data[14..].copy_from_slice(data);

                        if tx.blocking_send(eth_data).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::error!(?error, "WinDivert recv failed");
                        break;
                    }
                }
            }
        });

        // Sender: non-sniff, empty filter?
        // Use "false" to avoid capturing anything.
        // Flags: 0
        Ok(Self {
            recv_queue: Mutex::new(rx),
            sender: Arc::new(std::sync::Mutex::new(sender)),
            reader,
            ownership,
        })
    }
}

fn build_filter(src_addr: Option<SocketAddr>, dst_addr: SocketAddr) -> io::Result<String> {
    if let Some(src_addr) = src_addr
        && src_addr.is_ipv4() != dst_addr.is_ipv4()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "src/dst addr family mismatch",
        ));
    }

    let mut filters = Vec::with_capacity(5);
    filters.push("tcp".to_owned());

    match dst_addr {
        SocketAddr::V4(addr) => {
            filters.push(format!("ip.DstAddr == {}", addr.ip()));
            filters.push(format!("tcp.DstPort == {}", addr.port()));
        }
        SocketAddr::V6(addr) => {
            filters.push(format!("ipv6.DstAddr == {}", addr.ip()));
            filters.push(format!("tcp.DstPort == {}", addr.port()));
        }
    }

    if let Some(src_addr) = src_addr {
        match src_addr {
            SocketAddr::V4(addr) => {
                filters.push(format!("ip.SrcAddr == {}", addr.ip()));
                filters.push(format!("tcp.SrcPort == {}", addr.port()));
            }
            SocketAddr::V6(addr) => {
                filters.push(format!("ipv6.SrcAddr == {}", addr.ip()));
                filters.push(format!("tcp.SrcPort == {}", addr.port()));
            }
        }
    }

    Ok(filters.join(" and "))
}

#[async_trait::async_trait]
impl stack::Tun for WinDivertTun {
    fn captures_outbound_tcp(&self) -> bool {
        self.ownership.is_some()
    }
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                packet.extend_from_slice(&data);
                Ok(data.len())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            )),
        }
    }

    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        // Strip ethernet header
        if packet.len() < 14 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Packet too short",
            ));
        }
        let ip_data = &packet[14..];

        let Ok(sender) = self.sender.try_lock() else {
            return Err(std::io::Error::other("WinDivert sender lock failed"));
        };

        let mut pkt = unsafe { WinDivertPacket::<layer::NetworkLayer>::new(ip_data.to_vec()) };
        pkt.address.set_outbound(true);

        sender
            .send(&pkt)
            .map_err(|e| std::io::Error::other(format!("WinDivert send failed: {}", e)))?;

        Ok(())
    }

    fn driver_type(&self) -> &'static str {
        "windivert"
    }

    fn isolate_kernel_tcp(&self) -> io::Result<()> {
        self.ownership
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "sniff-only FakeTCP capture")
            })?
            .lock()
            .unwrap()
            .isolate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::fake_tcp::packet::{build_tcp_packet, parse_ip_packet};
    use pnet::{
        packet::{Packet, tcp::TcpFlags},
        util::MacAddr,
    };

    // The dependency exposes these helpers only through its sys crate. Match
    // its C ABI here to exercise the real filter compiler without loading a
    // driver. WinDivertAddress is repr(transparent) over WINDIVERT_ADDRESS.
    unsafe extern "C" {
        fn WinDivertHelperCompileFilter(
            filter: *const std::ffi::c_char,
            layer: i32,
            object: *mut std::ffi::c_char,
            len: u32,
            error: *mut *const std::ffi::c_char,
            position: *mut u32,
        ) -> i32;
        fn WinDivertHelperEvalFilter(
            filter: *const std::ffi::c_char,
            packet: *const std::ffi::c_void,
            len: u32,
            address: *const std::ffi::c_void,
        ) -> i32;
    }

    fn matches(filter: &str, src: SocketAddr, dst: SocketAddr, flags: u8, payload: &[u8]) -> bool {
        let filter = std::ffi::CString::new(filter).unwrap();
        let mut error = std::ptr::null();
        let mut position = 0;
        assert_ne!(
            unsafe {
                WinDivertHelperCompileFilter(
                    filter.as_ptr(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut error,
                    &mut position,
                )
            },
            0,
            "invalid guard filter at {position}: {filter:?}"
        );
        let eth = build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            src,
            dst,
            100,
            200,
            flags,
            Some(payload),
        );
        let mut packet = unsafe { WinDivertPacket::<layer::NetworkLayer>::new(eth[14..].to_vec()) };
        packet.address.as_mut().set_ipv6(src.is_ipv6());
        unsafe {
            WinDivertHelperEvalFilter(
                filter.as_ptr(),
                packet.data.as_ptr().cast(),
                packet.data.len() as u32,
                &packet.address as *const _ as *const std::ffi::c_void,
            ) != 0
        }
    }

    #[test]
    fn ownership_filters_protect_only_the_exact_tuple_in_both_families() {
        for (local, remote, unrelated) in [
            (
                "192.0.2.1:10000",
                "198.51.100.2:20000",
                "198.51.100.3:20000",
            ),
            (
                "[2001:db8::1]:10000",
                "[2001:db8::2]:20000",
                "[2001:db8::3]:20000",
            ),
        ] {
            let local = local.parse().unwrap();
            let remote = remote.parse().unwrap();
            let unrelated = unrelated.parse().unwrap();
            let (learning, owned) = ownership_filters(remote, local).unwrap();
            assert!(matches(&learning, remote, local, TcpFlags::ACK, b"quic"));
            assert!(!matches(&learning, remote, local, TcpFlags::ACK, b""));
            assert!(!matches(&learning, local, remote, TcpFlags::ACK, b"native"));
            for flag in [TcpFlags::ACK, TcpFlags::FIN | TcpFlags::ACK, TcpFlags::RST] {
                assert!(matches(&owned, remote, local, flag, b""));
                assert!(matches(&owned, local, remote, flag, b""));
                assert!(!matches(&owned, unrelated, local, flag, b""));
                assert!(!matches(&owned, local, unrelated, flag, b""));
            }
            let wrong_port = SocketAddr::new(remote.ip(), remote.port() + 1);
            assert!(!matches(&owned, wrong_port, local, TcpFlags::ACK, b"quic"));
            assert!(!matches(&owned, local, wrong_port, TcpFlags::ACK, b"quic"));
        }
        assert!(
            ownership_filters(
                "[::1]:10000".parse().unwrap(),
                "127.0.0.1:20000".parse().unwrap()
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires Administrator and WinDivert64.sys beside the test binary; isolated loopback tuple only"]
    async fn kernel_tuple_isolation_blocks_native_tcp_but_allows_raw_injection() {
        use stack::Tun;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, timeout};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let local = client.local_addr().unwrap();
        let remote = client.peer_addr().unwrap();
        // Keep the guard alive until the native socket has been aborted, even
        // on panic: this is the same owner used by the production MP path.
        let tun = Arc::new(
            WinDivertTun::new_for_mp(remote, local)
                .expect("WinDivert driver access is required for this acceptance test"),
        );
        let _reservation =
            super::super::super::KernelTcpReservation::new(client, tun.clone()).unwrap();
        let client = _reservation.stream.as_ref().unwrap();
        client.writable().await.unwrap();
        client.try_write(b"native-before").unwrap();
        let mut native = [0u8; 13];
        timeout(Duration::from_secs(2), server.read_exact(&mut native))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&native, b"native-before");
        server.write_all(b"peer-raw").await.unwrap();
        let peer_data = timeout(Duration::from_secs(2), async {
            loop {
                let mut packet = BytesMut::new();
                tun.recv(&mut packet).await.unwrap();
                let packet = packet.freeze();
                let (_, _, ip, tcp) = parse_ip_packet(&packet).unwrap();
                if ip.get_destination() == local.ip()
                    && tcp.get_destination() == local.port()
                    && !tcp.payload().is_empty()
                {
                    break packet;
                }
            }
        })
        .await
        .unwrap();
        let (_, _, _, tcp) = parse_ip_packet(&peer_data).unwrap();
        let sequence = tcp.get_acknowledgement();
        let ack = tcp.get_sequence().wrapping_add(8);
        let mut byte = [0u8; 1];
        assert!(
            matches!(client.try_read(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        );
        tun.isolate_kernel_tcp().unwrap();
        client.try_write(b"blocked-native").unwrap();
        assert!(
            timeout(Duration::from_millis(150), server.read(&mut byte))
                .await
                .is_err()
        );
        let raw = build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            local,
            remote,
            sequence,
            ack,
            TcpFlags::ACK,
            Some(b"raw-pass"),
        );
        tun.try_send(&raw).unwrap();
        let mut received = [0u8; 8];
        timeout(Duration::from_secs(2), server.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"raw-pass");
    }
}
