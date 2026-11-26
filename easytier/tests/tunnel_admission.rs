use std::time::Duration;

use easytier::tunnel::{
    Tunnel, TunnelError,
    mpsc::{MpscTunnel, MpscTunnelSender},
    packet_def::ZCPacket,
    ring::create_ring_tunnel_pair,
};
use futures::StreamExt;

fn packet(sequence: u32) -> ZCPacket {
    ZCPacket::new_with_payload(&sequence.to_be_bytes())
}

#[tokio::test(flavor = "current_thread")]
async fn a_ready_transport_accepts_a_burst_without_waiting_for_its_forwarder() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, None);
    let sender = tunnel.get_sink();
    // No yield: the actual transport has room for 128 packets. An idle
    // forwarding task must not make the 33rd packet look congested.
    for sequence in 0..64u32 {
        sender
            .try_send(packet(sequence))
            .expect("transport still has capacity");
    }
    let (mut receiver, _sink) = remote.split();
    for sequence in 0..64u32 {
        let received = tokio::time::timeout(Duration::from_secs(1), receiver.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.payload(), &sequence.to_be_bytes());
    }
}

async fn saturate(sender: &MpscTunnelSender) -> u32 {
    let mut accepted = 0u32;
    for _ in 0..16 {
        while sender.try_send(packet(accepted)).is_ok() {
            accepted += 1;
            assert!(accepted < 4096, "a blocked transport must stay bounded");
        }
        tokio::task::yield_now().await;
    }
    accepted
}

#[tokio::test(flavor = "current_thread")]
async fn a_full_transport_keeps_fifo_order_when_its_waiting_sender_resumes() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, None);
    let sender = tunnel.get_sink();
    let accepted = saturate(&sender).await;
    let waiting = sender.send(packet(accepted));
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    let (mut receiver, _sink) = remote.split();
    for sequence in 0..accepted {
        let received = tokio::time::timeout(Duration::from_secs(1), receiver.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.payload(), &sequence.to_be_bytes());
    }
    tokio::time::timeout(Duration::from_secs(1), &mut waiting)
        .await
        .unwrap()
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), receiver.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.payload(), &accepted.to_be_bytes());
}

#[tokio::test(flavor = "current_thread")]
async fn closing_a_full_transport_wakes_its_waiting_sender() {
    let (local, _remote) = create_ring_tunnel_pair();
    let mut tunnel = MpscTunnel::new(local, None);
    let sender = tunnel.get_sink();
    let accepted = saturate(&sender).await;
    let waiting = sender.send(packet(accepted));
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    tunnel.close();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), &mut waiting)
            .await
            .unwrap(),
        Err(TunnelError::Shutdown) | Err(TunnelError::Anyhow(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn a_full_peer_does_not_hold_up_a_ready_peer() {
    let (blocked, _blocked_remote) = create_ring_tunnel_pair();
    let blocked = MpscTunnel::new(blocked, None);
    let blocked_sender = blocked.get_sink();
    saturate(&blocked_sender).await;
    assert!(matches!(
        blocked_sender.try_send(packet(999)),
        Err(TunnelError::BufferFull)
    ));

    let (ready, remote) = create_ring_tunnel_pair();
    let ready = MpscTunnel::new(ready, None);
    let sender = ready.get_sink();
    for sequence in 0..16 {
        sender.try_send(packet(sequence)).unwrap();
    }
    let (mut receiver, _sink) = remote.split();
    for sequence in 0..16u32 {
        let received = tokio::time::timeout(Duration::from_secs(1), receiver.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.payload(), &sequence.to_be_bytes());
    }
}

// Exercise a sink with one buffered packet and capacity restored by flushing.
// Its readiness wake follows Sink's contract, including synchronous progress.
struct FlushTunnel {
    sink: std::sync::Mutex<Option<FlushSink>>,
}

struct FlushSink {
    pending: Option<ZCPacket>,
    received: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
    ready_waker: Option<std::task::Waker>,
}

impl futures::Sink<ZCPacket> for FlushSink {
    type Error = TunnelError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.pending.is_some() {
            self.ready_waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: ZCPacket) -> Result<(), Self::Error> {
        assert!(
            self.pending.replace(item).is_none(),
            "must poll readiness before each send"
        );
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if let Some(item) = self.pending.take() {
            self.received
                .lock()
                .unwrap()
                .push(u32::from_be_bytes(item.payload().try_into().unwrap()));
            if let Some(waker) = self.ready_waker.take() {
                waker.wake();
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

impl Tunnel for FlushTunnel {
    fn split(
        &self,
    ) -> (
        std::pin::Pin<Box<dyn easytier::tunnel::ZCPacketStream>>,
        std::pin::Pin<Box<dyn easytier::tunnel::ZCPacketSink>>,
    ) {
        (
            Box::pin(futures::stream::empty()),
            Box::pin(self.sink.lock().unwrap().take().unwrap()),
        )
    }

    fn info(&self) -> Option<easytier::proto::common::TunnelInfo> {
        None
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_flush_that_makes_capacity_available_does_not_leave_packets_asleep() {
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let tunnel = MpscTunnel::new(
        FlushTunnel {
            sink: std::sync::Mutex::new(Some(FlushSink {
                pending: None,
                received: received.clone(),
                ready_waker: None,
            })),
        },
        None,
    );
    for sequence in 0..16 {
        tunnel.get_sink().try_send(packet(sequence)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*received.lock().unwrap(), (0..16).collect::<Vec<u32>>());
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_tunnel_wakes_its_waiting_sender_and_closes_the_transport() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, None);
    let sender = tunnel.get_sink();
    let accepted = saturate(&sender).await;
    let waiting = sender.send(packet(accepted));
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    drop(tunnel);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut waiting)
            .await
            .unwrap()
            .is_err()
    );
    let (mut receiver, _sink) = remote.split();
    tokio::time::timeout(Duration::from_secs(1), async {
        while receiver.next().await.is_some() {}
    })
    .await
    .expect("external sender clones must not retain the closed transport");
}

#[tokio::test(flavor = "current_thread")]
async fn a_blocked_send_timeout_wakes_producers_without_timing_out_an_idle_tunnel() {
    let (local, _remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, Some(Duration::from_millis(20)));
    let sender = tunnel.get_sink();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        sender.try_send(packet(0)).is_ok(),
        "idle time is not a send timeout"
    );
    let mut sequence = 1;
    while sender.try_send(packet(sequence)).is_ok() {
        sequence += 1;
    }
    let result = tokio::time::timeout(Duration::from_secs(1), sender.send(packet(sequence)))
        .await
        .expect("the forwarding timeout must wake the waiting sender");
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_producers_keep_each_producers_order_and_deliver_every_packet() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, None);
    let (mut receiver, _sink) = remote.split();
    let mut producers = Vec::new();
    for producer in 0..4u32 {
        let sender = tunnel.get_sink();
        producers.push(tokio::spawn(async move {
            for sequence in 0..256u32 {
                sender
                    .send(packet((producer << 16) | sequence))
                    .await
                    .unwrap();
            }
        }));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut next = [0u32; 4];
        for _ in 0..1024 {
            let item = receiver.next().await.unwrap().unwrap();
            let value = u32::from_be_bytes(item.payload().try_into().unwrap());
            let producer = (value >> 16) as usize;
            assert_eq!(value & 0xffff, next[producer]);
            next[producer] += 1;
        }
        for producer in producers {
            producer.await.unwrap();
        }
        assert_eq!(next, [256; 4]);
    })
    .await
    .expect("concurrent backpressure must make progress");
}

#[tokio::test(flavor = "current_thread")]
async fn a_receiver_failure_wakes_a_sender_waiting_for_capacity() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, None);
    let sender = tunnel.get_sink();
    let accepted = saturate(&sender).await;
    let waiting = sender.send(packet(accepted));
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    drop(remote);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut waiting)
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_busy_transport_times_out_only_when_forwarding_stops_making_progress() {
    let (local, remote) = create_ring_tunnel_pair();
    let tunnel = MpscTunnel::new(local, Some(Duration::from_millis(100)));
    let sender = tunnel.get_sink();
    let mut next = saturate(&sender).await;
    let initial = next;
    let (mut receiver, _sink) = remote.split();

    // Keep the actual ring and bounded staging full for three timeout
    // periods, but free transport capacity every 10 ms. A timeout around
    // draining the entire continuously refilled queue kills a live sender.
    for sequence in 0..30u32 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let item = tokio::time::timeout(Duration::from_secs(1), receiver.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(item.payload(), &sequence.to_be_bytes());
        tokio::time::timeout(Duration::from_secs(1), sender.send(packet(next)))
            .await
            .unwrap()
            .expect("transport is making continuous progress");
        next += 1;
    }
    assert!(next >= initial + 30);
    for sequence in 30..next {
        let item = tokio::time::timeout(Duration::from_secs(1), receiver.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(item.payload(), &sequence.to_be_bytes());
    }

    // Genuine lack of capacity still closes the same sender within its
    // existing timeout; progress must not turn the timeout off forever.
    saturate(&sender).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), sender.send(packet(next)))
            .await
            .expect("a stalled transport must time out")
            .is_err()
    );
}
