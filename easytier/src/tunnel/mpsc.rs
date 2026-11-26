// Serialize admission to the transport, with bounded staging when it is blocked.

use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::{
    SinkExt,
    future::poll_fn,
    task::{ArcWake, AtomicWaker, waker},
};
use parking_lot::Mutex;
use tokio::{sync::Notify, time::timeout};
use tokio_util::task::AbortOnDropHandle;

use crate::proto::common::TunnelInfo;

use super::{Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket};

const STAGING_CAPACITY: usize = 32;

struct SendState {
    sink: Option<Pin<Box<dyn ZCPacketSink>>>,
    queued: VecDeque<ZCPacket>,
    /// Successful submissions to the transport, including synchronous producers.
    submitted: u64,
    dirty: bool,
    closed: bool,
}

impl SendState {
    // Keep FIFO ordering even when a producer runs before the forwarding task.
    // A bounded round also prevents a busy peer from monopolizing its executor.
    fn drain(&mut self, cx: &mut Context<'_>) -> Result<(), TunnelError> {
        let sink = self.sink.as_mut().ok_or(TunnelError::Shutdown)?;
        for _ in 0..STAGING_CAPACITY {
            if self.queued.is_empty() {
                break;
            }
            match sink.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(error) = sink.as_mut().start_send(self.queued.pop_front().unwrap()) {
                        self.closed = true;
                        return Err(error);
                    }
                    self.dirty = true;
                    self.submitted = self.submitted.wrapping_add(1);
                }
                Poll::Ready(Err(error)) => {
                    self.closed = true;
                    return Err(error);
                }
                Poll::Pending => break,
            }
        }
        Ok(())
    }
}

// The transport must wake its forwarder even when poll_ready was called by a
// synchronous producer. Own only the worker's waker here, not its sink/state.
struct ForwardWake(Arc<AtomicWaker>);

impl ArcWake for ForwardWake {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.wake();
    }
}

struct SharedSender {
    state: Mutex<SendState>,
    worker: Arc<AtomicWaker>,
    transport_waker: Waker,
    space: Notify,
}

enum Admission {
    Accepted,
    Full(ZCPacket),
    Failed(TunnelError),
}

impl SharedSender {
    fn admit(&self, item: ZCPacket) -> Admission {
        let mut state = self.state.lock();
        if state.closed {
            return Admission::Failed(TunnelError::Shutdown);
        }
        let mut cx = Context::from_waker(&self.transport_waker);
        let queued_before = state.queued.len();
        let result = (|| {
            state.drain(&mut cx)?;
            if state.queued.is_empty() {
                let sink = state.sink.as_mut().ok_or(TunnelError::Shutdown)?;
                match sink.as_mut().poll_ready(&mut cx) {
                    Poll::Ready(Ok(())) => {
                        sink.as_mut().start_send(item)?;
                        state.dirty = true;
                        state.submitted = state.submitted.wrapping_add(1);
                        return Ok(Admission::Accepted);
                    }
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Pending => {}
                }
            }
            if state.queued.len() == STAGING_CAPACITY {
                Ok(Admission::Full(item))
            } else {
                state.queued.push_back(item);
                Ok(Admission::Accepted)
            }
        })();
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                state.closed = true;
                Admission::Failed(error)
            }
        };
        let capacity_changed = state.queued.len() < queued_before || state.closed;
        drop(state);
        if capacity_changed {
            self.space.notify_waiters();
        }
        self.worker.wake();
        result
    }

    fn shutdown(&self) -> Option<Pin<Box<dyn ZCPacketSink>>> {
        let mut state = self.state.lock();
        state.closed = true;
        state.queued.clear();
        let sink = state.sink.take();
        drop(state);
        self.space.notify_waiters();
        self.worker.wake();
        sink
    }

    async fn forward(&self, send_timeout: Option<Duration>) -> Result<(), TunnelError> {
        loop {
            // Idle time is not a send timeout. Register before checking state
            // so a producer or transport wake cannot be lost.
            poll_fn(|cx| {
                self.worker.register(cx.waker());
                let state = self.state.lock();
                if state.closed {
                    Poll::Ready(Err(TunnelError::Shutdown))
                } else if state.dirty || !state.queued.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await?;

            let submitted_before = self.state.lock().submitted;
            let round = poll_fn(|cx| {
                self.worker.register(cx.waker());
                let mut state = self.state.lock();
                if state.closed {
                    return Poll::Ready(Err(TunnelError::Shutdown));
                }
                let before = state.queued.len();
                let mut transport_cx = Context::from_waker(&self.transport_waker);
                state.drain(&mut transport_cx)?;
                if state.queued.len() < before {
                    self.space.notify_waiters();
                }
                let result = loop {
                    let sink = state.sink.as_mut().ok_or(TunnelError::Shutdown)?;
                    match sink.as_mut().poll_flush(&mut transport_cx) {
                        Poll::Ready(Ok(())) => state.dirty = false,
                        Poll::Ready(Err(error)) => {
                            // Publish terminal failure while still holding
                            // the sink lock, before another producer can poll it.
                            state.closed = true;
                            return Poll::Ready(Err(error));
                        }
                        other => break other,
                    }
                    if state.queued.is_empty() {
                        break Poll::Ready(Ok(()));
                    }
                    // Flush may restore capacity. Recheck it in this same
                    // round; every successful pass consumes queued data, so
                    // one poll still handles at most STAGING_CAPACITY.
                    let before = state.queued.len();
                    state.drain(&mut transport_cx)?;
                    if state.queued.len() == before {
                        break Poll::Pending;
                    }
                    self.space.notify_waiters();
                };
                // A busy producer may keep the bounded queue nonempty for
                // longer than send_timeout while the transport keeps draining.
                // Finish this round on actual submission progress, retaining
                // dirty output for the next flush. Only a stalled round times
                // out; staging admission alone does not renew the timeout.
                if result.is_pending() && state.submitted != submitted_before {
                    Poll::Ready(Ok(()))
                } else {
                    result
                }
            });
            if let Some(limit) = send_timeout {
                timeout(limit, round).await??;
            } else {
                round.await?;
            }
            tokio::task::consume_budget().await;
        }
    }
}

#[derive(Clone)]
pub struct MpscTunnelSender(Arc<SharedSender>);

impl MpscTunnelSender {
    pub async fn send(&self, mut item: ZCPacket) -> Result<(), TunnelError> {
        loop {
            let notified = self.0.space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.0.admit(item) {
                Admission::Accepted => return Ok(()),
                Admission::Failed(error) => return Err(error),
                Admission::Full(pending) => item = pending,
            }
            notified.await;
        }
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        match self.0.admit(item) {
            Admission::Accepted => Ok(()),
            Admission::Full(_) => Err(TunnelError::BufferFull),
            Admission::Failed(error) => Err(error),
        }
    }
}

pub struct MpscTunnel<T> {
    sender: Arc<SharedSender>,
    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    task: AbortOnDropHandle<()>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        let (stream, sink) = tunnel.split();
        let worker = Arc::new(AtomicWaker::new());
        let sender = Arc::new(SharedSender {
            state: Mutex::new(SendState {
                sink: Some(sink),
                queued: VecDeque::with_capacity(STAGING_CAPACITY),
                submitted: 0,
                dirty: false,
                closed: false,
            }),
            transport_waker: waker(Arc::new(ForwardWake(worker.clone()))),
            worker,
            space: Notify::new(),
        });
        let task_sender = sender.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = task_sender.forward(send_timeout).await {
                tracing::debug!(?error, "mpsc forward stopped");
            }
            if let Some(mut sink) = task_sender.shutdown() {
                let close_ret = timeout(Duration::from_secs(5), sink.close()).await;
                tracing::debug!(?close_ret, "mpsc close sink");
            }
        });
        Self {
            sender,
            tunnel,
            stream: Some(stream),
            task: AbortOnDropHandle::new(task),
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub fn get_sink(&self) -> MpscTunnelSender {
        MpscTunnelSender(self.sender.clone())
    }

    pub fn close(&mut self) {
        self.sender.shutdown();
        self.task.abort();
    }

    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel.info()
    }
}

impl<T> Drop for MpscTunnel<T> {
    fn drop(&mut self) {
        self.sender.shutdown();
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        ring::{RING_TUNNEL_CAP, create_ring_tunnel_pair},
        tcp::{TcpTunnelConnector, TcpTunnelListener},
    };

    use super::*;
    // test slow send lock in framed tunnel
    #[tokio::test]
    async fn mpsc_slow_receiver() {
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());

        listener.listen().await.unwrap();
        let t1 = tokio::spawn(async move {
            let t = listener.accept().await.unwrap();
            let (mut stream, _sink) = t.split();
            let now = tokio::time::Instant::now();

            let mut a_counter = 0;
            let mut b_counter = 0;

            while let Some(Ok(msg)) = stream.next().await {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if now.elapsed().as_secs() > 5 {
                    break;
                }

                if msg.payload() == "hello".as_bytes() {
                    a_counter += 1;
                } else if msg.payload() == "hello2".as_bytes() {
                    b_counter += 1;
                }
            }

            tracing::info!("t1 exit");
            assert_ne!(a_counter, 0);
            assert_ne!(b_counter, 0);
        });

        let tunnel = connector.connect().await.unwrap();
        let mpsc_tunnel = MpscTunnel::new(tunnel, None);

        let sink1 = mpsc_tunnel.get_sink();
        let t2 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                let a = sink1
                    .send(ZCPacket::new_with_payload("hello".as_bytes()))
                    .await;
                if a.is_err() {
                    tracing::info!(?a, "t2 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t2 exit");
        });

        let sink2 = mpsc_tunnel.get_sink();
        let t3 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let a = sink2
                    .send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await;
                if a.is_err() {
                    tracing::info!(?a, "t3 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t3 exit");
        });

        let t4 = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("closing");
            drop(mpsc_tunnel);
            tracing::info!("closed");
        });

        let _ = tokio::join!(t1, t2, t3, t4);
    }

    #[tokio::test]
    async fn mpsc_slow_receiver_with_send_timeout() {
        let (a, _b) = create_ring_tunnel_pair();
        let mpsc_tunnel = MpscTunnel::new(a, Some(Duration::from_secs(1)));
        let s = mpsc_tunnel.get_sink();
        for _ in 0..RING_TUNNEL_CAP {
            s.send(ZCPacket::new_with_payload(&[0; 1024]))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_ok());

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_err());
    }
}
