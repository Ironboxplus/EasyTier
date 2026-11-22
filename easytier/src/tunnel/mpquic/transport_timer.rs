//! Deadline timer using the existing async-io reactor and native Windows waitable timers.
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

pub(crate) struct TransportTimer {
    #[cfg(not(windows))]
    timer: async_io::Timer,
    #[cfg(windows)]
    timer: async_io::os::windows::Waitable<std::os::windows::io::OwnedHandle>,
    deadline: Option<Instant>,
}

impl TransportTimer {
    pub(crate) fn new() -> io::Result<Self> {
        #[cfg(not(windows))]
        let timer = async_io::Timer::never();
        #[cfg(windows)]
        let timer = {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
            use windows::Win32::System::Threading::{
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateWaitableTimerExW, TIMER_ALL_ACCESS,
            };
            let create =
                |flags| unsafe { CreateWaitableTimerExW(None, None, flags, TIMER_ALL_ACCESS.0) };
            let handle = match create(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION) {
                Ok(handle) => handle,
                Err(error)
                    if error.code()
                        == windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) =>
                {
                    // The high-resolution flag requires Windows 10 1803. Older
                    // supported Windows versions keep a regular waitable timer.
                    tracing::warn!(
                        "high-resolution waitable timers unavailable; using regular Windows timer"
                    );
                    create(Default::default()).map_err(io::Error::other)?
                }
                Err(error) => return Err(io::Error::other(error)),
            };
            // OwnedHandle closes the timer after Waitable deregisters it.
            let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            async_io::os::windows::Waitable::new(owned)?
        };
        Ok(Self {
            timer,
            deadline: None,
        })
    }

    pub(crate) fn set_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        if deadline == self.deadline {
            return Ok(());
        }
        #[cfg(not(windows))]
        match deadline {
            Some(at) => self.timer.set_at(at),
            None => self.timer.clear(),
        }
        #[cfg(windows)]
        match deadline {
            Some(at) => self.arm(at)?,
            None => {
                unsafe { windows::Win32::System::Threading::CancelWaitableTimer(self.raw_handle()) }
                    .map_err(io::Error::other)?
            }
        }
        self.deadline = deadline;
        Ok(())
    }

    #[cfg(windows)]
    fn raw_handle(&self) -> windows::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(self.timer.as_raw_handle())
    }

    #[cfg(windows)]
    fn arm(&self, at: Instant) -> io::Result<()> {
        // Negative FILETIME values are relative 100 ns intervals. Round up,
        // and never pass zero (which would mean an absolute time in 1601).
        let ticks = at
            .saturating_duration_since(Instant::now())
            .as_nanos()
            .div_ceil(100)
            .max(1);
        let due = -i64::try_from(ticks).unwrap_or(i64::MAX);
        unsafe {
            windows::Win32::System::Threading::SetWaitableTimer(
                self.raw_handle(),
                &due,
                0,
                None,
                None,
                false,
            )
        }
        .map_err(io::Error::other)
    }
}

impl Future for TransportTimer {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(at) = this.deadline else {
            return Poll::Pending;
        };
        if Instant::now() >= at {
            this.set_deadline(None)?;
            return Poll::Ready(Ok(()));
        }
        #[cfg(not(windows))]
        return Pin::new(&mut this.timer).poll(cx).map(|_| {
            this.deadline = None;
            Ok(())
        });
        #[cfg(windows)]
        loop {
            if Instant::now() >= at {
                this.set_deadline(None)?;
                return Poll::Ready(Ok(()));
            }
            std::task::ready!(this.timer.poll_ready(cx))?;
            if Instant::now() < at {
                // An old notification may already have been queued when the
                // timer was rescheduled. Consume it and rearm the same handle;
                // it must neither finish a newer deadline early nor lose it.
                this.arm(at)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::time::Duration;

    async fn is_pending(timer: &mut TransportTimer) -> bool {
        poll_fn(|cx| Poll::Ready(Pin::new(&mut *timer).poll(cx).is_pending())).await
    }

    #[tokio::test]
    async fn inactive_cancelled_and_reused_deadlines() {
        let mut timer = TransportTimer::new().unwrap();
        assert!(is_pending(&mut timer).await);
        timer
            .set_deadline(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        assert!(is_pending(&mut timer).await);
        timer.set_deadline(None).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut timer)
                .await
                .is_err()
        );
        let at = Instant::now() + Duration::from_millis(2);
        timer.set_deadline(Some(at)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut timer)
            .await
            .unwrap()
            .unwrap();
        assert!(Instant::now() >= at);
        assert!(is_pending(&mut timer).await);
    }

    #[tokio::test]
    async fn deadlines_can_move_earlier_and_later() {
        let mut timer = TransportTimer::new().unwrap();
        timer
            .set_deadline(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        assert!(is_pending(&mut timer).await);
        let earlier = Instant::now() + Duration::from_millis(2);
        timer.set_deadline(Some(earlier)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut timer)
            .await
            .unwrap()
            .unwrap();
        assert!(Instant::now() >= earlier);
        timer
            .set_deadline(Some(Instant::now() + Duration::from_millis(1)))
            .unwrap();
        let later = Instant::now() + Duration::from_millis(10);
        timer.set_deadline(Some(later)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut timer)
            .await
            .unwrap()
            .unwrap();
        assert!(Instant::now() >= later);
    }

    #[tokio::test]
    async fn an_already_elapsed_deadline_completes_without_an_event() {
        let mut timer = TransportTimer::new().unwrap();
        timer.set_deadline(Some(Instant::now())).unwrap();
        assert!(!is_pending(&mut timer).await);
        assert!(is_pending(&mut timer).await);
    }
}
