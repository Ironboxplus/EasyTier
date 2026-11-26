use std::{
    fmt::Debug,
    future,
    sync::{Arc, Mutex},
};
use time::util::refresh_tz;
use tokio::{task::JoinSet, time::timeout};
use tracing::Instrument;

pub mod acl_processor;
pub mod compressor;
pub mod config;
pub mod constants;
pub mod dns;
pub mod egress_inventory;
/// Physical-egress-scoped quality service: inventory reconciliation ->
/// autorate estimate -> allocator -> shared governor/AQM handle
/// (MP_SQM_PLAN.md §4.3). Built on top of `transport_quality`'s pure
/// contracts; never imported by `connector::mp_*` or `tunnel::mpquic`.
pub mod egress_quality;
pub mod env_parser;
pub mod error;
pub mod expiring_set;
pub mod global_ctx;
pub mod idn;
pub mod ifcfg;
pub mod log;
pub mod machine_id;
pub mod netns;
pub mod network;
pub mod os_info;
pub mod punch_pacer;
pub mod stats_manager;
pub mod stun;
pub mod stun_codec_ext;
pub mod token_bucket;
pub mod tracing_rolling_appender;
/// Transport-quality domain contracts.  This module deliberately contains no
/// EasyTier config, RPC, tunnel, or engine dependency: high layers translate
/// user profiles into these values and engine adapters consume them.
pub mod transport_quality;
pub mod upnp;

// MPQUIC is normally built with a minimal feature set. Do not permit that
// build to silently select the unauthenticated XOR fallback: stock EasyTier
// v2.6.4 default builds encrypt peer-RPC payloads with an AEAD.
#[cfg(all(
    feature = "mpquic",
    not(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))
))]
compile_error!(
    "mpquic requires an AEAD backend to remain compatible with stock EasyTier encrypted peers"
);

pub use machine_id::{MachineIdOptions, resolve_machine_id};

pub fn get_logger_timer<F: time::formatting::Formattable>(
    format: F,
) -> tracing_subscriber::fmt::time::OffsetTime<F> {
    refresh_tz();
    let local_offset = time::UtcOffset::current_local_offset()
        .unwrap_or(time::UtcOffset::from_whole_seconds(0).unwrap());
    tracing_subscriber::fmt::time::OffsetTime::new(local_offset, format)
}

pub fn get_logger_timer_rfc3339()
-> tracing_subscriber::fmt::time::OffsetTime<time::format_description::well_known::Rfc3339> {
    get_logger_timer(time::format_description::well_known::Rfc3339)
}

pub type PeerId = u32;

pub fn new_peer_id() -> PeerId {
    rand::random()
}

pub fn join_joinset_background<T: Debug + Send + Sync + 'static>(
    js: Arc<Mutex<JoinSet<T>>>,
    origin: String,
) {
    let js = Arc::downgrade(&js);
    let o = origin.clone();
    tokio::spawn(
        async move {
            while js.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let fut = future::poll_fn(|cx| {
                    let Some(js) = js.upgrade() else {
                        return std::task::Poll::Ready(());
                    };

                    let mut js = js.lock().unwrap();
                    while !js.is_empty() {
                        let ret = js.poll_join_next(cx);
                        match ret {
                            std::task::Poll::Ready(Some(_)) => {
                                continue;
                            }
                            std::task::Poll::Ready(None) => {
                                break;
                            }
                            std::task::Poll::Pending => {
                                return std::task::Poll::Pending;
                            }
                        }
                    }
                    std::task::Poll::Ready(())
                });

                let _ = timeout(std::time::Duration::from_secs(5), fut).await;
            }
            tracing::debug!(?o, "joinset task exit");
        }
        .instrument(tracing::info_span!(
            "join_joinset_background",
            origin = origin
        )),
    );
}

pub fn shrink_dashmap<K: Eq + std::hash::Hash, V>(
    map: &dashmap::DashMap<K, V>,
    threshold: Option<usize>,
) {
    let threshold = threshold.unwrap_or(16);
    if map.capacity() - map.len() > threshold {
        map.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mpquic")]
    #[test]
    fn mpquic_default_encryption_is_aead() {
        assert_eq!(
            config::EncryptionAlgorithm::default(),
            config::EncryptionAlgorithm::AesGcm
        );
    }

    #[tokio::test]
    async fn test_join_joinset_backgroud() {
        let js = Arc::new(Mutex::new(JoinSet::<()>::new()));
        join_joinset_background(js.clone(), "TEST".to_owned());
        js.try_lock().unwrap().spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(js.try_lock().unwrap().is_empty());

        for _ in 0..5 {
            js.try_lock().unwrap().spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            });
            tokio::task::yield_now().await;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        for _ in 0..5 {
            js.try_lock().unwrap().spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            });
            tokio::task::yield_now().await;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(js.try_lock().unwrap().is_empty());

        let weak_js = Arc::downgrade(&js);
        drop(js);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert_eq!(weak_js.weak_count(), 0);
        assert_eq!(weak_js.strong_count(), 0);
    }
}
