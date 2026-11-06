//! Multipath-QUIC tunnel (bandwidth aggregation).
//!
//! This tunnel runs a single QUIC connection whose packets are spread across
//! multiple network paths by TQUIC's multipath scheduler, giving MPTCP-like
//! bandwidth aggregation with a "latency <-> bandwidth" slider (see the
//! `SqmWeighted` scheduler in the vendored TQUIC fork).
//!
//! TQUIC is a sans-io engine: it never touches sockets itself. We therefore run
//! its `Endpoint` on a dedicated OS thread with a current-thread Tokio runtime
//! (the engine holds `Rc`, so it is `!Send`), pump UDP datagrams in/out of it,
//! and bridge the QUIC byte stream to EasyTier's `Tunnel` (a `ZCPacket`
//! stream/sink) through an in-memory `tokio::io::duplex` pipe wrapped by the
//! shared `FramedReader`/`FramedWriter` framing used by every other tunnel.
//!
//! v1 scope: one connection per driver (which is exactly the aggregation case —
//! one connection, many paths). Serving many independent peers from one server
//! endpoint is a follow-up.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use super::common::{BindDev, FramedReader, FramedWriter, TunnelWrapper, bind};
use super::{
    FromUrl, IpVersion, SplitTunnel, Tunnel, TunnelConnector, TunnelError, TunnelInfo,
    TunnelListener,
};
use crate::common::egress_quality::{EgressQualityConfig, EgressQualityManager, SqmSample};
use crate::common::egress_inventory::EgressInventory;
use crate::common::transport_quality::rate::WireBitrate;
use crate::common::transport_quality::{CongestionControlProfile, EgressDirection, EgressScope};
use crate::proto::api::instance::MpDataPlaneStatus;
use super::mp_dataplane::{DataPlanePolicy, MAX_DATAGRAM_FRAME_SIZE, MpPipeZCPacketToBytes};

mod dataplane_driver;
mod egress_cake;
mod fair_pipe;
mod governed_sender;
mod owd;
mod pre_quic_cake;
mod stream_queue;
mod transport_timer;
use dataplane_driver::{CLIENT_PRIMARY_STREAM, DataPlaneDriver};
use governed_sender::{DatagramSender, MpPathRegistry, carrier_id, resolve_egress_scope};
pub(crate) use egress_cake::cake_status;
pub(crate) use governed_sender::{CarrierId, PathKey, path_key};

const MAX_PACKET_SIZE: usize = 2000;
// TQUIC recommends batch I/O; bound each turn as Quinn bounds receive work.
// Only drain packets already available, without waiting to assemble a batch.
const MAX_RECEIVE_BATCH: usize = 32;
/// Size of the in-memory pipe between the driver thread and the ET tunnel.
const DUPLEX_BUF: usize = 256 * 1024;
/// MP_SQM_PLAN.md S2.5 item 3c: when SQM is on, the egress CAKE queue
/// (`egress_cake`) and the stream queues (`stream_queue`) are meant to be the
/// places packets queue up ahead of the wire. The full-size `DUPLEX_BUF`
/// above is generous enough to hide a lot of backlog inside this pipe,
/// invisible to their sojourn measurement -- a hidden second FIFO. Shrunk to
/// a small multiple of the wire MTU: enough to keep the driver's read loop
/// from stalling on a single packet, not enough to queue meaningfully.
const SQM_DUPLEX_BUF: usize = 32 * 1024;
/// The same concern one level further down: TQUIC grows its flow-control
/// windows up to several MB, and a stream accepts writes up to the window,
/// so without a bound the driver would park seconds of data inside the QUIC
/// stream where CAKE does not see it. With SQM on the driver stops
/// pulling from the pipe while more than this much is written but not yet
/// sent (like TCP_NOTSENT_LOWAT): the backlog then waits in the queue in
/// front of the stream (`fair_pipe`, `stream_queue`).
const SQM_STREAM_NOTSENT_LOWAT: u64 = 32 * 1024;
/// The data plane's counterpart: TQUIC queues up to 1 MiB of DATAGRAMs and
/// then drops the oldest, so handing it frames without a bound turned the
/// congestion window into a deep drop-tail queue (seconds of delay on a slow
/// path, then bursts of loss for every inner flow). The data plane sends the
/// next datagram frame only while less than this much waits; the rest waits
/// in the queue in front of QUIC (`pre_quic_cake`), where COBALT judges it
/// per inner flow. Always on: the queue exists whether or not SQM is.
const DGRAM_NOTSENT_LOWAT: usize = 64 * 1024;
/// See `apply_common_config`.
const MP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 16;
/// Application-layer read chunk pulled from the QUIC stream per iteration.
const STREAM_CHUNK: usize = 64 * 1024;
const ALPN: &[u8] = b"et-mpquic";

/// MP_SQM_PLAN.md S2.5 item 3c: which ET<->driver duplex buffer size to use,
/// based on whether this session has SQM enabled. See [`SQM_DUPLEX_BUF`].
fn duplex_buf_bytes(sqm_enabled: bool) -> usize {
    if sqm_enabled { SQM_DUPLEX_BUF } else { DUPLEX_BUF }
}

/// Whether the ET end of the pipe frames its packets as the data plane does
/// (class tag in the length, inner flow hash behind the frame): the data
/// plane needs both, and the single stream of a session with SQM on queues
/// its frames per inner flow by the hash (`fair_pipe`). The driver of such a
/// pipe strips both before anything reaches the wire.
fn pipe_has_flow_trailer(runtime: &MpQuicSessionConfig) -> bool {
    runtime.data_plane || runtime.sqm_enabled
}

/// The session's stream as `fair_pipe` writes to it.
struct ConnStream<'a> {
    conn: &'a mut tquic::Connection,
    stream_id: u64,
}

impl fair_pipe::StreamSink for ConnStream<'_> {
    fn unsent(&mut self) -> u64 {
        self.conn.stream_unsent_bytes(self.stream_id).unwrap_or(0)
    }

    fn write(&mut self, data: &Bytes) -> Result<Option<usize>, String> {
        match self.conn.stream_write(self.stream_id, data.clone(), false) {
            Ok(written) => Ok(Some(written)),
            // Flow-control blocked; retry later.
            Err(tquic::Error::Done) => Ok(None),
            Err(error) => Err(format!("stream_write: {error}")),
        }
    }
}

/// Bytes written to the session's stream but never sent; `0` before the
/// stream exists. See [`SQM_STREAM_NOTSENT_LOWAT`].
fn stream_unsent_bytes(
    endpoint: &mut tquic::Endpoint,
    conn_index: Option<u64>,
    stream_id: Option<u64>,
) -> u64 {
    let (Some(ci), Some(sid)) = (conn_index, stream_id) else {
        return 0;
    };
    endpoint
        .conn_get_mut(ci)
        .and_then(|conn| conn.stream_unsent_bytes(sid))
        .unwrap_or(0)
}

/// A validated path that received nothing for this long is dead. Only time
/// decides this, as in noq's path idle timeout: PTOs drive loss recovery (TQUIC
/// already routes data around a path after a few of them), and on a LAN a
/// run of PTOs spans well under a second, which one Wi-Fi hiccup can cause.
/// 45 s matches EasyTier's own silence timeout for a session and is three
/// `PATH_KEEPALIVE_INTERVAL`s, so a healthy idle path always answers in time.
const PATH_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// ValidatingMTU counts: the peer answered the challenge (relay-next-hop paths
/// stay there, see `path_validation_decision`).
fn path_is_validated(conn: &mut tquic::Connection, local: SocketAddr, remote: SocketAddr) -> bool {
    conn.get_path(local, remote).is_ok_and(|path| {
        matches!(
            path.state(),
            tquic::PathState::Validated | tquic::PathState::ValidatingMTU
        )
    })
}

/// Whether taking `target` out would leave the connection without a path that
/// can carry data. Usable means validated and not abandoned: a path still
/// waiting for its challenge to be answered (one offered while the network was
/// down, say) is not a path to keep the session on, and removing it is always
/// fine. Mirrors noq `ClosePathError::LastOpenPath`.
fn removal_takes_last_usable_path(
    conn: &mut tquic::Connection,
    path_specs: &[(SocketAddr, SocketAddr)],
    target: (SocketAddr, SocketAddr),
) -> bool {
    fn usable(conn: &mut tquic::Connection, (local, remote): (SocketAddr, SocketAddr)) -> bool {
        path_is_validated(conn, local, remote)
            && conn
                .get_path(local, remote)
                .is_ok_and(|path| !path.is_abandoned())
    }
    usable(conn, target)
        && !path_specs
            .iter()
            .any(|spec| *spec != target && usable(conn, *spec))
}

/// How often a validated path that sent nothing gets a keep-alive PING. NATs
/// drop idle UDP mappings after 30 s or more (RFC 4787 asks for 2 min), and a
/// path the optimizer holds idle (paused, excluded, not pinned) must still work
/// when it is needed again.
const PATH_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// PING every validated path whose sent bytes did not move since the last
/// round; `last_sent` carries each path's count to the next round.
fn keepalive_idle_paths(
    conn: &mut tquic::Connection,
    path_specs: &[(SocketAddr, SocketAddr)],
    last_sent: &mut HashMap<(SocketAddr, SocketAddr), u64>,
) {
    let mut sent_now = HashMap::with_capacity(path_specs.len());
    for &(local, remote) in path_specs {
        if !path_is_validated(conn, local, remote) {
            continue;
        }
        let Ok(stats) = conn.get_path_stats(local, remote) else {
            continue;
        };
        let sent = stats.sent_bytes;
        if last_sent.get(&(local, remote)) == Some(&sent) {
            let _ = conn.ping(Some(tquic::FourTuple { local, remote }));
        }
        sent_now.insert((local, remote), sent);
    }
    *last_sent = sent_now;
}

/// What the driver can tell about one of its paths by looking at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathHealth {
    /// Not validated yet, or not in TQUIC yet (the peer's first packet on it
    /// has not arrived): nothing to judge.
    Pending,
    Validated {
        /// Time since a packet last arrived on it.
        idle: std::time::Duration,
    },
}

/// Validated paths that heard nothing for `idle_timeout`, never the last
/// usable one (a single-path session rides out an outage and lets the idle
/// timeout decide). Compares timestamps, so it does not depend on when it is
/// looked at; what became of a path (abandoned, dropped) comes from
/// [`specs_to_retire_for_events`] instead.
fn paths_to_retire(
    paths: &[((SocketAddr, SocketAddr), PathHealth)],
    idle_timeout: std::time::Duration,
) -> Vec<(SocketAddr, SocketAddr)> {
    let mut alive = 0usize;
    let mut dead = Vec::new();
    for &(spec, health) in paths {
        match health {
            PathHealth::Pending => {}
            PathHealth::Validated { idle } if idle >= idle_timeout => dead.push(spec),
            PathHealth::Validated { .. } => alive += 1,
        }
    }
    if alive == 0 {
        dead.clear();
    }
    dead
}

/// The paths of `path_specs` that went silent for `PATH_IDLE_TIMEOUT`, see
/// [`paths_to_retire`].
fn black_hole_paths(
    conn: &mut tquic::Connection,
    path_specs: &[(SocketAddr, SocketAddr)],
) -> Vec<(SocketAddr, SocketAddr)> {
    let mut health = Vec::with_capacity(path_specs.len());
    for &(local, remote) in path_specs {
        let state = if conn
            .get_path(local, remote)
            .is_ok_and(|path| path.is_abandoned())
            || !path_is_validated(conn, local, remote)
        {
            PathHealth::Pending
        } else if let Ok(stats) = conn.get_path_stats(local, remote) {
            PathHealth::Validated {
                idle: std::time::Duration::from_micros(stats.idle_time),
            }
        } else {
            PathHealth::Pending
        };
        health.push(((local, remote), state));
    }
    paths_to_retire(&health, PATH_IDLE_TIMEOUT)
}

/// QUIC transport error NO_VIABLE_PATH (draft-ietf-quic-multipath).
const QUIC_NO_VIABLE_PATH: u64 = 0x10;

/// How long a session whose last path failed waits for a replacement path
/// before it closes with NO_VIABLE_PATH: three probe timeouts (noq,
/// `noq-proto/src/connection/mod.rs`, closes the same way after
/// `3 * pto_max_path` when the remote abandoned the last path). The probe
/// timeout is estimated as RFC 9002's `srtt + 4 * rttvar` with the
/// `rttvar = srtt / 2` a fresh estimator starts from. At least one second:
/// a replacement path needs a punch, which takes more than one round trip.
fn last_path_grace(srtt_micros: u64) -> std::time::Duration {
    let pto = srtt_micros.saturating_mul(3).max(1_000);
    std::time::Duration::from_micros(pto.saturating_mul(3)).max(std::time::Duration::from_secs(1))
}

/// Whether the failed `removed` paths are every path the session has, so that
/// abandoning them would leave it without one.
fn failure_takes_last_path(
    path_specs: &[(SocketAddr, SocketAddr)],
    removed: &[(SocketAddr, SocketAddr)],
) -> bool {
    !path_specs.is_empty() && path_specs.iter().all(|spec| removed.contains(spec))
}

/// Which TQUIC path (its serial) each driver path spec currently stands for.
type BoundPaths = HashMap<(SocketAddr, SocketAddr), u64>;

/// Specs to retire according to TQUIC's path events: a path the peer
/// abandoned, or one that drained and was dropped. An event is matched to a
/// spec by 4-tuple *and* path serial, so the events of a path an earlier mount
/// of the same 4-tuple stood for never retire the mount that replaced it.
/// `bound` follows the spec: an `Opened` path binds it.
fn specs_to_retire_for_events(
    events: &[tquic::PathLifecycleEvent],
    path_specs: &[(SocketAddr, SocketAddr)],
    bound: &mut BoundPaths,
) -> Vec<(SocketAddr, SocketAddr)> {
    use tquic::PathLifecycleEvent::*;
    let mut retire = Vec::new();
    for event in events {
        match *event {
            Opened { local, remote, serial } if path_specs.contains(&(local, remote)) => {
                bound.insert((local, remote), serial);
            }
            // This end abandoned it (the spec is removed by whoever did).
            Abandoned { local, remote, serial, by_peer: false, .. }
                if bound.get(&(local, remote)) == Some(&serial) =>
            {
                bound.remove(&(local, remote));
            }
            Abandoned { local, remote, serial, by_peer: true, .. }
            | Discarded { local, remote, serial, .. }
                if bound.get(&(local, remote)) == Some(&serial) =>
            {
                bound.remove(&(local, remote));
                if path_specs.contains(&(local, remote)) && !retire.contains(&(local, remote)) {
                    retire.push((local, remote));
                }
            }
            _ => {}
        }
    }
    retire
}

/// Take TQUIC's path events and return the specs they retire. Specs that no
/// event bound yet (the session's first path exists before anyone listens)
/// are bound to the live path on their 4-tuple.
fn retired_by_path_events(
    conn: &mut tquic::Connection,
    path_specs: &[(SocketAddr, SocketAddr)],
    bound: &mut BoundPaths,
) -> Vec<(SocketAddr, SocketAddr)> {
    let events = conn.take_path_events();
    let retire = specs_to_retire_for_events(&events, path_specs, bound);
    bound.retain(|spec, _| path_specs.contains(spec));
    for &(local, remote) in path_specs {
        if !bound.contains_key(&(local, remote))
            && let Ok(path) = conn.get_path(local, remote)
            && !path.is_abandoned()
        {
            bound.insert((local, remote), path.serial());
        }
    }
    retire
}

/// Forget a path spec: abandon its path (a no-op if TQUIC no longer has it),
/// drop it from the driver's lists and registry, and report it down.
fn retire_path_spec(
    (local, remote): (SocketAddr, SocketAddr),
    conn: &mut tquic::Connection,
    path_specs: &mut Vec<(SocketAddr, SocketAddr)>,
    path_registry: &RwLock<MpPathRegistry>,
    recv_tasks: &mut HashMap<CarrierId, tokio::task::JoinHandle<()>>,
    pending_path_events: &mut VecDeque<MpPathEvent>,
) -> anyhow::Result<()> {
    if let Err(error) = conn.abandon_path(local, remote) {
        tracing::debug!(?error, "failed to abandon retired MP path");
    }
    path_specs.retain(|spec| *spec != (local, remote));
    let key = path_registry
        .read()
        .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
        .key_for_addresses(local, remote);
    if let Some(key) = key {
        unregister_path(key, path_registry, recv_tasks)?;
        pending_path_events.push_back(MpPathEvent::Down(key));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS + config
// ---------------------------------------------------------------------------

/// A process-wide self-signed cert/key written to temp files once.
///
/// The QUIC-layer TLS is not the security boundary here (EasyTier keeps its own
/// Noise/AEAD layer above the tunnel and the client disables verification), so
/// a throwaway self-signed identity is sufficient and avoids a real PKI.
struct SelfSignedCert {
    cert_path: String,
    key_path: String,
}

fn self_signed() -> Result<&'static SelfSignedCert, TunnelError> {
    // `get_or_init` runs the generator EXACTLY once and blocks all other
    // callers until it finishes, so concurrent server drivers can never race to
    // generate two different cert/key pairs and clobber each other's files (a
    // fixed path plus a plain get/set TOCTOU produced a mismatched cert+key that
    // BoringSSL rejected). The PID also keeps separate processes from colliding.
    static CERT: OnceLock<Result<SelfSignedCert, String>> = OnceLock::new();
    CERT.get_or_init(|| {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("rcgen: {e}"))?;
        let cert_pem = cert
            .serialize_pem()
            .map_err(|e| format!("serialize cert: {e}"))?;
        let key_pem = cert.serialize_private_key_pem();

        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert_path = dir.join(format!("et-mpquic-{pid}-cert.pem"));
        let key_path = dir.join(format!("et-mpquic-{pid}-key.pem"));
        std::fs::write(&cert_path, cert_pem).map_err(|e| format!("write cert: {e}"))?;
        std::fs::write(&key_path, key_pem).map_err(|e| format!("write key: {e}"))?;
        Ok(SelfSignedCert {
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
        })
    })
    .as_ref()
    .map_err(|e| TunnelError::InternalError(e.clone()))
}

/// Map the ET-side [`MpAlgorithm`](super::mp_plugin::MpAlgorithm) onto TQUIC's
/// own scheduler enum (kept separate so the plugin registry stays TQUIC-free).
fn mp_algorithm_to_tquic(a: super::mp_plugin::MpAlgorithm) -> tquic::MultipathAlgorithm {
    use super::mp_plugin::MpAlgorithm;
    match a {
        MpAlgorithm::MinRtt => tquic::MultipathAlgorithm::MinRtt,
        MpAlgorithm::RoundRobin => tquic::MultipathAlgorithm::RoundRobin,
        MpAlgorithm::Redundant => tquic::MultipathAlgorithm::Redundant,
        MpAlgorithm::SqmWeighted => tquic::MultipathAlgorithm::SqmWeighted,
    }
}

/// Normalize an `ET_MPQUIC_SCHED` value (incl. legacy aliases `rr`/`sqm`) to a
/// plugin registry name; unknown/empty falls back to the default `min-rtt`.
fn normalize_sched_name(v: &str) -> &'static str {
    match v.to_ascii_lowercase().as_str() {
        "redundant" => "redundant",
        "roundrobin" | "rr" | "round-robin" => "round-robin",
        "sqm" | "sqm-weighted" => "sqm-weighted",
        _ => "min-rtt",
    }
}

/// Selects the multipath scheduler via the plugin registry (MP_SQM_PLAN.md §5),
/// so the algorithm set is data-driven and shared with config/GUI. Defaults to
/// MinRtt so the pipe is first validated with a stock, proven scheduler
/// (MP_SQM_PLAN.md 阶段2 v1 scope). Override with
/// `ET_MPQUIC_SCHED=minrtt|redundant|roundrobin|sqm`.
fn mp_runtime_config_from_env() -> MpQuicSessionConfig {
    let raw = std::env::var("ET_MPQUIC_SCHED").unwrap_or_default();
    let name = normalize_sched_name(&raw);
    let registry = super::mp_plugin::MpSchedulerRegistry::with_builtins();
    let resolved = registry.resolve(name, &serde_json::json!({})).unwrap_or(
        super::mp_plugin::ResolvedMpConfig {
            algorithm: super::mp_plugin::MpAlgorithm::MinRtt,
            lambda: 0.5,
        },
    );
    resolved.into()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct MpQuicSessionConfig {
    pub(crate) algorithm: super::mp_plugin::MpAlgorithm,
    pub(crate) lambda: f64,
    /// Installed into both client and server TQUIC Config before endpoint
    /// creation. This is deliberately an engine adapter value, not a fake
    /// cross-engine CongestionController trait.
    pub(crate) congestion_control: CongestionControlProfile,
    /// MP_SQM_PLAN.md S2.4: Brutal's fixed send-rate target, in bytes/sec
    /// (TQUIC's `RecoveryConfig::brutal_bps` convention -- NOT the ET-wide
    /// bits/sec convention), converted from `MpConfig.congestion_control_
    /// params_json`'s `up_mbps` (Mbit/s) via `brutal_mbps_to_bytes_per_sec`.
    /// Meaningless (left at the default `0`) for every other
    /// `congestion_control`.
    pub(crate) brutal_bps: u64,
    /// MP_SQM_PLAN.md S2.4: Brutal's loss-compensation toggle, same source.
    pub(crate) brutal_disable_loss_compensation: bool,
    pub(crate) establishment_timeout: std::time::Duration,
    /// MP_SQM_PLAN.md S2.5 item 3c: mirrors `MpConfig.sqm.enabled`. Set by
    /// `apply_congestion_control_from_mp_config`, the one function both the
    /// standalone (`apply_standalone_transport_config`) and MP-managed
    /// (`mp_session.rs::quic_config`) session builders route through, so
    /// both session kinds shrink QUIC's flow-control windows and the ET<->
    /// driver duplex buffer identically. See [`duplex_buf_bytes`] and
    /// `apply_common_config`.
    pub(crate) sqm_enabled: bool,
    /// MP_SQM_PLAN.md S2.9/S2.10: advertise `max_datagram_frame_size` and run
    /// the datagram data plane (`dataplane_driver`). Only MP-managed
    /// sessions set it (`mp_session.rs::quic_config`); it is fixed for the
    /// session's life because the transport parameter is exchanged in the
    /// handshake.
    pub(crate) data_plane: bool,
}

impl From<super::mp_plugin::ResolvedMpConfig> for MpQuicSessionConfig {
    fn from(value: super::mp_plugin::ResolvedMpConfig) -> Self {
        Self {
            algorithm: value.algorithm,
            lambda: value.lambda,
            congestion_control: CongestionControlProfile::EngineDefault,
            brutal_bps: 0,
            brutal_disable_loss_compensation: false,
            establishment_timeout: std::time::Duration::from_secs(10),
            sqm_enabled: false,
            data_plane: false,
        }
    }
}

impl Default for MpQuicSessionConfig {
    fn default() -> Self {
        Self {
            algorithm: super::mp_plugin::MpAlgorithm::MinRtt,
            lambda: 0.5,
            congestion_control: CongestionControlProfile::EngineDefault,
            brutal_bps: 0,
            brutal_disable_loss_compensation: false,
            sqm_enabled: false,
            establishment_timeout: std::time::Duration::from_secs(10),
            data_plane: false,
        }
    }
}

pub(crate) fn congestion_control_from_mp_config(
    config: &crate::proto::common::MpConfig,
) -> Result<CongestionControlProfile, TunnelError> {
    let profile = CongestionControlProfile::parse(&config.congestion_control)
        .map_err(|error| TunnelError::InvalidProtocol(error.to_string()))?;
    if profile == CongestionControlProfile::DummyExperimental {
        return Err(TunnelError::InvalidProtocol(
            "mp.congestion_control=dummy is test/experimental only".into(),
        ));
    }
    Ok(profile)
}

/// Resolves `MpConfig.congestion_control`/`congestion_control_params_json`
/// together and applies the result onto `runtime` (MP_SQM_PLAN.md S2.4).
/// Shared by both the standalone and MP-managed session config builders so
/// Brutal's tx/loss-compensation params reach TQUIC's `Config` exactly the
/// same way regardless of which path built the session.
///
/// `validate_mp_config` already rejects a config where brutal has no tx, so a
/// resolve failure here only happens for a config that skipped validation
/// (e.g. a stale in-memory config); treat it the same way -- refuse to start
/// rather than silently falling back to some made-up rate.
pub(crate) fn apply_congestion_control_from_mp_config(
    mut runtime: MpQuicSessionConfig,
    config: &crate::proto::common::MpConfig,
) -> Result<MpQuicSessionConfig, TunnelError> {
    runtime.congestion_control = congestion_control_from_mp_config(config)?;
    let params: serde_json::Value = serde_json::from_str(&config.congestion_control_params_json)
        .map_err(|error| {
            TunnelError::InvalidProtocol(format!(
                "mp.congestion_control_params_json must be valid JSON: {error}"
            ))
        })?;
    match super::mp_plugin::MpCcRegistry::with_builtins()
        .resolve(runtime.congestion_control.as_str(), &params)
    {
        Some(Ok(super::mp_plugin::ResolvedCcConfig::Native)) | None => {
            runtime.brutal_bps = 0;
            runtime.brutal_disable_loss_compensation = false;
        }
        Some(Ok(super::mp_plugin::ResolvedCcConfig::Brutal(tunables))) => {
            // `up_mbps` is Mbit/s (§9's schema); TQUIC's `brutal_bps` is
            // bytes/sec -- getting this conversion wrong (or skipping it)
            // silently paces at 8x the configured rate.
            runtime.brutal_bps = super::mp_plugin::brutal_mbps_to_bytes_per_sec(tunables.up_mbps);
            runtime.brutal_disable_loss_compensation = tunables.disable_loss_compensation;
        }
        Some(Err(message)) => return Err(TunnelError::InvalidProtocol(message)),
    }
    // MP_SQM_PLAN.md S2.5 item 3c: both the standalone and MP-managed
    // session builders route through this function, so setting it here
    // (rather than in each caller separately) is the one place that keeps
    // it in sync with `MpConfig.sqm.enabled` for every session kind.
    runtime.sqm_enabled = config.sqm.as_ref().is_some_and(|sqm| sqm.enabled);
    Ok(runtime)
}

/// Apply only the transport-engine settings to an explicitly configured
/// `mpquic://` connector/listener. `mp.enabled` controls the dynamic MP path
/// manager, not whether an explicitly selected TQUIC transport may run with
/// one path. Preserve the legacy environment-selected scheduler here because
/// an N=1 session has no path choice; do not silently reinterpret every
/// standalone peer as a managed multi-path session.
fn apply_standalone_transport_config(
    runtime: MpQuicSessionConfig,
    config: &crate::proto::common::MpConfig,
) -> Result<MpQuicSessionConfig, TunnelError> {
    let mut runtime = apply_congestion_control_from_mp_config(runtime, config)?;
    runtime.establishment_timeout =
        std::time::Duration::from_millis(config.establishment_timeout_ms);
    Ok(runtime)
}

fn standalone_runtime_from_mp_config(
    config: &crate::proto::common::MpConfig,
) -> Result<MpQuicSessionConfig, TunnelError> {
    apply_standalone_transport_config(mp_runtime_config_from_env(), config)
}

fn tquic_congestion_control(
    profile: CongestionControlProfile,
) -> tquic::CongestionControlAlgorithm {
    match profile {
        // TQUIC's Config default is BBR; spell it out here to make the
        // preserved legacy/default effective value observable and deterministic.
        CongestionControlProfile::EngineDefault | CongestionControlProfile::Bbr => {
            tquic::CongestionControlAlgorithm::Bbr
        }
        CongestionControlProfile::Cubic => tquic::CongestionControlAlgorithm::Cubic,
        CongestionControlProfile::Bbr3 => tquic::CongestionControlAlgorithm::Bbr3,
        CongestionControlProfile::Copa => tquic::CongestionControlAlgorithm::Copa,
        CongestionControlProfile::Brutal => tquic::CongestionControlAlgorithm::Brutal,
        CongestionControlProfile::DummyExperimental => tquic::CongestionControlAlgorithm::Dummy,
    }
}

/// TQUIC's datagram bypass trips a circuit breaker after sustained loss
/// (RFC 8084 for a tunnel with no congestion control of its own). With SQM on
/// the egress CAKE queue is the rate limit, and its AQM drops are not network
/// congestion for the breaker to act on, so it stays off; without SQM nothing
/// below limits the bypass and the breaker is its only safeguard.
fn datagram_bypass_breaker(runtime: MpQuicSessionConfig) -> bool {
    !runtime.sqm_enabled
}

fn apply_common_config(config: &mut tquic::Config, runtime: MpQuicSessionConfig) {
    let cc = tquic_congestion_control(runtime.congestion_control);
    config.set_congestion_control_algorithm(cc);
    // Harmless to set unconditionally: TQUIC's Brutal controller is the only
    // reader of these, and it is only selected when `congestion_control ==
    // Brutal`, in which case `brutal_bps` was resolved from a validated
    // config (`validate_mp_config` refuses brutal without a configured tx).
    config.set_brutal_bps(runtime.brutal_bps);
    config.set_brutal_disable_loss_compensation(runtime.brutal_disable_loss_compensation);
    // TQUIC's default stateless-reset key is empty, i.e. the same for every
    // endpoint everywhere.  A simultaneous open leaves the losing handshake's
    // endpoint on a socket the winning session then probes; that endpoint
    // answered with a reset valid for the winner and killed it.  RFC 9000
    // §10.3: the key must be the endpoint's own secret.
    let mut reset_key = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut reset_key);
    config.set_reset_token_key(reset_key);
    config.enable_multipath(true);
    // Every path needs its own connection ID from the peer, and the peer
    // issues one fewer than this limit (TQUIC caps it at 16; a peer built
    // before that caps it at 8, and the lower limit wins). The default 2
    // allowed a single path beyond the first: a relay path plus one punched
    // or per-NIC path, and every further path waited forever unvalidated.
    config.set_active_connection_id_limit(MP_ACTIVE_CONNECTION_ID_LIMIT);
    config.set_multipath_algorithm(mp_algorithm_to_tquic(runtime.algorithm));
    // Keep-alives keep a working session from idling out, so this only
    // decides how long an outage is waited out. A cellular uplink stalls for
    // 18-60 s and comes back; the peer connection above it waits 45 s
    // (`peers::peer_conn_ping::MIN_SILENCE_BEFORE_CLOSE`), and the session
    // must not give up before it. The peer's smaller value still wins.
    config.set_max_idle_timeout(60_000);
    // The probe timeout of a path that hears nothing grows by at most this much
    // per consecutive timeout (noq `MAX_PTO_INTERVAL`, also 2 s). Plain
    // exponential backoff reaches tens of seconds within the idle timeout
    // above, and after an outage the first probe through can be that far off
    // (a 20 s outage was noticed 10 s after the link returned); a first hop
    // that reconnects in about 3 s needs a probe every 2 s to be found.
    config.set_max_pto_interval(2_000);
    // MP_SQM_PLAN.md S2.9: a full Ethernet-MTU UDP payload. The peer sends
    // at most the smaller of this and its own limit, and DPLPMTUD raises the
    // send size from 1200 only as far as each path proves.
    config.set_recv_udp_payload_size(1472);
    config.set_send_udp_payload_size(1200);
    // MP_SQM_PLAN.md S2.14: peer-reported addresses identify each path's WAN.
    // A peer without the transport parameter never reports, as before.
    config.enable_address_discovery(true);
    if runtime.data_plane {
        config.set_max_datagram_frame_size(MAX_DATAGRAM_FRAME_SIZE);
        // RFC 9484 Section 10.2: datagram classes are not held by the outer
        // congestion window; the egress CAKE queue is their AQM.
        config.enable_datagram_bypass_cwnd(true);
        config.enable_datagram_bypass_breaker(datagram_bypass_breaker(runtime));
    }
    if runtime.sqm_enabled {
        // MP_SQM_PLAN.md S2.5 item 3c: SQM's whole point is that the egress
        // CAKE queue is where packets queue. Multi-megabyte flow-control
        // windows would let TQUIC itself buffer seconds of backlog that CAKE
        // never sees or schedules -- a hidden second FIFO. Shrunk
        // to a small multiple of the wire MTU: enough for a few packets of
        // pipelining, not enough to become a queue in its own right.
        config.set_initial_max_data(256 * 1024);
        config.set_initial_max_stream_data_bidi_local(128 * 1024);
        config.set_initial_max_stream_data_bidi_remote(128 * 1024);
    } else {
        // Generous flow-control windows: the tunnel carries an aggregate of
        // many logical flows, so we do not want QUIC-level windows to be the
        // bottleneck.
        config.set_initial_max_data(64 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_local(16 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(16 * 1024 * 1024);
    }
    // The data plane opens up to `reliable_stream_max` (<= 1024) streams per
    // flow class on top of the primary one.
    config.set_initial_max_streams_bidi(if runtime.data_plane { 1100 } else { 16 });
}

fn client_config(runtime: MpQuicSessionConfig) -> Result<tquic::Config, TunnelError> {
    let mut config =
        tquic::Config::new().map_err(|e| TunnelError::InternalError(format!("config: {e}")))?;
    let mut tls = tquic::TlsConfig::new_client_config(vec![ALPN.to_vec()], false)
        .map_err(|e| TunnelError::InternalError(format!("tls client: {e}")))?;
    tls.set_verify(false);
    config.set_tls_config(tls);
    apply_common_config(&mut config, runtime);
    Ok(config)
}

fn server_config(runtime: MpQuicSessionConfig) -> Result<tquic::Config, TunnelError> {
    let cert = self_signed()?;
    let mut config =
        tquic::Config::new().map_err(|e| TunnelError::InternalError(format!("config: {e}")))?;
    let tls = tquic::TlsConfig::new_server_config(
        &cert.cert_path,
        &cert.key_path,
        vec![ALPN.to_vec()],
        false,
    )
    .map_err(|e| TunnelError::InternalError(format!("tls server: {e}")))?;
    config.set_tls_config(tls);
    apply_common_config(&mut config, runtime);
    Ok(config)
}

// ---------------------------------------------------------------------------
// Sans-io plumbing: packet sender + event-recording transport handler
// ---------------------------------------------------------------------------

/// MP_SQM_PLAN.md S1.2: the carrier trait itself moved to
/// `tunnel::datagram_carrier::DatagramCarrier` (its shape is this trait's
/// former `local_addr`/`try_send_to`/`recv_from`, plus default `mtu()`/
/// `per_packet_overhead()` methods merged in from the old, separate
/// `DatagramCarrier` that used to live only there). This alias keeps every
/// existing `MpDatagramPath` reference in this crate (`connector::mp_path`,
/// `connector::mp_relay`, `connector::mp_session`, `connector::
/// tcp_hole_punch_transport`, `tunnel::fake_tcp`) compiling unmodified --
/// only the trait's one true definition and location changed, not its name
/// at any of those call sites.
pub(crate) use super::datagram_carrier::DatagramCarrier as MpDatagramPath;

struct UdpDatagramPath {
    local_addr: SocketAddr,
    socket: UdpSocket,
}

pub(crate) struct SharedUdpDatagramPath {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    _lifetime_guard: Option<Arc<dyn Send + Sync>>,
}

/// A shared UDP socket whose peer endpoint is intentionally unknown when the
/// path is armed.  Symmetric NAT punching cannot know the eventual source port
/// in advance; the server learns it from the first TQUIC Initial and replies
/// with `send_to` on this same socket.  This is a transport carrier only — the
/// original EasyTier punch algorithm still owns mapping creation and retry.
pub(crate) struct SharedUnconnectedUdpDatagramPath {
    local_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    _lifetime_guard: Option<Arc<dyn Send + Sync>>,
}

impl SharedUnconnectedUdpDatagramPath {
    pub(crate) fn new_with_guard(
        socket: Arc<UdpSocket>,
        lifetime_guard: Option<Arc<dyn Send + Sync>>,
    ) -> std::io::Result<Self> {
        set_dont_fragment(&socket);
        Ok(Self {
            local_addr: socket.local_addr()?,
            socket,
            _lifetime_guard: lifetime_guard,
        })
    }
}

/// RFC 9000 §14: QUIC must not let IPv4 routers or the local stack fragment
/// its datagrams, otherwise DPLPMTUD never sees a probe fail and the path
/// MTU never shrinks.  `IP_PMTUDISC_PROBE` sets DF but ignores the kernel's
/// cached PMTU, as quinn does, leaving the search to tquic.
fn set_dont_fragment(socket: &UdpSocket) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let value: nix::libc::c_int = nix::libc::IP_PMTUDISC_PROBE;
        let v6_value: nix::libc::c_int = nix::libc::IPV6_PMTUDISC_PROBE;
        for (level, name, value) in [
            (nix::libc::IPPROTO_IP, nix::libc::IP_MTU_DISCOVER, value),
            (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_MTU_DISCOVER, v6_value),
        ] {
            // The IPv6 option fails on IPv4 sockets and vice versa; either
            // way the socket keeps working, just without DF.
            let _ = unsafe {
                nix::libc::setsockopt(
                    fd,
                    level,
                    name,
                    &value as *const _ as *const nix::libc::c_void,
                    std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
                )
            };
        }
    }
    #[cfg(windows)]
    crate::arch::windows::set_dont_fragment(socket);
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    let _ = socket;
}

impl SharedUdpDatagramPath {
    pub(crate) async fn connect(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
    ) -> std::io::Result<Self> {
        Self::connect_with_guard(socket, remote_addr, None).await
    }

    pub(crate) async fn connect_with_guard(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        lifetime_guard: Option<Arc<dyn Send + Sync>>,
    ) -> std::io::Result<Self> {
        socket.connect(remote_addr).await?;
        set_dont_fragment(&socket);
        Ok(Self {
            local_addr: socket.local_addr()?,
            remote_addr,
            socket,
            _lifetime_guard: lifetime_guard,
        })
    }
}

#[async_trait::async_trait]
impl MpDatagramPath for SharedUdpDatagramPath {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
        if remote != self.remote_addr {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "connected UDP carrier targets {}, not {remote}",
                    self.remote_addr
                ),
            ));
        }
        self.socket.try_send(payload)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket
            .recv(buf)
            .await
            .map(|size| (size, self.remote_addr))
    }
}

#[async_trait::async_trait]
impl MpDatagramPath for SharedUnconnectedUdpDatagramPath {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
        self.socket.try_send_to(payload, remote)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

#[async_trait::async_trait]
impl MpDatagramPath for UdpDatagramPath {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
        self.socket.try_send_to(payload, remote)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

enum MpPathInput {
    Udp {
        local_addr: SocketAddr,
        socket: std::net::UdpSocket,
    },
    /// With the path's NIC-level egress scope when the caller resolved one.
    Ready(Arc<dyn MpDatagramPath>, Option<EgressScope>),
}

impl MpPathInput {
    fn udp(local_addr: SocketAddr, socket: std::net::UdpSocket) -> Self {
        Self::Udp { local_addr, socket }
    }

    fn activate(
        self,
    ) -> std::io::Result<(Arc<dyn MpDatagramPath>, Option<EgressScope>)> {
        match self {
            Self::Udp { local_addr, socket } => {
                socket.set_nonblocking(true)?;
                let socket = UdpSocket::from_std(socket)?;
                set_dont_fragment(&socket);
                Ok((
                    Arc::new(UdpDatagramPath { local_addr, socket }),
                    None,
                ))
            }
            Self::Ready(path, nic_scope) => Ok((path, nic_scope)),
        }
    }
}

/// Events surfaced by the (synchronous) transport callbacks and drained by the
/// asynchronous driver loop.
#[derive(Debug)]
enum DrvEvent {
    Established(u64),
    StreamCreated(u64, u64),
    Readable(u64, u64),
    StreamClosed(u64, u64),
    Closed(u64),
}

/// What a refused `add_path` says when the connection has no free connection
/// ID or path slot: the peer gave it as many connection IDs as paths it may
/// hold, and an abandoned path returns its own only once it drained. The
/// counterpart of noq `PathError::RemoteCidsExhausted`/`MaxPathIdReached`.
pub(crate) const NO_FREE_PATH_SLOT: &str = "mpquic add_path: no free QUIC path slot";

/// Whether `error` is an `add_path` refused for [`NO_FREE_PATH_SLOT`], i.e. a
/// failure worth retrying rather than the end of that path.
pub(crate) fn is_no_free_path_slot(error: &TunnelError) -> bool {
    matches!(error, TunnelError::InternalError(message) if message == NO_FREE_PATH_SLOT)
}

/// What a refused `remove_path` says when the path is the last one the session
/// has: it stays, and QUIC (its idle timeout, or the grace period after the
/// peer abandoned it) decides whether the connection lives, not this path's
/// socket or first hop. The counterpart of noq `ClosePathError::LastOpenPath`.
pub(crate) const LAST_OPEN_PATH: &str = "mpquic remove_path: last open path of the session";

/// Whether `error` is a `remove_path` refused for [`LAST_OPEN_PATH`], i.e. the
/// path was kept rather than failed to remove.
pub(crate) fn is_last_open_path(error: &TunnelError) -> bool {
    matches!(error, TunnelError::InternalError(message) if message == LAST_OPEN_PATH)
}

enum DriverCommand {
    /// EasyTier has declared the peer unavailable.  End the MP driver even if
    /// the application pipe has not observed its close yet, so a stale session
    /// can never outlive EasyTier's peer lifecycle.
    Shutdown,
    AddPath {
        path: Arc<dyn MpDatagramPath>,
        remote: SocketAddr,
        nic_scope: Option<EgressScope>,
        result: oneshot::Sender<Result<(), String>>,
    },
    SnapshotPaths {
        result: oneshot::Sender<Result<Vec<MpPathTelemetry>, String>>,
    },
    SetPathTargets {
        targets: Vec<MpPathTarget>,
        result: oneshot::Sender<Result<(), String>>,
    },
    RemovePath {
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        result: oneshot::Sender<Result<(), String>>,
    },
    SetScheduler {
        runtime: MpQuicSessionConfig,
        result: oneshot::Sender<Result<(), String>>,
    },
    TakePathEvents {
        result: oneshot::Sender<Vec<MpPathEvent>>,
    },
    /// MP_SQM_PLAN.md S2.5: "standalone session 同样按出口发布 autorate 样本".
    /// Fire-and-forget (no `result`): a best-effort periodic sample, not a
    /// request whose outcome a caller needs to act on. Deliberately routed
    /// through this existing command channel -- processed inside the same
    /// `Some(command) = commands.recv() => {...}` branch every other command
    /// already uses -- rather than a dedicated `tokio::time::interval` arm in
    /// `drive()`'s own `tokio::select!`. A real loopback measurement
    /// (`mpquic_loopback_udp_brutal_goodput_tracks_configured_up_mbps`) showed
    /// that adding a *new* always-ready timer branch to that `select!`
    /// measurably starved Brutal's packet pacing even though the branch body
    /// (`sample_standalone_autorate`) did not touch the governor in that
    /// measurement -- isolating the cause narrowed it to the
    /// extra `tokio::select!` branch itself (a raw `Interval`), not the stats
    /// read or the egress-quality publish underneath it. `commands.recv()` is
    /// already one of this same `select!`'s branches on every driver
    /// (MP-managed sessions poll it every `control_interval_ms` for
    /// `SnapshotPaths`, default 500 ms, with no observed Brutal regression),
    /// so reusing it keeps this to a periodic *message*, not a competing
    /// timer source.
    PublishAutorateSample,
    /// MP_SQM_PLAN.md S2.10: the current data-plane policy and the peer's
    /// announced `mp_dataplane_caps`. Fire-and-forget, re-sent every control
    /// tick; a session built without the data plane ignores it.
    SetDataPlane {
        policy: Arc<DataPlanePolicy>,
        peer_caps: Option<u32>,
    },
    SnapshotDataPlane {
        result: oneshot::Sender<MpDataPlaneStatus>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MpPathTarget {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    /// Bits/sec (`mp_optimizer`'s `path_rates_bps`/`capacity_bps` convention,
    /// the ET-wide `_bps` unit) -- NOT TQUIC's `set_path_target_rate`/
    /// `RecoveryConfig::brutal_bps`, which are bytes/sec. The `SetPathTargets`
    /// driver command converts (divides by 8) at that boundary; nothing
    /// upstream of it (the MP optimizer, `MpPathPolicy` pause/prefer, this
    /// struct itself) should ever be handed a bytes/sec value.
    pub(crate) rate: Option<u64>,
    /// A usable path the optimizer did not select: TQUIC sends data on it
    /// only when no selected path is left (`Connection::set_path_standby`).
    pub(crate) standby: bool,
}

/// `MpPathTarget.rate` (bits/sec) -> TQUIC's `set_path_target_rate`/
/// `scheduler_target_rate` (bytes/sec). See `MpPathTarget::rate`'s doc for
/// why this boundary, specifically, is where the conversion belongs.
fn bits_per_sec_to_bytes_per_sec(bits_per_sec: u64) -> u64 {
    bits_per_sec / 8
}

/// The inverse of `bits_per_sec_to_bytes_per_sec`, for the read-back side of
/// the same boundary: `tquic::PathStats::scheduler_target_rate` is bytes/sec
/// (set via `set_path_target_rate` above), but `MpPathTelemetry::
/// scheduler_target_rate_bps` -- like every other `_bps` field ET reports --
/// is bits/sec. MP_SQM_PLAN.md S2.4 review: this conversion was missing,
/// so every reader of `scheduler_target_rate_bps` (the GUI's per-path target
/// rate, `MpPathRuntimeSnapshot::target_rate_bps`'s telemetry fallback) saw
/// a value 8x too small.
fn bytes_per_sec_to_bits_per_sec(bytes_per_sec: u64) -> u64 {
    bytes_per_sec.saturating_mul(8)
}

/// Keep rate updates scoped to paths that still exist in the TQUIC connection.
///
/// Path removal and control ticks are intentionally asynchronous. A target that
/// was valid while the optimizer selected it may be retired before the driver
/// processes its update; it must not make updates for the remaining paths fail.
fn registered_path_targets<F>(targets: Vec<MpPathTarget>, mut is_registered: F) -> Vec<MpPathTarget>
where
    F: FnMut(SocketAddr, SocketAddr) -> bool,
{
    targets
        .into_iter()
        .filter(|target| is_registered(target.local_addr, target.remote_addr))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MpPathEvent {
    Down(PathKey),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MpPathTelemetry {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) validation_state: tquic::PathState,
    pub(crate) bandwidth_model_valid: bool,
    /// `tquic::PathStats::btlbw` and `latest_delivery_rate`, converted from
    /// the bytes/sec TQUIC's bandwidth model uses to bits/sec: the optimizer
    /// weighs them against egress budgets as `capacity_bps`.
    pub(crate) btlbw: u64,
    pub(crate) delivery_rate: u64,
    pub(crate) app_limited: bool,
    pub(crate) sample_age_micros: Option<u64>,
    pub(crate) congestion_control_state: tquic::CongestionControlState,
    /// `tquic::PathStats::scheduler_target_rate`, converted from the
    /// wire-bytes/sec TQUIC stores it in (same convention as `pacing_rate`
    /// below) to the bits/sec convention every other `_bps` field in this
    /// codebase uses. MP_SQM_PLAN.md S2.4 review: this used to be a raw
    /// passthrough of the bytes/sec value, reported as bits/sec 8x too low
    /// everywhere it was read (`MpPathStatus.target_rate_bps` in the GUI,
    /// `MpPathRuntimeSnapshot::target_rate_bps`'s telemetry fallback).
    pub(crate) scheduler_target_rate_bps: Option<u64>,
    pub(crate) min_rtt_micros: u64,
    /// `tquic::PathStats::windowed_min_rtt`: the smallest RTT sample of the
    /// last 300 s, the path's propagation delay (S-I4).
    pub(crate) windowed_min_rtt_micros: u64,
    /// The path's PTOs keep firing (`tquic::PATH_BACKOFF_PTO_COUNT` in a row),
    /// so TQUIC's scheduler passes it over and hands its in-flight data to the
    /// other paths.
    pub(crate) backed_off: bool,
    pub(crate) srtt_micros: u64,
    pub(crate) sent_bytes: u64,
    pub(crate) recv_bytes: u64,
    /// `tquic::PathStats::lost_data_bytes`: lost PMTU probes are not path loss.
    pub(crate) lost_bytes: u64,
    /// `tquic::PathStats::acked_bytes`, whatever the congestion control.
    pub(crate) acked_bytes: u64,
    /// High-water mark of `Recovery::bytes_in_flight` for this path
    /// (`tquic::PathStats::max_inflight`). Distinct from `sent_bytes`: TQUIC
    /// marks a packet in-flight at generation time (`conn.send()`), before
    /// `on_packets_send`/`on_packets_send_sparse` ever run, so this can grow
    /// even while the governor is holding every one of those packets back.
    /// It is the only signal that discriminates "generated ahead of the
    /// governor, then queued" from "generated at the governor's own pace" --
    /// wire-rate/srtt alone do not, since the governor still paces what
    /// actually reaches the wire either way. MP_SQM_PLAN.md S2.2 reports this
    /// as `MpPathStatus.bytes_in_flight` -- TQUIC's `PathStats` has no
    /// separate *current* in-flight gauge, only this high-water mark, so it
    /// is the closest real (non-fabricated) value available.
    pub(crate) max_inflight_bytes: u64,
    /// `tquic::PathStats::final_cwnd` (MP_SQM_PLAN.md S2.2's `MpPathStatus.
    /// cwnd_bytes`). Despite the "final" in its TQUIC-side name, it is
    /// continuously updated by `Recovery`'s own congestion-control loop, not
    /// only written once at connection close -- reading it here mid-session
    /// (like `sent_bytes`/`srtt_micros` above) yields the live value.
    pub(crate) cwnd_bytes: u64,
    /// `tquic::PathStats::pacing_rate`, converted from the wire-bytes/sec
    /// TQUIC stores it in (see `connection/recovery.rs`'s own `* 8` at its
    /// qlog call site) to the bits/sec convention every other `*_bps` field
    /// in this codebase uses. MP_SQM_PLAN.md S2.2's `MpPathStatus.
    /// pacing_rate_bps`.
    pub(crate) pacing_rate_bps: u64,
    /// `tquic::PathStats::observed_local_addr`: the endpoint the peer reports
    /// seeing for this path (OBSERVED_ADDRESS frame), `None` until reported or
    /// when the peer does not support address discovery.
    pub(crate) observed_local_addr: Option<SocketAddr>,
}

fn path_telemetry_from_stats(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    validation_state: tquic::PathState,
    stats: &tquic::PathStats,
) -> MpPathTelemetry {
    MpPathTelemetry {
        local_addr,
        remote_addr,
        validation_state,
        bandwidth_model_valid: stats.bandwidth_model_valid,
        btlbw: bytes_per_sec_to_bits_per_sec(stats.btlbw),
        delivery_rate: bytes_per_sec_to_bits_per_sec(stats.latest_delivery_rate),
        app_limited: stats.delivery_rate_sample_app_limited,
        sample_age_micros: stats
            .delivery_rate_sample_time_valid
            .then_some(stats.delivery_rate_sample_age),
        congestion_control_state: stats.congestion_control_state,
        scheduler_target_rate_bps: stats
            .scheduler_target_rate_valid
            .then_some(bytes_per_sec_to_bits_per_sec(stats.scheduler_target_rate)),
        min_rtt_micros: stats.min_rtt,
        windowed_min_rtt_micros: stats.windowed_min_rtt,
        backed_off: stats.pto_count >= tquic::PATH_BACKOFF_PTO_COUNT as u64,
        srtt_micros: stats.srtt,
        sent_bytes: stats.sent_bytes,
        recv_bytes: stats.recv_bytes,
        lost_bytes: stats.lost_data_bytes,
        acked_bytes: stats.acked_bytes,
        max_inflight_bytes: stats.max_inflight,
        cwnd_bytes: stats.final_cwnd,
        pacing_rate_bps: stats.pacing_rate.saturating_mul(8),
        observed_local_addr: stats.observed_local_addr,
    }
}

// `pub`, not `pub(crate)`: this is returned from `Tunnel::mp_session_handle`
// (a `pub` trait method) and `PeerConn::take_mp_session_handle` (a `pub`
// fn) -- MP_SQM_PLAN.md S1.4. Its methods below stay `pub(crate)`; only the
// type name itself needs to be nameable at those call sites' visibility.
#[derive(Clone)]
pub struct MpSessionHandle {
    commands: mpsc::UnboundedSender<DriverCommand>,
}

impl MpSessionHandle {
    #[cfg(test)]
    pub(crate) fn closed_for_test() -> Self {
        let (commands, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        Self { commands }
    }

    /// A live handle whose driver refuses every `remove_path` for being the
    /// session's last open path ([`LAST_OPEN_PATH`]) and ignores the rest.
    #[cfg(test)]
    pub(crate) fn refusing_remove_path_for_test() -> Self {
        let (commands, mut receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                if let DriverCommand::RemovePath { result, .. } = command {
                    let _ = result.send(Err(LAST_OPEN_PATH.into()));
                }
            }
        });
        Self { commands }
    }

    /// A live handle whose commands are never answered while the returned
    /// guard (the driver's receiving end) is kept alive.
    #[cfg(test)]
    pub(crate) fn unanswered_for_test() -> (Self, Box<dyn std::any::Any + Send>) {
        let (commands, receiver) = mpsc::unbounded_channel();
        (Self { commands }, Box::new(receiver))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.commands.is_closed()
    }

    pub(crate) fn same_session(&self, other: &Self) -> bool {
        self.commands.same_channel(&other.commands)
    }

    pub(crate) fn shutdown(&self) {
        // Peer removal is authoritative.  There is no response to wait for:
        // once queued, the driver exits and all of its carrier receive tasks
        // are dropped with it.
        let _ = self.commands.send(DriverCommand::Shutdown);
    }

    /// MP_SQM_PLAN.md S2.5: fire-and-forget, like `shutdown` -- see
    /// `DriverCommand::PublishAutorateSample`'s doc comment for why this has
    /// no response to wait for either. Returns whether the send succeeded so
    /// `spawn_standalone_autorate_sampler`'s periodic caller knows to stop
    /// once the driver is gone, instead of ticking forever into a closed
    /// channel.
    pub(crate) fn request_autorate_sample(&self) -> bool {
        self.commands.send(DriverCommand::PublishAutorateSample).is_ok()
    }

    /// Fails with [`NO_FREE_PATH_SLOT`] (see [`is_no_free_path_slot`]) when
    /// the connection has no free connection ID or path slot: the caller
    /// opens the path again later (iroh `open_path_on_conn`).
    pub(crate) async fn add_path(
        &self,
        path: Arc<dyn MpDatagramPath>,
        remote: SocketAddr,
        nic_scope: Option<EgressScope>,
    ) -> Result<(), TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::AddPath {
                path,
                remote,
                nic_scope,
                result,
            })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx
            .await
            .map_err(|_| {
                TunnelError::InternalError("mpquic driver dropped add-path result".into())
            })?
            .map_err(TunnelError::InternalError)
    }

    pub(crate) async fn path_telemetry(&self) -> Result<Vec<MpPathTelemetry>, TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::SnapshotPaths { result })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx
            .await
            .map_err(|_| {
                TunnelError::InternalError("mpquic driver dropped telemetry result".into())
            })?
            .map_err(TunnelError::InternalError)
    }

    pub(crate) async fn set_path_targets(
        &self,
        targets: Vec<MpPathTarget>,
    ) -> Result<(), TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::SetPathTargets { targets, result })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx
            .await
            .map_err(|_| {
                TunnelError::InternalError("mpquic driver dropped path-target result".into())
            })?
            .map_err(TunnelError::InternalError)
    }

    pub(crate) async fn remove_path(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::RemovePath {
                local_addr,
                remote_addr,
                result,
            })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx
            .await
            .map_err(|_| {
                TunnelError::InternalError("mpquic driver dropped remove-path result".into())
            })?
            .map_err(TunnelError::InternalError)
    }

    pub(crate) async fn set_scheduler(
        &self,
        runtime: MpQuicSessionConfig,
    ) -> Result<(), TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::SetScheduler { runtime, result })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx
            .await
            .map_err(|_| {
                TunnelError::InternalError("mpquic driver dropped scheduler result".into())
            })?
            .map_err(TunnelError::InternalError)
    }

    pub(crate) fn set_data_plane(&self, policy: Arc<DataPlanePolicy>, peer_caps: Option<u32>) -> bool {
        self.commands
            .send(DriverCommand::SetDataPlane { policy, peer_caps })
            .is_ok()
    }

    pub(crate) async fn data_plane_status(&self) -> Result<MpDataPlaneStatus, TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::SnapshotDataPlane { result })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx.await.map_err(|_| {
            TunnelError::InternalError("mpquic driver dropped data-plane result".into())
        })
    }

    pub(crate) async fn take_path_events(&self) -> Result<Vec<MpPathEvent>, TunnelError> {
        let (result, result_rx) = oneshot::channel();
        self.commands
            .send(DriverCommand::TakePathEvents { result })
            .map_err(|_| TunnelError::InternalError("mpquic driver is closed".into()))?;
        result_rx.await.map_err(|_| {
            TunnelError::InternalError("mpquic driver dropped path-event result".into())
        })
    }
}

fn driver_command_channel() -> (MpSessionHandle, mpsc::UnboundedReceiver<DriverCommand>) {
    let (commands, command_rx) = mpsc::unbounded_channel();
    (MpSessionHandle { commands }, command_rx)
}

#[derive(Default)]
struct DriverState {
    events: VecDeque<DrvEvent>,
}

struct Handler {
    state: Rc<std::cell::RefCell<DriverState>>,
}

impl Handler {
    fn push(&self, ev: DrvEvent) {
        self.state.borrow_mut().events.push_back(ev);
    }
}

impl tquic::TransportHandler for Handler {
    fn on_conn_created(&mut self, _conn: &mut tquic::Connection) {}

    fn on_conn_established(&mut self, conn: &mut tquic::Connection) {
        if let Some(idx) = conn.index() {
            self.push(DrvEvent::Established(idx));
        }
    }

    fn on_conn_closed(&mut self, conn: &mut tquic::Connection) {
        // Why it ended: idle timeout, stateless reset, or the error either side
        // closed with. Logged here: the endpoint drops the connection right after.
        tracing::info!(
            target: "mpq",
            trace_id = conn.trace_id(),
            idle_timeout = conn.is_idle_timeout(),
            reset = conn.is_reset(),
            handshake_timeout = conn.is_handshake_timeout(),
            local_error = ?conn.local_error(),
            peer_error = ?conn.peer_error(),
            "mpquic connection closed"
        );
        if let Some(idx) = conn.index() {
            self.push(DrvEvent::Closed(idx));
        }
    }

    fn on_stream_created(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(idx) = conn.index() {
            self.push(DrvEvent::StreamCreated(idx, stream_id));
        }
    }

    fn on_stream_readable(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(idx) = conn.index() {
            self.push(DrvEvent::Readable(idx, stream_id));
        }
    }

    fn on_stream_writable(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {}

    fn on_stream_closed(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        if let Some(idx) = conn.index() {
            self.push(DrvEvent::StreamClosed(idx, stream_id));
        }
    }

    fn on_new_token(&mut self, _conn: &mut tquic::Connection, _token: Vec<u8>) {}
}

// ---------------------------------------------------------------------------
// Driver: pumps one QUIC connection between UDP sockets and a duplex pipe
// ---------------------------------------------------------------------------

/// Inputs needed to drive one connection on the dedicated thread.
struct DriverCfg {
    is_server: bool,
    /// Carrier-agnostic datagram paths. The first is the primary QUIC path.
    paths: Vec<MpPathInput>,
    remote: SocketAddr,
    /// The driver end of the ET<->QUIC pipe.
    pipe: tokio::io::DuplexStream,
    /// Signalled once the stream is ready (client) or a connection arrives
    /// (server); carries the peer address used by the initial QUIC path.
    ready: oneshot::Sender<Result<SocketAddr, String>>,
    commands: mpsc::UnboundedReceiver<DriverCommand>,
    runtime: MpQuicSessionConfig,
    /// MP_SQM_PLAN.md §4.4 (b): every carrier `drive()` registers is governed
    /// against this manager's ledgers -- see `governed_sender` module doc for
    /// which callers share the process's real manager (`connector::mp_session`)
    /// versus a private, per-driver one (`MpQuicTunnelConnector`/`MpQuicTunnelListener`).
    egress_quality: Arc<EgressQualityManager>,
    /// MP_SQM_PLAN.md S1.3 (remainder): the connector already knows `remote`
    /// before spawning the driver, so it resolves this via
    /// `EgressInventory::best_route_to` up front and passes the result here
    /// for the *first* path only (`paths[0]`) -- `None` for the manual
    /// multi-NIC case (`bind_devs`/`ET_MPQUIC_DEVS`) and always `None` for a
    /// listener, which does not know its peer yet at spawn time.
    initial_resolved_scope: Option<EgressScope>,
    /// MP_SQM_PLAN.md S1.3 (remainder): a listener has no remote to resolve
    /// against at spawn time, so it instead carries this handle in so
    /// `drive()` itself can resolve one once it learns the real peer address
    /// from the first inbound datagram (see the `is_server &&
    /// peer_remote.is_none()` branch) and rescope its primary path. `None`
    /// for the connector, which already resolved (or gave up trying to)
    /// before spawning.
    egress_inventory: Option<EgressInventory>,
    /// MP_SQM_PLAN.md S2.10: `Some` exactly when `runtime.data_plane`; the
    /// ET end of `pipe` then carries class tags (`MpPipeZCPacketToBytes`).
    data_plane: Option<Arc<DataPlanePolicy>>,
}

fn spawn_driver(cfg: DriverCfg) {
    std::thread::Builder::new()
        .name("mpquic-driver".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = cfg.ready.send(Err(format!("runtime: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = drive(cfg).await {
                    tracing::warn!(?e, "mpquic driver exited with error");
                }
            });
        })
        .expect("spawn mpquic driver thread");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathReceiverEvent {
    Failed(CarrierId),
}

/// An error a connected UDP socket reports because an ICMP error came back
/// for an earlier send (the peer's socket from a superseded punch attempt is
/// closed, a NAT or router refused one packet). It says nothing about the
/// path; QUIC's own loss detection and idle timeout decide whether the path
/// is alive, as quinn does.
fn is_icmp_error(error: &std::io::Error) -> bool {
    // With DF set, an oversized DPLPMTUD probe or an ICMP frag-needed comes
    // back as EMSGSIZE; the loss is what shrinks the path MTU.
    #[cfg(unix)]
    if error.raw_os_error() == Some(nix::libc::EMSGSIZE) {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(10040) {
        // WSAEMSGSIZE
        return true;
    }
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
    )
}

/// A send error that says the carrier can never send again: its NIC or
/// local address is gone.
fn is_carrier_gone_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    if error.raw_os_error() == Some(nix::libc::ENODEV) {
        return true;
    }
    matches!(
        error.kind(),
        std::io::ErrorKind::NetworkDown | std::io::ErrorKind::AddrNotAvailable
    )
}

/// One receive event, stamped before it can wait in the driver's channel.
/// TQUIC's PacketInfo::time is arrival time, not when the driver drains it.
struct ReceivedDatagram {
    payload: Vec<u8>,
    info: tquic::PacketInfo,
}

fn spawn_path_receiver(
    path: Arc<dyn MpDatagramPath>,
    tx: mpsc::Sender<ReceivedDatagram>,
    event_tx: mpsc::UnboundedSender<PathReceiverEvent>,
) -> tokio::task::JoinHandle<()> {
    let local_addr = path.local_addr();
    let carrier_id = carrier_id(&path);
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            match path.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let received = ReceivedDatagram {
                        payload: buf[..n].to_vec(),
                        info: tquic::PacketInfo {
                            src: from,
                            dst: local_addr,
                            time: Instant::now(),
                            recv_timestamp: owd::owd_clock_us(),
                            send_meta: tquic::PacketSendMeta::default(),
                        },
                    };
                    if tx
                        .send(received)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if is_icmp_error(&error) => {
                    tracing::debug!(?error, ?local_addr, "MP path receiver: ICMP error ignored");
                }
                Err(error) => {
                    tracing::warn!(?error, ?local_addr, "MP path receiver failed");
                    let _ = event_tx.send(PathReceiverEvent::Failed(carrier_id));
                    break;
                }
            }
        }
    })
}

async fn drive(cfg: DriverCfg) -> anyhow::Result<()> {
    let DriverCfg {
        is_server,
        paths,
        remote,
        pipe,
        ready,
        mut commands,
        runtime,
        egress_quality,
        mut initial_resolved_scope,
        egress_inventory,
        data_plane,
    } = cfg;

    // Activate each carrier inside this driver's Tokio runtime. Every path is
    // shared between the synchronous TQUIC sender callback and one recv task.
    let paths = paths
        .into_iter()
        .map(MpPathInput::activate)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut path_specs = Vec::with_capacity(paths.len());
    let (dgram_tx, mut dgram_rx) = mpsc::channel::<ReceivedDatagram>(1024);
    let mut incoming_batch = Vec::with_capacity(MAX_RECEIVE_BATCH);
    let (path_event_tx, mut path_event_rx) = mpsc::unbounded_channel();
    let mut pending_path_events = VecDeque::new();
    let mut registry = MpPathRegistry::new(egress_quality);
    let mut recv_tasks = HashMap::new();
    // MP_SQM_PLAN.md S1.3 (remainder): retained so a server driver can
    // rescope its primary path once it learns the real peer address (see
    // the `is_server && peer_remote.is_none()` branch below) --
    // `GovernedCarrier` deliberately exposes no way to get the raw carrier
    // back out once registered, so the only clone of it is the one taken
    // here, before that happens.
    let mut path_by_local: HashMap<SocketAddr, Arc<dyn MpDatagramPath>> = HashMap::new();
    for (path, nic_scope) in paths {
        // Only the first path gets the connector's up-front resolution
        // (MP_SQM_PLAN.md S1.3 remainder): `take()` so any further path in
        // the manual multi-NIC case falls back to `EgressStableId::Fallback`,
        // exactly as it did before this remainder landed.
        let resolved_route = initial_resolved_scope.take();
        let key = registry
            .register(path.clone(), remote, nic_scope, resolved_route)
            .map_err(anyhow::Error::msg)?;
        path_by_local.insert(key.local_addr, path.clone());
        recv_tasks
            .entry(key.carrier_id)
            .or_insert_with(|| spawn_path_receiver(path, dgram_tx.clone(), path_event_tx.clone()));
        path_specs.push((key.local_addr, key.remote_addr));
    }
    let primary_local = path_specs
        .first()
        .map(|(local, _)| *local)
        .ok_or_else(|| anyhow::anyhow!("mpquic driver requires at least one path"))?;
    tracing::info!(
        target: "mpq",
        is_server,
        ?primary_local,
        ?remote,
        npaths = path_specs.len(),
        congestion_control = runtime.congestion_control.as_str(),
        "mpquic drive(): start"
    );

    let state = Rc::new(std::cell::RefCell::new(DriverState::default()));
    let handler = Box::new(Handler {
        state: state.clone(),
    });
    let path_registry = Arc::new(RwLock::new(registry));
    // MP_SQM_PLAN.md §4.4 (b): a `Blocked { retry_at }` outcome from
    // `DatagramSender::on_packets_send` arms this instead of being silently
    // dropped -- see the loop's `sleep` computation below, which takes
    // `min(endpoint.timeout(), next_wake)` so the driver wakes in time to
    // retry a governed send that TQUIC's own timers know nothing about.
    // `Rc<Cell<_>>`, not `Arc`/atomics: this whole driver is single-threaded
    // by construction (TQUIC's `Endpoint` itself holds `Rc`s and is `!Send`).
    let next_wake: Rc<std::cell::Cell<Option<Instant>>> = Rc::new(std::cell::Cell::new(None));
    // OWD_AUTORATE_PLAN.md 1.1: the data plane's one-way delay probes; the
    // sender marks the packets that carry them.
    let owd_probes = Arc::new(owd::OwdProbes::new());
    let mut sender = DatagramSender::new(
        path_registry.clone(),
        next_wake.clone(),
        path_event_tx.clone(),
    );
    if data_plane.is_some() {
        sender = sender.with_probes(owd_probes.clone());
    }
    let sender = Rc::new(sender);
    let send_handler: Rc<dyn tquic::PacketSendHandler> = sender.clone();

    let config = if is_server {
        server_config(runtime)?
    } else {
        client_config(runtime)?
    };
    let mut endpoint = tquic::Endpoint::new(Box::new(config), is_server, handler, send_handler);

    // Client kicks off the connection and registers the extra paths.
    let mut conn_index: Option<u64> = None;
    if !is_server {
        let idx = endpoint
            .connect(primary_local, remote, Some("localhost"), None, None, None)
            .context("mpquic connect")?;
        tracing::info!(target: "mpq", idx, "mpquic drive(): client connect() issued");
        conn_index = Some(idx);
        endpoint.process_connections().ok();
    }

    let (mut pipe_rd, mut pipe_wr) = tokio::io::split(pipe);
    let mut stream_id: Option<u64> = None;
    let mut ready = Some(ready);
    // The client already knows its configured peer. The server learns the
    // initial path's peer from the first inbound UDP datagram, before TQUIC
    // surfaces Established/StreamCreated.
    let mut peer_remote = (!is_server).then_some(remote);
    let mut app_out = vec![0u8; STREAM_CHUNK];
    let mut stream_read_buf = vec![0u8; STREAM_CHUNK];
    // Application backpressure belongs to this delivery buffer. Its partial
    // write competes with receive, timers and commands in the event loop.
    let mut app_in = Bytes::new();
    let mut inbound_more = false;
    let mut inbound_finished = false;
    // Bytes read from the pipe but not yet accepted by QUIC flow control.
    let mut pending: Option<Bytes> = None;
    // What the stream queues dropped, as far as the egress's card has it.
    let mut reported_stream_drops = stream_queue::StreamDrops::default();
    // MP_SQM_PLAN.md S2.10: `None` keeps the single-stream pump below as it
    // always was; `Some` routes whole frames per class instead.
    let mut dp = data_plane.map(|policy| {
        DataPlaneDriver::new(
            policy,
            Instant::now(),
            owd_probes.clone(),
        )
    });

    // SQM on and no data plane: the single stream's frames wait per inner
    // flow in an unlimited-rate CAKE (`fair_pipe`), not in pipe order.
    let mut fair = if dp.is_none() && runtime.sqm_enabled {
        let aqm = stream_queue::StreamAqm {
            rate_bytes_per_sec: 0,
            mtu: 1500,
            target: std::time::Duration::from_millis(5),
            interval: std::time::Duration::from_millis(100),
        };
        Some(fair_pipe::FairPipe::new(&aqm, Instant::now()).map_err(anyhow::Error::msg)?)
    } else {
        None
    };

    // Per-path telemetry ("HUD"): sample each path's BBR-derived stats on a
    // fixed cadence so the multipath scheduler's cross-path aggregation is
    // observable. Gated behind ET_MPQUIC_HUD so normal runs stay quiet.
    let hud_enabled = std::env::var_os("ET_MPQUIC_HUD").is_some();
    let hud_interval = std::time::Duration::from_secs(1);
    let mut hud_tick = tokio::time::interval(hud_interval);
    hud_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut hud_last_sent: HashMap<SocketAddr, u64> = HashMap::new();

    // MP_SQM_PLAN.md S2.5: standalone-session autorate sampling state.
    // Deliberately NOT a `tokio::time::interval`/`select!` branch of its own
    // -- see `DriverCommand::PublishAutorateSample`'s doc comment for why a
    // dedicated timer branch here measurably starved Brutal's packet pacing
    // in a real loopback goodput test. The cadence lives in an external task
    // (spawned by `MpQuicTunnelConnector::connect()`/`MpQuicTunnelListener::
    // accept()`) that sends this command through the existing `commands`
    // channel instead; `autorate_last_tick` records real elapsed time between
    // whatever cadence that task actually achieves (not an assumed fixed
    // interval), same spirit as `connector::mp_session`'s `EgressSampleState`.
    let mut autorate_last_bytes: HashMap<SocketAddr, u64> = HashMap::new();
    let mut autorate_last_tick = Instant::now();
    // Checked at the end of each loop turn, no timer branch of its own (see
    // the autorate note above).
    let mut keepalive_last_sent = HashMap::new();
    // Which TQUIC path each path spec stands for, see `specs_to_retire_for_events`.
    let mut bound_paths = BoundPaths::new();
    let mut keepalive_next = Instant::now() + PATH_KEEPALIVE_INTERVAL;
    // The last path failed and QUIC keeps the connection: it waits for a
    // replacement until this deadline, then closes with NO_VIABLE_PATH. The
    // failed paths are abandoned once a replacement has validated.
    let mut no_viable_path_at: Option<Instant> = None;
    let mut failed_last_paths: Vec<(SocketAddr, SocketAddr)> = Vec::new();
    // Preserve CAKE/QUIC deadlines on every backend. The Windows waitable
    // timer is registered through the existing async-io reactor as well.
    let mut transport_timer = transport_timer::TransportTimer::new()?;

    loop {
        if inbound_finished && app_in.is_empty() {
            pipe_wr.shutdown().await?;
            return Ok(());
        }
        let now = Instant::now();
        let timeout = endpoint.timeout().map(|duration| now + duration);
        // `take()`: this wake is consumed for exactly one sleep computation.
        // If the governed send that armed it is retried again this same
        // iteration (via `endpoint.process_connections()` below) and blocks
        // again, `on_packets_send` re-arms `next_wake` before the next time
        // this line runs -- so a wake is never silently lost, only ever
        // recomputed fresh. `on_timeout()` firing early off a stale wake is
        // a documented safe no-op (MP_SQM_PLAN.md §4.4 (b) design note), so
        // there is no correctness cost to consuming it eagerly here.
        let wake = next_wake.take();
        let deadline = match (timeout, wake) {
            (Some(t), Some(w)) => Some(t.min(w)),
            (Some(t), None) => Some(t),
            (None, Some(w)) => Some(w),
            (None, None) => None,
        };
        transport_timer.set_deadline(deadline)?;

        // Only pull from the pipe when we already have a stream and no backlog.
        // The data plane needs no stream to start: it pulls once the session
        // is ready. Its stream queues never stop the pull (COBALT drops from
        // them, `stream_queue`), so a datagram class does not wait behind them.
        let can_pull = match &dp {
            Some(_) => conn_index.is_some() && ready.is_none(),
            // The fair queue takes whatever the pipe has: its own memory limit
            // and COBALT bound the backlog, not the pipe.
            None if fair.is_some() => stream_id.is_some(),
            None => {
                stream_id.is_some()
                    && pending.is_none()
                    && (!runtime.sqm_enabled
                        || stream_unsent_bytes(&mut endpoint, conn_index, stream_id)
                            < SQM_STREAM_NOTSENT_LOWAT)
            }
        };

        tokio::select! {
            // `write` is cancellation safe: only its completed byte count
            // advances this buffer. Never await a whole application delivery
            // outside select, where a stalled reader would stop the engine.
            written = pipe_wr.write(&app_in), if !app_in.is_empty() => {
                let written = written?;
                if written == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                app_in = app_in.slice(written..);
            }
            // A bounded application read left work in QUIC. Revisit it after
            // delivery even if no new UDP packet or timer arrives.
            _ = std::future::ready(()), if inbound_more && app_in.is_empty() => {
                inbound_more = false;
            }
            // A relay path can remain continuously readable while QUIC is
            // acknowledging or recovering packets. Do not bias it ahead of
            // the EasyTier application pipe: that can indefinitely delay
            // peer ping/pong replies and make EasyTier correctly retire an
            // otherwise live MP connection. Tokio's unbiased selection keeps
            // the transport pump and both application directions making
            // progress under sustained ingress.

            // Periodic per-path telemetry sampling (client side, multipath).
            _ = hud_tick.tick(), if hud_enabled => {
                if let Some(ci) = conn_index {
                    dump_path_stats(
                        &mut endpoint,
                        ci,
                        &path_specs,
                        &mut hud_last_sent,
                        hud_interval.as_secs_f64(),
                    );
                }
            }

            // Process one bounded batch before advancing connections and
            // application I/O; timers and commands participate again next turn.
            received = dgram_rx.recv_many(&mut incoming_batch, MAX_RECEIVE_BATCH) => {
                if received == 0 {
                    break;
                }
                for ReceivedDatagram { payload: mut buf, info } in incoming_batch.drain(..) {
                    let from = info.src;
                    let local_dst = info.dst;
                    if is_server && peer_remote.is_none() {
                        peer_remote = Some(from);
                        if let Some((_, initial_remote)) = path_specs.iter_mut().find(|(_, remote)| {
                            remote.ip().is_unspecified() && remote.port() == 0
                        }) {
                            *initial_remote = from;
                        }
                        // MP_SQM_PLAN.md S1.3 (remainder): this is the first
                        // moment a server driver knows its real peer address, so
                        // it is also the first moment it can resolve a real
                        // EgressScope via `EgressInventory::best_route_to` for
                        // its reply direction -- accounting only, the carrier's
                        // socket stays exactly where `listen()` bound it. A
                        // resolution failure (no inventory yet, no route) simply
                        // leaves this carrier on the `EgressStableId::Fallback`
                        // scope it was registered with above.
                        if let Some(inventory) = &egress_inventory
                            && let Some(path) = path_by_local.get(&local_dst)
                            && let Some(scope) =
                                resolve_egress_scope(inventory, from, EgressDirection::Egress).await
                        {
                            path_registry
                                .write()
                                .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
                                .rescope(local_dst, path.clone(), scope);
                        }
                    }
                    tracing::debug!(target: "mpq", is_server, ?from, ?local_dst, n = buf.len(), "mpquic rx dgram");
                    if let Err(e) = endpoint.recv(&mut buf, &info) {
                        tracing::debug!(target: "mpq", is_server, ?e, "mpquic endpoint.recv error");
                    }
                }
            }

            Some(PathReceiverEvent::Failed(carrier_id)) = path_event_rx.recv() => {
                let removed = path_registry
                    .write()
                    .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
                    .take_carrier_paths(carrier_id);
                if removed.is_empty() {
                    continue;
                }
                let removed_specs: Vec<_> = removed
                    .iter()
                    .map(|key| (key.local_addr, key.remote_addr))
                    .collect();
                if let Some(ci) = conn_index
                    && let Some(conn) = endpoint.conn_get_mut(ci)
                {
                    if failure_takes_last_path(&path_specs, &removed_specs) {
                        // QUIC decides whether the connection lives, not this
                        // path's socket: keep the path in TQUIC, report it
                        // down so a replacement is requested, and close only
                        // if none validates within the grace period.
                        let mut srtt = 0;
                        for &(local, remote) in &removed_specs {
                            if let Ok(stats) = conn.get_path_stats(local, remote) {
                                srtt = srtt.max(stats.srtt);
                            }
                        }
                        let deadline = Instant::now() + last_path_grace(srtt);
                        no_viable_path_at.get_or_insert(deadline);
                        failed_last_paths.extend(removed_specs.iter().copied());
                        tracing::warn!(target: "mpq", is_server, paths = ?removed_specs,
                            "mpquic last path failed, waiting for a replacement");
                    } else {
                        for key in &removed {
                            if let Err(error) = conn.abandon_path(key.local_addr, key.remote_addr) {
                                tracing::debug!(?error, ?key, "failed to abandon broken MP path");
                            }
                        }
                    }
                }
                path_specs.retain(|spec| {
                    !removed.iter().any(|key| *spec == (key.local_addr, key.remote_addr))
                });
                recv_tasks.remove(&carrier_id);
                pending_path_events.extend(removed.into_iter().map(MpPathEvent::Down));
            }

            Some(command) = commands.recv() => {
                match command {
                    DriverCommand::Shutdown => {
                        tracing::info!(
                            target: "mpq",
                            is_server,
                            ?conn_index,
                            ?stream_id,
                            paths = ?path_specs,
                            "mpquic driver exit: EasyTier peer removed"
                        );
                        break;
                    }
                    DriverCommand::AddPath { path, remote: path_remote, nic_scope, result } => {
                        // Both ends punch the same 4-tuple, so the offer that
                        // lost the session race brings this session's own path
                        // back. It is already here: reporting it as a failure
                        // would get it pruned, i.e. abandoned on both ends.
                        if path_specs.contains(&(path.local_addr(), path_remote)) {
                            let _ = result.send(Ok(()));
                            continue;
                        }
                        let key = match path_registry
                            .write()
                            .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
                            .register(path.clone(), path_remote, nic_scope, None)
                        {
                            Ok(key) => key,
                            Err(error) => {
                                let _ = result.send(Err(error));
                                continue;
                            }
                        };
                        recv_tasks
                            .entry(key.carrier_id)
                            .or_insert_with(|| {
                                spawn_path_receiver(path, dgram_tx.clone(), path_event_tx.clone())
                            });
                        path_specs.push((key.local_addr, key.remote_addr));
                        // A new mount: the events of an earlier one on this 4-tuple are not its.
                        bound_paths.remove(&(key.local_addr, key.remote_addr));

                        let add_result = if !is_server {
                            if let Some(ci) = conn_index
                                && let Some(conn) = endpoint.conn_get_mut(ci)
                            {
                                match conn.add_path(key.local_addr, key.remote_addr) {
                                    Ok(_) => Ok(()),
                                    // `Done` for a 4-tuple it has open already;
                                    // otherwise for no free path slot or
                                    // connection ID (the connection holds at most
                                    // as many paths as the peer gave connection
                                    // IDs; an abandoned path's are back once it
                                    // drained) -- the caller retries later.
                                    Err(tquic::Error::Done)
                                        if conn
                                            .get_path(key.local_addr, key.remote_addr)
                                            .is_ok_and(|path| !path.is_abandoned()) =>
                                    {
                                        Ok(())
                                    }
                                    Err(tquic::Error::Done) => Err(NO_FREE_PATH_SLOT.into()),
                                    Err(error) => Err(format!("mpquic add_path failed: {error}")),
                                }
                            } else {
                                Err("mpquic connection is not ready".into())
                            }
                        } else {
                            // The client initiates PATH_CHALLENGE. The server only
                            // needs the matching carrier registered before it
                            // arrives; a 4-tuple it abandoned earlier is a new
                            // QUIC path once the client's packets on it arrive.
                            Ok(())
                        };

                        if add_result.is_err() {
                            path_specs.retain(|spec| *spec != (key.local_addr, key.remote_addr));
                            unregister_path(key, &path_registry, &mut recv_tasks)?;
                        }
                        let _ = result.send(add_result);
                    }
                    DriverCommand::SnapshotPaths { result } => {
                        let snapshot = if let Some(ci) = conn_index
                            && let Some(conn) = endpoint.conn_get_mut(ci)
                        {
                            let mut telemetry = Vec::with_capacity(path_specs.len());
                            for &(local, remote) in &path_specs {
                                let Ok(path) = conn.get_path(local, remote) else {
                                    continue;
                                };
                                let state = path.state();
                                let Ok(stats) = conn.get_path_stats(local, remote) else {
                                    continue;
                                };
                                telemetry.push(path_telemetry_from_stats(
                                    local, remote, state, stats,
                                ));
                            }
                            Ok(telemetry)
                        } else {
                            Err("mpquic connection is not ready".to_string())
                        };
                        let _ = result.send(snapshot);
                    }
                    DriverCommand::SetPathTargets { targets, result } => {
                        let update = if let Some(ci) = conn_index
                            && let Some(conn) = endpoint.conn_get_mut(ci)
                        {
                            let requested_count = targets.len();
                            let targets = registered_path_targets(targets, |local, remote| {
                                conn.get_path(local, remote).is_ok()
                            });
                            let skipped_count = requested_count.saturating_sub(targets.len());
                            if skipped_count > 0 {
                                tracing::debug!(
                                    skipped_count,
                                    requested_count,
                                    "skipped stale MP path target updates; the next control tick will reconcile"
                                );
                            }
                            targets
                                .iter()
                                .try_for_each(|target| {
                                    conn.set_path_target_rate(
                                        target.local_addr,
                                        target.remote_addr,
                                        // `MpPathTarget.rate` is bits/sec;
                                        // TQUIC's scheduler target rate (what
                                        // Brutal's `set_target_rate` reads) is
                                        // bytes/sec -- convert at this
                                        // boundary, not upstream.
                                        target.rate.map(bits_per_sec_to_bytes_per_sec),
                                    )?;
                                    conn.set_path_standby(
                                        target.local_addr,
                                        target.remote_addr,
                                        target.standby,
                                    )
                                })
                                .map_err(|error| {
                                    format!("mpquic set_path_target_rate failed: {error}")
                                })
                        } else {
                            Err("mpquic connection is not ready".into())
                        };
                        let _ = result.send(update);
                    }
                    DriverCommand::RemovePath {
                        local_addr,
                        remote_addr,
                        result,
                    } => {
                        let key = path_registry
                            .read()
                            .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
                            .key_for_addresses(local_addr, remote_addr);
                        let takes_last_path = conn_index
                            .and_then(|ci| endpoint.conn_get_mut(ci))
                            .is_some_and(|conn| {
                                removal_takes_last_usable_path(
                                    conn,
                                    &path_specs,
                                    (local_addr, remote_addr),
                                )
                            });
                        let removal = if key.is_some() && takes_last_path {
                            // noq `ClosePathError::LastOpenPath`: the last path
                            // stays whatever became of its first hop or socket.
                            // A session left without a path only idles (and
                            // spins the endpoint) until the peer or the idle
                            // timeout ends it, and cannot take the path back
                            // when the first hop returns.
                            Err(LAST_OPEN_PATH.to_owned())
                        } else if let Some(key) = key {
                            let abandon_result = if let Some(ci) = conn_index
                                && let Some(conn) = endpoint.conn_get_mut(ci)
                            {
                                conn.abandon_path(local_addr, remote_addr)
                                    .map_err(|error| {
                                        format!("mpquic abandon_path failed: {error}")
                                    })
                            } else {
                                Ok(())
                            };
                            path_specs.retain(|spec| *spec != (local_addr, remote_addr));
                            unregister_path(key, &path_registry, &mut recv_tasks)?;
                            abandon_result
                        } else {
                            Ok(())
                        };
                        let _ = result.send(removal);
                    }
                    DriverCommand::SetScheduler { runtime, result } => {
                        let update = if let Some(ci) = conn_index
                            && let Some(conn) = endpoint.conn_get_mut(ci)
                        {
                            conn.set_multipath_scheduler(mp_algorithm_to_tquic(runtime.algorithm))
                            .map_err(|error| {
                                format!("mpquic set_multipath_scheduler failed: {error}")
                            })
                        } else {
                            Err("mpquic connection is not ready".into())
                        };
                        let _ = result.send(update);
                    }
                    DriverCommand::TakePathEvents { result } => {
                        let _ = result.send(pending_path_events.drain(..).collect());
                    }
                    DriverCommand::SetDataPlane { policy, peer_caps } => {
                        if let Some(dp) = dp.as_mut() {
                            dp.set_policy(policy, peer_caps);
                        }
                    }
                    DriverCommand::SnapshotDataPlane { result } => {
                        let conn = conn_index.and_then(|ci| endpoint.conn_get_mut(ci));
                        let status = match (dp.as_mut(), conn) {
                            (Some(dp), Some(conn)) => {
                                dp.refresh(conn);
                                dp.status(Some(conn))
                            }
                            (Some(dp), None) => dp.status(None),
                            (None, _) => super::mp_dataplane::disabled_status(
                                "session built without the data plane; reconnect to enable",
                            ),
                        };
                        let _ = result.send(status);
                    }
                    DriverCommand::PublishAutorateSample => {
                        if let Some(ci) = conn_index {
                            let now = Instant::now();
                            let elapsed = now.saturating_duration_since(autorate_last_tick);
                            autorate_last_tick = now;
                            sample_standalone_autorate(
                                &mut endpoint,
                                ci,
                                &path_specs,
                                &path_registry,
                                &mut autorate_last_bytes,
                                elapsed,
                            );
                        }
                    }
                }
            }

            // ET wrote application bytes to be sent over QUIC.
            r = pipe_rd.read(&mut app_out), if can_pull => {
                let n = r?;
                if n == 0 {
                    // ET side closed: shut the stream and exit.
                    tracing::info!(
                        target: "mpq",
                        is_server,
                        ?conn_index,
                        ?stream_id,
                        paths = ?path_specs,
                        "mpquic driver exit: EasyTier application pipe closed"
                    );
                    if let Some(dp) = dp.as_mut() {
                        if let Some(ci) = conn_index
                            && let Some(conn) = endpoint.conn_get_mut(ci)
                        {
                            dp.close(conn);
                        }
                    } else if let (Some(ci), Some(sid)) = (conn_index, stream_id)
                        && let Some(conn) = endpoint.conn_get_mut(ci) {
                        let _ = conn.stream_write(sid, Bytes::new(), true);
                    }
                    endpoint.process_connections().ok();
                    break;
                }
                match (dp.as_mut(), fair.as_mut()) {
                    (Some(dp), _) => dp.push_outbound(&app_out[..n]),
                    (None, Some(fair)) => fair
                        .push(&app_out[..n], Instant::now())
                        .map_err(anyhow::Error::msg)?,
                    (None, None) => pending = Some(Bytes::copy_from_slice(&app_out[..n])),
                }
            }

            result = &mut transport_timer => {
                result?;
                endpoint.on_timeout(Instant::now());
                // A validated path that heard nothing for `PATH_IDLE_TIMEOUT` is dead
                // (the peer dropped it, or the route died without an error): retire
                // it here like a failed carrier. TQUIC already moved a silent path's
                // in-flight data to the others after a few PTOs. Paths the peer
                // abandoned or that were dropped are retired from TQUIC's path events,
                // every turn (below).
                if let Some(ci) = conn_index
                    && let Some(conn) = endpoint.conn_get_mut(ci)
                {
                    for (local, remote) in black_hole_paths(conn, &path_specs) {
                        tracing::warn!(target: "mpq", is_server, ?local, ?remote,
                            "mpquic path stopped answering, retiring it");
                        retire_path_spec(
                            (local, remote),
                            conn,
                            &mut path_specs,
                            &path_registry,
                            &mut recv_tasks,
                            &mut pending_path_events,
                        )?;
                    }
                }
            }
        }

        if let Some(deadline) = no_viable_path_at
            && let Some(ci) = conn_index
            && let Some(conn) = endpoint.conn_get_mut(ci)
        {
            let replaced = path_specs.iter().any(|&(local, remote)| {
                !failed_last_paths.contains(&(local, remote))
                    && path_is_validated(conn, local, remote)
            });
            if replaced {
                no_viable_path_at = None;
                for (local, remote) in failed_last_paths.drain(..) {
                    let _ = conn.abandon_path(local, remote);
                }
            } else if Instant::now() >= deadline {
                tracing::warn!(target: "mpq", is_server,
                    "mpquic driver exit: no replacement for the last path");
                let _ = conn.close(false, QUIC_NO_VIABLE_PATH, b"no viable path");
                endpoint.process_connections().ok();
                break;
            } else {
                next_wake.set(Some(next_wake.get().map_or(deadline, |wake| wake.min(deadline))));
            }
        }

        // Try to hand any pending application bytes to QUIC.
        if let Some(dp) = dp.as_mut() {
            if let Some(ci) = conn_index
                && let Some(conn) = endpoint.conn_get_mut(ci)
            {
                let now = Instant::now();
                let egress = path_specs.first().and_then(|(local, _)| {
                    path_registry.read().ok()?.carrier_for_local(*local)
                });
                if let Some(carrier) = &egress {
                    dp.set_aqm(egress_cake::stream_aqm(carrier), now);
                }
                dp.housekeeping(conn, now);
                dp.route_outbound(conn, now).map_err(anyhow::Error::msg)?;
                dp.flush(conn, now).map_err(anyhow::Error::msg)?;
                dp.flush_datagrams(conn, now);
                dp.owd_tick(conn, now);
                // The next probe is due without any packet arriving to wake us.
                if let Some(at) = dp.next_owd_wake() {
                    next_wake.set(Some(next_wake.get().map_or(at, |wake| wake.min(at))));
                }
                // The egress's card shows what its sessions' stream queues dropped.
                let drops = dp.stream_drops();
                if let Some(carrier) = &egress {
                    egress_cake::report_stream_drops(
                        carrier,
                        stream_queue::StreamDrops {
                            aqm: drops.aqm - reported_stream_drops.aqm,
                            overlimit: drops.overlimit - reported_stream_drops.overlimit,
                        },
                    );
                    reported_stream_drops = drops;
                }
            }
        } else if let Some(fair) = fair.as_mut() {
            if let (Some(ci), Some(stream_id)) = (conn_index, stream_id)
                && let Some(conn) = endpoint.conn_get_mut(ci)
            {
                let now = Instant::now();
                let egress = path_specs.first().and_then(|(local, _)| {
                    path_registry.read().ok()?.carrier_for_local(*local)
                });
                if let Some(carrier) = &egress {
                    fair.set_aqm(&egress_cake::stream_aqm(carrier), now);
                }
                fair.pump(
                    &mut ConnStream { conn, stream_id },
                    SQM_STREAM_NOTSENT_LOWAT,
                    now,
                )
                .map_err(anyhow::Error::msg)?;
                // The egress's card shows what its sessions' queues dropped.
                let drops = fair.drops();
                if let Some(carrier) = &egress {
                    egress_cake::report_stream_drops(
                        carrier,
                        stream_queue::StreamDrops {
                            aqm: drops.aqm - reported_stream_drops.aqm,
                            overlimit: drops.overlimit - reported_stream_drops.overlimit,
                        },
                    );
                    reported_stream_drops = drops;
                }
            }
        } else if let (Some(buf), Some(ci), Some(sid)) = (pending.clone(), conn_index, stream_id)
            && let Some(conn) = endpoint.conn_get_mut(ci)
        {
            match conn.stream_write(sid, buf.clone(), false) {
                Ok(written) if written >= buf.len() => pending = None,
                Ok(written) => pending = Some(buf.slice(written..)),
                Err(tquic::Error::Done) => { /* flow-control blocked; retry later */ }
                Err(e) => return Err(anyhow::anyhow!("stream_write: {e}")),
            }
        }

        if Instant::now() >= keepalive_next {
            keepalive_next = Instant::now() + PATH_KEEPALIVE_INTERVAL;
            if let Some(ci) = conn_index
                && let Some(conn) = endpoint.conn_get_mut(ci)
            {
                keepalive_idle_paths(conn, &path_specs, &mut keepalive_last_sent);
            }
        }

        // Move this driver's egress queues on before generating more, so the
        // data gate sees what actually left.
        sender.pump();
        endpoint.process_connections().ok();
        // QUIC has just sent what it held: if datagram frames wait in front
        // of it, the next turn must come now (`flush_datagrams`), not with
        // the next acknowledgment.
        if let Some(dp) = dp.as_ref()
            && let Some(ci) = conn_index
            && let Some(conn) = endpoint.conn_get_mut(ci)
            && dp.datagrams_ready(conn)
        {
            next_wake.set(Some(Instant::now()));
        }

        // What became of the paths comes from TQUIC's path events, taken every
        // turn so that no path can come and go between two looks at it.
        if let Some(ci) = conn_index
            && let Some(conn) = endpoint.conn_get_mut(ci)
        {
            for event in conn.take_path_abandon_events() {
                tracing::info!(target: "mpq", is_server, paths = ?path_specs, event);
            }
            for spec in retired_by_path_events(conn, &path_specs, &mut bound_paths) {
                tracing::warn!(target: "mpq", is_server, local = ?spec.0, remote = ?spec.1,
                    "mpquic path abandoned by the peer or dropped, retiring it");
                retire_path_spec(
                    spec,
                    conn,
                    &mut path_specs,
                    &path_registry,
                    &mut recv_tasks,
                    &mut pending_path_events,
                )?;
            }
        }

        // Drain transport events produced by the callbacks above.
        let events: Vec<DrvEvent> = state.borrow_mut().events.drain(..).collect();
        for ev in events {
            match ev {
                DrvEvent::Established(idx) => {
                    tracing::info!(target: "mpq", is_server, idx, "mpquic event: Established");
                    conn_index.get_or_insert(idx);
                    // MP_SQM_PLAN.md S2.10: a data-plane client may send only
                    // datagrams, so its server cannot wait for a stream.
                    if is_server
                        && dp.is_some()
                        && let Some(tx) = ready.take()
                    {
                        let _ = tx.send(
                            peer_remote.ok_or_else(|| "mpquic peer address unavailable".into()),
                        );
                    }
                    if !is_server && let Some(conn) = endpoint.conn_get_mut(idx) {
                        // Register every additional local socket as an extra QUIC
                        // path (client-only, requires a completed handshake) so
                        // the multipath scheduler can stripe/aggregate across
                        // them. Each add_path kicks off a PATH_CHALLENGE.
                        // A path TQUIC refuses is not kept as a phantom
                        // "validating" entry: it is retired like a failed carrier.
                        let mut refused = Vec::new();
                        for &(local, path_remote) in &path_specs[1..] {
                            match conn.add_path(local, path_remote) {
                                Ok(_) => {}
                                Err(tquic::Error::Done)
                                    if conn
                                        .get_path(local, path_remote)
                                        .is_ok_and(|path| !path.is_abandoned()) => {}
                                Err(e) => {
                                    tracing::warn!(?e, ?local, "mpquic add_path failed");
                                    refused.push((local, path_remote));
                                }
                            }
                        }
                        for (local, path_remote) in refused {
                            path_specs.retain(|spec| *spec != (local, path_remote));
                            let key = path_registry
                                .read()
                                .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
                                .key_for_addresses(local, path_remote);
                            if let Some(key) = key {
                                unregister_path(key, &path_registry, &mut recv_tasks)?;
                                pending_path_events.push_back(MpPathEvent::Down(key));
                            }
                        }
                        // Open the single application stream once.
                        if stream_id.is_none()
                            && let Ok(sid) = conn.stream_bidi_new(0, true)
                        {
                            tracing::info!(target: "mpq", sid, "mpquic client: opened stream, signaling ready");
                            stream_id = Some(sid);
                            if let Some(dp) = dp.as_mut() {
                                dp.set_primary(sid);
                            }
                            if let Some(tx) = ready.take() {
                                let _ = tx.send(
                                    peer_remote
                                        .ok_or_else(|| "mpquic peer address unavailable".into()),
                                );
                            }
                        }
                    }
                }
                DrvEvent::StreamCreated(idx, sid) => {
                    tracing::info!(target: "mpq", is_server, idx, sid, "mpquic event: StreamCreated");
                    conn_index.get_or_insert(idx);
                    if let Some(dp) = dp.as_mut() {
                        if is_server && sid == CLIENT_PRIMARY_STREAM {
                            dp.adopt_client_primary();
                        }
                    } else if stream_id.is_none() {
                        stream_id = Some(sid);
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(
                                peer_remote.ok_or_else(|| "mpquic peer address unavailable".into()),
                            );
                        }
                    }
                }
                DrvEvent::Readable(_, _) => {}
                // Data plane: reliable streams come and go; only the client's
                // first stream ends the session.
                DrvEvent::StreamClosed(_, sid) if dp.is_some() && sid != CLIENT_PRIMARY_STREAM => {}
                ev @ (DrvEvent::StreamClosed(..) | DrvEvent::Closed(_)) => {
                    let before_ready = ready.is_some();
                    tracing::info!(
                        target: "mpq",
                        is_server,
                        before_ready,
                        ?conn_index,
                        ?stream_id,
                        event = ?ev,
                        paths = ?path_specs,
                        "mpquic event: Closed"
                    );
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(Err("connection closed before ready".into()));
                    }
                    return Ok(());
                }
            }
        }

        // Take one bounded application batch only when the previous one was
        // delivered. A full pipe must not stop QUIC or grow an unbounded queue.
        if app_in.is_empty() && !inbound_finished {
            if let Some(dp) = dp.as_mut() {
                if let Some(ci) = conn_index
                    && let Some(conn) = endpoint.conn_get_mut(ci)
                {
                    let inbound = dp.inbound(conn, Instant::now()).map_err(anyhow::Error::msg)?;
                    app_in = match inbound.frames.as_slice() {
                        [] => Bytes::new(),
                        [frame] => frame.clone(),
                        frames => Bytes::from(frames.concat()),
                    };
                    inbound_more = inbound.more;
                    inbound_finished = inbound.primary_finished;
                }
            } else if let (Some(ci), Some(sid)) = (conn_index, stream_id) {
                match endpoint.conn_get_mut(ci).map(|conn| conn.stream_read(sid, &mut stream_read_buf)) {
                    Some(Ok((n, fin))) => {
                        app_in = Bytes::copy_from_slice(&stream_read_buf[..n]);
                        inbound_more = n > 0 && !fin;
                        inbound_finished = fin;
                    }
                    Some(Err(tquic::Error::Done)) | None => inbound_more = false,
                    Some(Err(error)) => return Err(anyhow::anyhow!("stream_read: {error}")),
                }
            }
        }

        if endpoint
            .conn_get_mut(conn_index.unwrap_or(u64::MAX))
            .is_none()
            && conn_index.is_some()
        {
            // Connection is gone.
            tracing::info!(
                target: "mpq",
                is_server,
                ?conn_index,
                ?stream_id,
                paths = ?path_specs,
                "mpquic driver exit: endpoint connection disappeared"
            );
            let _ = pipe_wr.shutdown().await;
            return Ok(());
        }
    }

    Ok(())
}

/// Drop a path's registry entry, and stop its carrier's receiver once the
/// carrier carries no path any more.
fn unregister_path(
    key: PathKey,
    path_registry: &RwLock<MpPathRegistry>,
    recv_tasks: &mut HashMap<CarrierId, tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let removed_carrier = path_registry
        .write()
        .map_err(|_| anyhow::anyhow!("MP path registry poisoned"))?
        .unregister(key);
    tracing::debug!(target: "mpq", ?key, removed_carrier, "MP path unregistered");
    if removed_carrier && let Some(recv_task) = recv_tasks.remove(&key.carrier_id) {
        recv_task.abort();
    }
    Ok(())
}

/// Emit one line of per-path telemetry (the "HUD"): reads each path's
/// BBR-derived stats (pacing rate, smoothed RTT, cwnd) and a per-interval
/// send-throughput delta, so bandwidth aggregation across paths is visible in
/// the logs during a run. Also reported as the total across all paths.
fn dump_path_stats(
    endpoint: &mut tquic::Endpoint,
    ci: u64,
    paths: &[(SocketAddr, SocketAddr)],
    last_sent: &mut HashMap<SocketAddr, u64>,
    interval_secs: f64,
) {
    let mut lines = Vec::with_capacity(paths.len());
    let mut total_tx_bits = 0.0f64;
    for &(local, remote) in paths {
        let Some(conn) = endpoint.conn_get_mut(ci) else {
            break;
        };
        let Ok(st) = conn.get_path_stats(local, remote) else {
            continue;
        };
        // Copy the fields we need so the borrow of `conn` ends before the next
        // `conn_get_mut`.
        let sent_bytes = st.sent_bytes;
        let srtt_ms = st.srtt as f64 / 1000.0;
        let pace_mbit = st.pacing_rate as f64 * 8.0 / 1e6;
        let cwnd = st.final_cwnd;
        let lost = st.lost_bytes;
        let slow_start = st.in_slow_start;

        let prev = last_sent.insert(local, sent_bytes).unwrap_or(0);
        let tx_bits = sent_bytes.saturating_sub(prev) as f64 * 8.0;
        total_tx_bits += tx_bits;
        let tx_mbit_s = tx_bits / 1e6 / interval_secs;

        lines.push(format!(
            "{local} tx={tx_mbit_s:.2}Mb/s srtt={srtt_ms:.1}ms pace={pace_mbit:.1}Mb cwnd={cwnd} lost={lost}{}",
            if slow_start { " ss" } else { "" }
        ));
    }
    if !lines.is_empty() {
        let agg_mbit_s = total_tx_bits / 1e6 / interval_secs;
        tracing::info!(
            target: "mpquic::hud",
            paths = lines.len(),
            aggregate = format!("{agg_mbit_s:.2}Mb/s"),
            "mpquic tx per path:  {}",
            lines.join("   |   ")
        );
    }
}

/// MP_SQM_PLAN.md S2.5: "standalone session 同样按出口发布 autorate 样本". Mirrors
/// `dump_path_stats`'s per-path sent-bytes-delta/RTT sampling shape (same
/// `last_sent` bookkeeping convention), but publishes an `SqmSample` into
/// each path's own `GovernedCarrier` (via `MpPathRegistry::carrier_for_local`)
/// instead of logging -- the *only* sampler a standalone session has, since
/// `connector::mp_session::refresh_all_egress_capacities` never sees it (it
/// only iterates `MpSessionManager`-managed sessions, S1.4). One physical
/// local socket has exactly one carrier (`carrier_id`'s doc comment), so this
/// keys `last_bytes` (sent) by `local_addr`, same as the HUD
/// does, without needing a per-remote breakdown. Called from `DriverCommand::PublishAutorateSample`'s
/// handler, not a dedicated `select!` timer branch -- see that variant's doc
/// comment for why. `elapsed` is the real wall-clock time since the previous
/// call (whatever cadence the external caller actually achieved), not an
/// assumed fixed interval.
fn sample_standalone_autorate(
    endpoint: &mut tquic::Endpoint,
    ci: u64,
    paths: &[(SocketAddr, SocketAddr)],
    registry: &Arc<RwLock<MpPathRegistry>>,
    last_bytes: &mut HashMap<SocketAddr, u64>,
    elapsed: std::time::Duration,
) {
    let dt_micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
    for &(local, remote) in paths {
        let Some(conn) = endpoint.conn_get_mut(ci) else {
            break;
        };
        let Ok(st) = conn.get_path_stats(local, remote) else {
            continue;
        };
        let sent_bytes = st.sent_bytes;
        let srtt_micros = st.srtt;
        let min_rtt_micros = st.min_rtt;
        let prev = last_bytes.insert(local, sent_bytes).unwrap_or(sent_bytes);
        let achieved_bps =
            WireBitrate::from_byte_delta_over_micros(sent_bytes.saturating_sub(prev), dt_micros).0;
        // Same baseline-normalization convention as
        // `connector::mp_session::refresh_all_egress_capacities`: queue delay
        // is SRTT minus min-RTT, plus a small constant so the estimator's
        // internal baseline stays well-defined even at exactly zero.
        let owd_us = srtt_micros.saturating_sub(min_rtt_micros).saturating_add(1);

        let Some(carrier) = registry
            .read()
            .ok()
            .and_then(|registry| registry.carrier_for_local(local))
        else {
            continue;
        };
        if let Err(error) =
            carrier.publish_autorate_sample(SqmSample { owd_us, achieved_bps })
        {
            tracing::debug!(
                ?error,
                ?local,
                ?remote,
                "skipped standalone autorate sample for a retired-generation egress scope"
            );
        }
    }
}

/// MP_SQM_PLAN.md S2.5: drives `DriverCommand::PublishAutorateSample` on a
/// fixed cadence for one standalone `mpquic://` session, for as long as its
/// driver is alive. Spawned on the ambient (multi-threaded) runtime
/// `connect()`/`accept()` run on -- deliberately NOT on the driver's own
/// dedicated single-threaded runtime -- so this task's own scheduling never
/// competes with that driver's packet-pacing loop for the same OS thread; it
/// only ever sends one lightweight message down the existing `commands`
/// channel per tick. `request_autorate_sample` returning `false` means the
/// driver has shut down (peer removed / tunnel dropped), so this task exits
/// instead of ticking forever against a channel with no reader.
fn spawn_standalone_autorate_sampler(session: MpSessionHandle) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if !session.request_autorate_sample() {
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

fn bind_udp(
    local: SocketAddr,
    dev: BindDev,
) -> Result<(SocketAddr, std::net::UdpSocket), TunnelError> {
    // Reuse ET's device-aware bind: SO_BINDTODEVICE on Linux, IP_UNICAST_IF by
    // interface index on Windows (so it survives the NIC's IP changing).
    let sock: std::net::UdpSocket = bind::<std::net::UdpSocket>().addr(local).dev(dev).call()?;
    let addr = sock
        .local_addr()
        .map_err(|e| TunnelError::InternalError(format!("local_addr: {e}")))?;
    Ok((addr, sock))
}

fn unspecified_for(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// MP_SQM_PLAN.md S2.10: as `make_tunnel`, but the ET-to-driver direction
/// carries each packet's data-plane class tag in the frame length's upper
/// bytes. The driver strips it; nothing tagged reaches the wire.
fn make_data_plane_tunnel(pipe: tokio::io::DuplexStream, info: TunnelInfo) -> Box<dyn Tunnel> {
    let (r, w) = tokio::io::split(pipe);
    Box::new(TunnelWrapper::new(
        FramedReader::new(r, MAX_PACKET_SIZE),
        FramedWriter::new_with_converter(w, MpPipeZCPacketToBytes),
        Some(info),
    ))
}

fn make_tunnel(pipe: tokio::io::DuplexStream, info: TunnelInfo) -> Box<dyn Tunnel> {
    let (r, w) = tokio::io::split(pipe);
    Box::new(TunnelWrapper::new(
        FramedReader::new(r, MAX_PACKET_SIZE),
        FramedWriter::new(w),
        Some(info),
    ))
}

/// MP_SQM_PLAN.md S1.4: wraps an ordinary `make_tunnel` byte pipe so a
/// standalone `mpquic://` connector/listener (not `MpSessionManager`-managed)
/// can surface its `MpSessionHandle` through `Tunnel::mp_session_handle`.
/// Only `MpQuicTunnelConnector::connect()` and `MpQuicTunnelListener::accept()`
/// use this -- `session_from_datagram_paths_with_config` (the MP-managed
/// path) keeps calling plain `make_tunnel` and hands its handle to its caller
/// directly via its tuple return, so it must NOT also be wrapped here: doing
/// so would make `PeerConn` see the same session twice, once "managed" and
/// once "standalone".
struct StandaloneMpQuicTunnel {
    inner: Box<dyn Tunnel>,
    session: MpSessionHandle,
    congestion_control: CongestionControlProfile,
}

impl Tunnel for StandaloneMpQuicTunnel {
    fn split(&self) -> SplitTunnel {
        self.inner.split()
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.inner.info()
    }

    fn mp_session_handle(&self) -> Option<MpSessionHandle> {
        Some(self.session.clone())
    }

    fn mp_congestion_control(&self) -> Option<&'static str> {
        Some(self.congestion_control.as_str())
    }
}

fn make_standalone_tunnel(
    pipe: tokio::io::DuplexStream,
    info: TunnelInfo,
    session: MpSessionHandle,
    congestion_control: CongestionControlProfile,
    runtime: &MpQuicSessionConfig,
) -> Box<dyn Tunnel> {
    let inner = if pipe_has_flow_trailer(runtime) {
        make_data_plane_tunnel(pipe, info)
    } else {
        make_tunnel(pipe, info)
    };
    Box::new(StandaloneMpQuicTunnel {
        inner,
        session,
        congestion_control,
    })
}

async fn wait_for_session_ready(
    ready_rx: oneshot::Receiver<Result<SocketAddr, String>>,
    deadline: std::time::Duration,
) -> Result<SocketAddr, TunnelError> {
    tokio::time::timeout(deadline, ready_rx)
        .await
        .map_err(|_| TunnelError::InternalError("mpquic session establishment timed out".into()))?
        .map_err(|_| TunnelError::InternalError("mpquic driver gone".into()))?
        .map_err(TunnelError::InternalError)
}

pub(crate) async fn tunnel_from_datagram_paths(
    is_server: bool,
    paths: Vec<(Arc<dyn MpDatagramPath>, Option<EgressScope>)>,
    remote: SocketAddr,
    remote_url: url::Url,
    tunnel_type: &str,
    egress_quality: Arc<EgressQualityManager>,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    session_from_datagram_paths(
        is_server,
        paths,
        remote,
        remote_url,
        tunnel_type,
        egress_quality,
    )
    .await
    .map(|(tunnel, _session)| tunnel)
}

pub(crate) async fn session_from_datagram_paths(
    is_server: bool,
    paths: Vec<(Arc<dyn MpDatagramPath>, Option<EgressScope>)>,
    remote: SocketAddr,
    remote_url: url::Url,
    tunnel_type: &str,
    egress_quality: Arc<EgressQualityManager>,
) -> Result<(Box<dyn Tunnel>, MpSessionHandle), TunnelError> {
    session_from_datagram_paths_with_config(
        is_server,
        paths,
        remote,
        remote_url,
        tunnel_type,
        mp_runtime_config_from_env(),
        egress_quality,
        None,
    )
    .await
}

/// Shuts the session's driver down when dropped before [`Self::disarm`].
struct ShutdownOnDrop(Option<MpSessionHandle>);

impl ShutdownOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.shutdown();
        }
    }
}

pub(crate) async fn session_from_datagram_paths_with_config(
    is_server: bool,
    paths: Vec<(Arc<dyn MpDatagramPath>, Option<EgressScope>)>,
    remote: SocketAddr,
    remote_url: url::Url,
    tunnel_type: &str,
    runtime: MpQuicSessionConfig,
    egress_quality: Arc<EgressQualityManager>,
    data_plane: Option<Arc<DataPlanePolicy>>,
) -> Result<(Box<dyn Tunnel>, MpSessionHandle), TunnelError> {
    let local_addr = paths
        .first()
        .map(|(path, _)| path.local_addr())
        .ok_or_else(|| TunnelError::InternalError("mpquic requires at least one path".into()))?;
    let (et_end, drv_end) = tokio::io::duplex(duplex_buf_bytes(runtime.sqm_enabled));
    let (ready_tx, ready_rx) = oneshot::channel();
    let (session, commands) = driver_command_channel();
    spawn_driver(DriverCfg {
        is_server,
        paths: paths
            .into_iter()
            .map(|(path, nic_scope)| MpPathInput::Ready(path, nic_scope))
            .collect(),
        remote,
        pipe: drv_end,
        ready: ready_tx,
        commands,
        runtime,
        egress_quality,
        // MP-managed paths already carry the NIC scope the session resolved
        // per path, which `scope_for` prefers over a resolved route -- no
        // separate resolution needed here.
        initial_resolved_scope: None,
        egress_inventory: None,
        data_plane: data_plane.filter(|_| runtime.data_plane),
    });

    // A handshake that is dropped (a carrier given to another session) or
    // fails must not leave its driver running: it would keep reading the
    // carrier's socket that the next attempt, or another session's path, uses.
    let abort = ShutdownOnDrop(Some(session.clone()));
    let peer_remote = wait_for_session_ready(ready_rx, runtime.establishment_timeout).await?;
    abort.disarm();
    let local_url = super::build_url_from_socket_addr(&local_addr.to_string(), "mpquic");
    let resolved_remote = super::build_url_from_socket_addr(&peer_remote.to_string(), "mpquic");
    let info = TunnelInfo {
        tunnel_type: tunnel_type.to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.into()),
        resolved_remote_addr: Some(resolved_remote.into()),
    };
    let tunnel = if pipe_has_flow_trailer(&runtime) {
        make_data_plane_tunnel(et_end, info)
    } else {
        make_tunnel(et_end, info)
    };
    Ok((tunnel, session))
}

// ---------------------------------------------------------------------------
// Connector (client)
// ---------------------------------------------------------------------------

pub struct MpQuicTunnelConnector {
    addr: url::Url,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    bind_addrs: Vec<SocketAddr>,
    /// v1 manual multipath: one QUIC subflow per selected egress NIC.
    bind_devs: Vec<BindDev>,
    runtime: MpQuicSessionConfig,
    /// MP_SQM_PLAN.md S1.3: the real factory path (`new_with_mp_config`,
    /// used by `connector::create_connector_by_url`) injects the process's
    /// one shared `GlobalCtx::egress_quality_manager()` here instead of this
    /// connector building its own. `new`/`new_with_runtime` (standalone/test
    /// construction, with no `GlobalCtx` in hand) still fall back to a
    /// private instance -- every path opened through it is still governed
    /// the same way, it just does not share ledgers with the rest of the
    /// process.
    egress_quality: Arc<EgressQualityManager>,
    /// MP_SQM_PLAN.md S1.3 (remainder): the process's shared
    /// `GlobalCtx::get_egress_inventory()`, when one has been published (it
    /// is set once `PeerManager::start_egress_inventory()` has run). Used in
    /// `connect()` to resolve `remote` to an `EgressScope` via
    /// `EgressInventory::best_route_to` -- accounting only, never a bind
    /// change. `None` for standalone/test construction (`new`,
    /// `new_with_runtime`), which have no `GlobalCtx` in hand; every path
    /// then stays on `EgressStableId::Fallback` exactly as before.
    egress_inventory: Option<EgressInventory>,
}

impl MpQuicTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self::new_with_egress_quality(
            addr,
            EgressQualityManager::new(EgressQualityConfig::default()),
        )
    }

    fn new_with_egress_quality(addr: url::Url, egress_quality: Arc<EgressQualityManager>) -> Self {
        Self {
            addr,
            ip_version: IpVersion::Both,
            resolved_addr: None,
            bind_addrs: Vec::new(),
            bind_devs: Vec::new(),
            runtime: mp_runtime_config_from_env(),
            egress_quality,
            egress_inventory: None,
        }
    }

    pub(crate) fn new_with_mp_config(
        addr: url::Url,
        config: &crate::proto::common::MpConfig,
        egress_quality: Arc<EgressQualityManager>,
        egress_inventory: Option<EgressInventory>,
    ) -> Result<Self, TunnelError> {
        let mut connector = Self::new_with_egress_quality(addr, egress_quality);
        connector.runtime = standalone_runtime_from_mp_config(config)?;
        connector.egress_inventory = egress_inventory;
        Ok(connector)
    }

    #[cfg(test)]
    fn new_with_runtime(addr: url::Url, runtime: MpQuicSessionConfig) -> Self {
        Self {
            runtime,
            ..Self::new(addr)
        }
    }

    /// v1 multipath: manually select the egress NIC(s). Each name becomes one
    /// QUIC subflow bound to that interface. Binding is by device name/index (not
    /// IP), so it survives the interface's IP changing. See MP_SQM_PLAN.md §2.
    pub fn set_bind_devs(&mut self, devs: Vec<String>) {
        self.bind_devs = devs
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(BindDev::Custom)
            .collect();
    }

    /// Resolve the set of `(bind_addr, device)` pairs to open, one per path.
    /// Priority: explicit NIC list (`set_bind_devs`) → `ET_MPQUIC_DEVS` env
    /// (comma-separated NIC names, for manual testing) → a single OS-routed
    /// socket (the default).
    ///
    /// Multipath egress is selected by DEVICE, never by source IP: ET's
    /// connector framework auto-populates `bind_addrs` with *every* local
    /// interface IP as connect *candidates* (the source-IP model the TCP/UDP
    /// connectors use, where they try each and keep the first that connects).
    /// Turning those into one QUIC subflow apiece is wrong on two counts — it
    /// aborts the whole connect if any single interface IP is unbindable
    /// (stale/link-local addr, VM host-only adapter, ...), and it pins the
    /// primary path to an arbitrary interface that may not route to `remote`
    /// (fatal for loopback / cross-subnet). Binding by device instead keeps a
    /// path alive across the NIC's IP changing (see MP_SQM_PLAN.md §2), so the
    /// framework-provided `bind_addrs` are intentionally ignored here.
    fn resolve_path_specs(&self, remote: SocketAddr) -> Vec<(SocketAddr, BindDev)> {
        if !self.bind_devs.is_empty() {
            return self
                .bind_devs
                .iter()
                .cloned()
                .map(|dev| (unspecified_for(remote), dev))
                .collect();
        }
        if !self.bind_addrs.is_empty() {
            tracing::debug!(
                addrs = ?self.bind_addrs,
                "mpquic: ignoring framework-provided bind_addrs; egress is device-selected, \
                 defaulting to a single OS-routed socket",
            );
        }
        if let Ok(devs) = std::env::var("ET_MPQUIC_DEVS") {
            let specs: Vec<(SocketAddr, BindDev)> = devs
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| (unspecified_for(remote), BindDev::Custom(s.to_string())))
                .collect();
            if !specs.is_empty() {
                return specs;
            }
        }
        vec![(unspecified_for(remote), BindDev::Disabled)]
    }
}

#[async_trait::async_trait]
impl TunnelConnector for MpQuicTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let remote = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };

        // Bind one socket per requested path. v1: one subflow per selected NIC
        // (device-bound); otherwise a single OS-routed socket.
        let path_specs = self.resolve_path_specs(remote);
        let mut socks = Vec::with_capacity(path_specs.len());
        for (b, dev) in path_specs {
            match bind_udp(b, dev) {
                Ok(s) => socks.push(s),
                // One unbindable egress (a stale/link-local interface addr or a
                // NIC that just went down) must not sink the whole connection;
                // skip it and keep the paths that did bind, like the TCP/UDP
                // connectors do with their candidate bind addrs.
                Err(e) => tracing::warn!(?e, bind = ?b, "mpquic: skip unbindable egress path"),
            }
        }
        if socks.is_empty() {
            return Err(TunnelError::InternalError(
                "mpquic connect: no egress socket could be bound".into(),
            ));
        }
        let local_addr = socks[0].0;

        // MP_SQM_PLAN.md S1.3 (remainder): accounting only -- resolve which
        // egress interface the OS would route `remote` through and use it
        // for budget scoping, but never rebind. Skipped for the manual
        // multi-NIC case (explicit `bind_devs`/`ET_MPQUIC_DEVS`): each of
        // those sockets is already pinned to a caller-chosen device, so
        // resolving a single OS-routed scope for `remote` would misattribute
        // every one of them to whichever interface the OS happens to prefer.
        let initial_resolved_scope = if self.bind_devs.is_empty() && std::env::var("ET_MPQUIC_DEVS").is_err() {
            match &self.egress_inventory {
                Some(inventory) => {
                    resolve_egress_scope(inventory, remote, EgressDirection::Egress).await
                }
                None => None,
            }
        } else {
            None
        };

        let (et_end, drv_end) = tokio::io::duplex(duplex_buf_bytes(self.runtime.sqm_enabled));
        let (ready_tx, ready_rx) = oneshot::channel();
        let (session, commands) = driver_command_channel();
        spawn_driver(DriverCfg {
            is_server: false,
            paths: socks
                .into_iter()
                .map(|(local_addr, socket)| MpPathInput::udp(local_addr, socket))
                .collect(),
            remote,
            pipe: drv_end,
            ready: ready_tx,
            commands,
            runtime: self.runtime,
            egress_quality: self.egress_quality.clone(),
            initial_resolved_scope,
            egress_inventory: None,
            // Standalone sessions keep the single stream (S2.10).
            data_plane: None,
        });
        spawn_standalone_autorate_sampler(session.clone());

        let _peer_remote = ready_rx
            .await
            .map_err(|_| TunnelError::InternalError("mpquic driver gone".into()))?
            .map_err(TunnelError::InternalError)?;

        let info = TunnelInfo {
            tunnel_type: "mpquic".to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "mpquic").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&remote.to_string(), "mpquic").into(),
            ),
        };
        // MP_SQM_PLAN.md S1.4: this is a standalone connect (not routed
        // through MpSessionManager), so the session handle has no other
        // owner -- surface it via the tunnel itself instead of dropping it.
        Ok(make_standalone_tunnel(
            et_end,
            info,
            session,
            self.runtime.congestion_control,
            &self.runtime,
        ))
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
}

// ---------------------------------------------------------------------------
// Listener (server)
// ---------------------------------------------------------------------------

pub struct MpQuicTunnelListener {
    addr: url::Url,
    local_addr: Option<SocketAddr>,
    /// Socket bound by `listen()`, handed to the server driver on the first
    /// `accept()`. Held here — NOT in a detached driver thread — until then so
    /// that a listener dropped before it is ever accepted from (e.g. the
    /// `ListenerManager::run` "try listen once" probe) releases the port
    /// synchronously on drop instead of leaking it to a driver that outlives us.
    pending_sock: Option<std::net::UdpSocket>,
    accept_rx: Option<mpsc::Receiver<Box<dyn Tunnel>>>,
    /// Kept so the accept channel stays open for the listener's lifetime.
    _accept_tx: Option<mpsc::Sender<Box<dyn Tunnel>>>,
    runtime: MpQuicSessionConfig,
    /// Same MP_SQM_PLAN.md S1.3 GlobalCtx-injection note as
    /// `MpQuicTunnelConnector::egress_quality` -- see there.
    egress_quality: Arc<EgressQualityManager>,
    /// MP_SQM_PLAN.md S1.3 (remainder): unlike the connector, the listener
    /// has no target IP at all until a peer's first packet arrives, so it
    /// cannot resolve a route up front. It carries this handle in instead so
    /// `drive()` can resolve one itself, per accepted session, once the real
    /// peer address is known (see the `is_server && peer_remote.is_none()`
    /// branch and `MpPathRegistry::rescope`). `None` for standalone/test
    /// construction; that path stays on `EgressStableId::Fallback`.
    egress_inventory: Option<EgressInventory>,
}

impl MpQuicTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        Self::new_with_egress_quality(
            addr,
            EgressQualityManager::new(EgressQualityConfig::default()),
        )
    }

    fn new_with_egress_quality(addr: url::Url, egress_quality: Arc<EgressQualityManager>) -> Self {
        Self {
            addr,
            local_addr: None,
            pending_sock: None,
            accept_rx: None,
            _accept_tx: None,
            runtime: mp_runtime_config_from_env(),
            egress_quality,
            egress_inventory: None,
        }
    }

    pub(crate) fn new_with_mp_config(
        addr: url::Url,
        config: &crate::proto::common::MpConfig,
        egress_quality: Arc<EgressQualityManager>,
        egress_inventory: Option<EgressInventory>,
    ) -> Result<Self, TunnelError> {
        let mut listener = Self::new_with_egress_quality(addr, egress_quality);
        listener.runtime = standalone_runtime_from_mp_config(config)?;
        listener.egress_inventory = egress_inventory;
        Ok(listener)
    }

    #[cfg(test)]
    fn new_with_runtime(addr: url::Url, runtime: MpQuicSessionConfig) -> Self {
        Self {
            runtime,
            ..Self::new(addr)
        }
    }
}

#[async_trait::async_trait]
impl TunnelListener for MpQuicTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let bind: SocketAddr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        // The server listens on a fixed address; device binding is only for the
        // connector's per-path egress selection, so keep it disabled here.
        let (local_addr, std_sock) = bind_udp(bind, BindDev::Disabled)?;
        self.local_addr = Some(local_addr);
        self.addr.set_port(Some(local_addr.port())).ok();
        // Hold the bound socket here rather than moving it straight into the
        // driver: `listen()` is called once as a "try listen" probe by
        // `ListenerManager::run` and the resulting listener is dropped
        // immediately, so binding must have no side effect that outlives the
        // listener. The driver is spawned lazily on the first `accept()`.
        self.pending_sock = Some(std_sock);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        // Spawn the single server driver lazily on the first accept(), taking
        // the socket bound in listen(). Keeping the driver out of listen() is
        // what lets a probe-then-drop listener release its port cleanly.
        if self.accept_rx.is_none() {
            let std_sock = self
                .pending_sock
                .take()
                .ok_or_else(|| TunnelError::InternalError("mpquic listener not bound".into()))?;
            let local_addr = self
                .local_addr
                .ok_or_else(|| TunnelError::InternalError("mpquic listener not bound".into()))?;

            let (accept_tx, accept_rx) = mpsc::channel(16);
            self.accept_rx = Some(accept_rx);
            self._accept_tx = Some(accept_tx.clone());

            // One driver per server endpoint, one connection (v1). Each accepted
            // connection produces a tunnel pushed to `accept_tx`.
            let (et_end, drv_end) = tokio::io::duplex(duplex_buf_bytes(self.runtime.sqm_enabled));
            let (ready_tx, ready_rx) = oneshot::channel();
            let (session, commands) = driver_command_channel();
            spawn_driver(DriverCfg {
                is_server: true,
                paths: vec![MpPathInput::udp(local_addr, std_sock)],
                remote: unspecified_for(local_addr),
                pipe: drv_end,
                ready: ready_tx,
                commands,
                runtime: self.runtime,
                egress_quality: self.egress_quality.clone(),
                initial_resolved_scope: None,
                egress_inventory: self.egress_inventory.clone(),
                data_plane: None,
            });
            spawn_standalone_autorate_sampler(session.clone());

            let listen_url = self.local_url();
            let congestion_control = self.runtime.congestion_control;
            let runtime = self.runtime;
            tokio::spawn(async move {
                if let Ok(Ok(peer_remote)) = ready_rx.await {
                    let peer_url =
                        super::build_url_from_socket_addr(&peer_remote.to_string(), "mpquic");
                    let info = TunnelInfo {
                        tunnel_type: "mpquic".to_owned(),
                        local_addr: Some(listen_url.clone().into()),
                        remote_addr: Some(peer_url.clone().into()),
                        resolved_remote_addr: Some(peer_url.into()),
                    };
                    // MP_SQM_PLAN.md S1.4: same standalone-session rationale
                    // as the connector side above.
                    let _ = accept_tx
                        .send(make_standalone_tunnel(
                            et_end,
                            info,
                            session,
                            congestion_control,
                            &runtime,
                        ))
                        .await;
                }
            });
        }

        let rx = self
            .accept_rx
            .as_mut()
            .ok_or_else(|| TunnelError::InternalError("listener not started".into()))?;
        rx.recv()
            .await
            .ok_or_else(|| TunnelError::InternalError("mpquic accept channel closed".into()))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn udp_carriers_set_dont_fragment() {
        use std::os::fd::AsRawFd;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _path = SharedUnconnectedUdpDatagramPath::new_with_guard(socket.clone(), None).unwrap();
        let mut value: nix::libc::c_int = 0;
        let mut len = std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t;
        let rc = unsafe {
            nix::libc::getsockopt(
                socket.as_raw_fd(),
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MTU_DISCOVER,
                &mut value as *mut _ as *mut nix::libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(value, nix::libc::IP_PMTUDISC_PROBE);
        assert!(is_icmp_error(&std::io::Error::from_raw_os_error(
            nix::libc::EMSGSIZE
        )));
    }

    #[tokio::test]
    async fn session_ready_wait_has_a_bounded_deadline() {
        let (_ready_tx, ready_rx) = oneshot::channel();
        let bounded = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            wait_for_session_ready(ready_rx, std::time::Duration::from_millis(10)),
        )
        .await;

        let result = bounded.expect("session ready wait must enforce its own deadline");
        let error = result.expect_err("stalled session establishment must time out");
        assert!(
            error
                .to_string()
                .contains("session establishment timed out")
        );
    }
    use crate::tunnel::TunnelConnector;
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};
    use crate::common::egress_inventory::EgressStableId;
    use crate::common::transport_quality::rate::WireBitrate;
    use crate::common::transport_quality::{EgressDirection, EgressScope};
    use crate::tunnel::packet_def::ZCPacket;
    use futures_util::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use std::sync::{LazyLock, Mutex};
    use tokio::runtime::{Builder, Runtime};

    static RUNTIME: LazyLock<Runtime> =
        LazyLock::new(|| Builder::new_multi_thread().enable_all().build().unwrap());

    struct MockDatagramPath {
        local_addr: SocketAddr,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for MockDatagramPath {
        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
            self.sent.lock().unwrap().push((payload.to_vec(), remote));
            Ok(payload.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    struct FailedReceivePath {
        local_addr: SocketAddr,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for FailedReceivePath {
        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        fn try_send_to(&self, payload: &[u8], _remote: SocketAddr) -> std::io::Result<usize> {
            Ok(payload.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "expected receiver failure",
            ))
        }
    }

    #[tokio::test]
    async fn path_receiver_reports_carrier_failure() {
        let path: Arc<dyn MpDatagramPath> = Arc::new(FailedReceivePath {
            local_addr: "127.0.0.1:31000".parse().unwrap(),
        });
        let expected = carrier_id(&path);
        let (dgram_tx, _dgram_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let task = spawn_path_receiver(path, dgram_tx, event_tx);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
            .await
            .expect("path receiver did not terminate");
        task.await.unwrap();

        assert_eq!(event, Some(PathReceiverEvent::Failed(expected)));
    }

    #[tokio::test]
    async fn path_receiver_keeps_arrival_time_while_the_driver_is_busy() {
        let (_sender, _sender_addr, receiver, receiver_addr) = real_udp_path_pair().await;
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let queued = tx.clone();
        let (events, _event_rx) = mpsc::unbounded_channel();
        let task = spawn_path_receiver(receiver, tx, events);
        sender.send_to(b"arrival-stamp", receiver_addr).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while queued.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the real UDP receive never queued its packet");
        let queued_before = Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let packet = rx.recv().await.unwrap();
        assert_eq!(packet.payload, b"arrival-stamp");
        assert_eq!(packet.info.dst, receiver_addr);
        assert!(
            packet.info.time <= queued_before,
            "driver queue time must not move the arrival timestamp"
        );
        task.abort();
        let _ = task.await;
    }

    /// Fails every send and receive with `kind`.
    struct ErrorPath {
        local_addr: SocketAddr,
        kind: std::io::ErrorKind,
        recvs: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for ErrorPath {
        fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        fn try_send_to(&self, _payload: &[u8], _remote: SocketAddr) -> std::io::Result<usize> {
            Err(self.kind.into())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            if self.recvs.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3 {
                return Err(self.kind.into());
            }
            std::future::pending().await
        }
    }

    fn error_path(port: u16, kind: std::io::ErrorKind) -> Arc<ErrorPath> {
        Arc::new(ErrorPath {
            local_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            kind,
            recvs: Default::default(),
        })
    }

    /// An ICMP error surfacing on a connected socket (a closed port from a
    /// superseded punch) used to kill the path receiver and with it the
    /// only path of the session.
    #[tokio::test]
    async fn path_receiver_survives_icmp_errors() {
        let path = error_path(31020, std::io::ErrorKind::ConnectionRefused);
        let (dgram_tx, _dgram_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let task = spawn_path_receiver(path.clone(), dgram_tx, event_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while path.recvs.load(std::sync::atomic::Ordering::SeqCst) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("receiver stopped reading");
        assert!(event_rx.try_recv().is_err());
        assert!(!task.is_finished());
        task.abort();
    }

    /// A failed send drops the packet (QUIC recovers it) instead of failing
    /// TQUIC's whole send round; only a gone NIC or address retires the
    /// carrier.
    #[tokio::test]
    async fn datagram_sender_drops_on_send_errors_and_retires_only_gone_carriers() {
        let remote: SocketAddr = "127.0.0.1:32020".parse().unwrap();
        for (port, kind, retired) in [
            (31021, std::io::ErrorKind::ConnectionRefused, false),
            (31022, std::io::ErrorKind::NetworkUnreachable, false),
            (31023, std::io::ErrorKind::AddrNotAvailable, true),
        ] {
            let path = error_path(port, kind);
            let expected = carrier_id(&(path.clone() as Arc<dyn MpDatagramPath>));
            let mut registry = MpPathRegistry::new(test_manager());
            registry.register(path.clone(), remote, None, None).unwrap();
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let sender = DatagramSender::new(
                Arc::new(RwLock::new(registry)),
                Rc::new(std::cell::Cell::new(None)),
                event_tx,
            );
            let packet = || {
                (
                    b"lost".to_vec(),
                    tquic::PacketInfo {
                        src: path.local_addr,
                        dst: remote,
                        time: Instant::now(),
                        recv_timestamp: None,
                        send_meta: tquic::PacketSendMeta::default(),
                    },
                )
            };
            assert_eq!(
                tquic::PacketSendHandler::on_packets_send_sparse(&sender, &[packet()]).unwrap(),
                vec![0],
                "{kind:?}"
            );
            assert_eq!(
                tquic::PacketSendHandler::on_packets_send(&sender, &[packet()]).unwrap(),
                1,
                "{kind:?}"
            );
            let event = event_rx.try_recv().ok();
            assert_eq!(
                event,
                retired.then_some(PathReceiverEvent::Failed(expected)),
                "{kind:?}"
            );
        }
    }

    /// `MpPathRegistry::new` requires an `EgressQualityManager`, whose
    /// `_retain_task` needs an active Tokio runtime to `tokio::spawn` into --
    /// see `EgressQualityManager::new`. A fresh manager per test, matching
    /// the "no shared ledger between unrelated tests" pattern used
    /// throughout `common::egress_quality`'s and `tunnel::datagram_carrier`'s
    /// own tests.
    fn test_manager() -> Arc<EgressQualityManager> {
        EgressQualityManager::new(EgressQualityConfig::default())
    }

    /// A `DatagramSender` for tests that only exercise routing/governing
    /// behavior, not the driver's own wake-up plumbing or carrier
    /// retirement. `next_wake`/`event_tx` are real (not mocked) but nothing
    /// here asserts on them.
    fn test_sender(registry: MpPathRegistry) -> DatagramSender {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        DatagramSender::new(
            Arc::new(RwLock::new(registry)),
            Rc::new(std::cell::Cell::new(None)),
            event_tx,
        )
    }

    /// S-I12 (TCP small queues): a path with more than two packets (or 1 ms
    /// of the shaping rate) waiting in its egress's CAKE queue takes no more
    /// congestion-controlled data, and the driver is woken to ask again. The
    /// count follows the queue exactly: what CAKE sends and what it drops both
    /// leave it, so the gate opens again once the queue is empty.
    #[tokio::test]
    async fn data_waits_while_a_path_has_its_share_queued_in_cake() {
        use crate::common::transport_quality::rate::WireBitrate;
        let local: SocketAddr = "127.0.0.1:31041".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:32041".parse().unwrap();
        let path = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        registry.register(path.clone(), remote, None, None).unwrap();
        let (_, carrier) = registry.carrier_for(local, remote).unwrap();
        // 100 kB/s: 1 ms of it is 100 bytes, so the limit is two packets.
        carrier
            .bottleneck()
            .set_budget(Some(WireBitrate(800_000)))
            .unwrap();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let wake = Rc::new(std::cell::Cell::new(None));
        let sender = DatagramSender::new(
            Arc::new(RwLock::new(registry)),
            wake.clone(),
            event_tx,
        );
        let gate = |sender: &DatagramSender| {
            tquic::PacketSendHandler::can_send_data(sender, local, remote, 1_200)
        };
        assert!(gate(&sender), "an empty queue admits data");

        let burst: Vec<_> = (0..12)
            .map(|_| {
                (
                    vec![0u8; 1_200],
                    tquic::PacketInfo {
                        src: local,
                        dst: remote,
                        time: Instant::now(),
                        recv_timestamp: None,
                        send_meta: tquic::PacketSendMeta {
                            contains_data: true,
                            ..tquic::PacketSendMeta::default()
                        },
                    },
                )
            })
            .collect();
        tquic::PacketSendHandler::on_packets_send(&sender, &burst).unwrap();
        wake.set(None);
        assert!(!gate(&sender), "a backlog in CAKE holds data back");
        assert!(wake.get().is_some(), "and the driver is woken to ask again");

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while !gate(&sender) {
            assert!(Instant::now() < deadline, "the gate never reopened");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            sender.pump();
        }
        // Everything CAKE released or dropped has left the count.
        loop {
            sender.pump();
            if wake.take().is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let queue = super::egress_cake::EgressCake::of(&carrier);
        assert_eq!(queue.queued_bytes(local, remote), 0);
        assert!(gate(&sender));
    }

    #[tokio::test]
    async fn datagram_sender_routes_by_local_path_address() {
        let local_a: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let local_b: SocketAddr = "127.0.0.1:31002".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:32001".parse().unwrap();
        let path_a = Arc::new(MockDatagramPath {
            local_addr: local_a,
            sent: Mutex::new(Vec::new()),
        });
        let path_b = Arc::new(MockDatagramPath {
            local_addr: local_b,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        registry.register(path_a.clone(), remote, None, None).unwrap();
        registry.register(path_b.clone(), remote, None, None).unwrap();
        let sender = test_sender(registry);
        let packet = (
            b"path-b".to_vec(),
            tquic::PacketInfo {
                src: local_b,
                dst: remote,
                time: Instant::now(),
                recv_timestamp: None,
                send_meta: tquic::PacketSendMeta {
                    contains_data: true,
                    ..tquic::PacketSendMeta::default()
                },
            },
        );

        assert_eq!(
            tquic::PacketSendHandler::on_packets_send(&sender, &[packet]).unwrap(),
            1
        );
        assert!(path_a.sent.lock().unwrap().is_empty());
        assert_eq!(
            path_b.sent.lock().unwrap().as_slice(),
            &[(b"path-b".to_vec(), remote)]
        );
    }

    /// A packet for a path whose carrier is gone (or a remote it was never
    /// registered for) is dropped, not left unsent: the endpoint generates
    /// nothing more while an unsent packet sits in its queue, so one such
    /// packet stopped every path of the connection for good (spike S5).
    #[tokio::test]
    async fn datagram_sender_drops_packets_for_a_vanished_path() {
        let local: SocketAddr = "127.0.0.1:31013".parse().unwrap();
        let registered_remote: SocketAddr = "127.0.0.1:32012".parse().unwrap();
        let unregistered_remote: SocketAddr = "127.0.0.1:32013".parse().unwrap();
        let path = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        registry
            .register(path.clone(), registered_remote, None, None)
            .unwrap();
        let sender = test_sender(registry);
        let packet = |payload: &[u8], dst| {
            (
                payload.to_vec(),
                tquic::PacketInfo {
                    src: local,
                    dst,
                    time: Instant::now(),
                    recv_timestamp: None,
                    send_meta: tquic::PacketSendMeta {
                        contains_data: true,
                        ..tquic::PacketSendMeta::default()
                    },
                },
            )
        };
        let batch = [
            packet(b"vanished", unregistered_remote),
            packet(b"live", registered_remote),
        ];

        assert_eq!(
            tquic::PacketSendHandler::on_packets_send_sparse(&sender, &batch).unwrap(),
            vec![0, 1]
        );
        assert_eq!(
            tquic::PacketSendHandler::on_packets_send(&sender, &batch).unwrap(),
            2
        );
        assert_eq!(
            path.sent.lock().unwrap().as_slice(),
            &[
                (b"live".to_vec(), registered_remote),
                (b"live".to_vec(), registered_remote)
            ]
        );
    }

    #[tokio::test]
    async fn path_registry_allows_one_carrier_for_multiple_remote_endpoints() {
        let local: SocketAddr = "127.0.0.1:31005".parse().unwrap();
        let remote_a: SocketAddr = "127.0.0.1:32005".parse().unwrap();
        let remote_b: SocketAddr = "127.0.0.1:32006".parse().unwrap();
        let path: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());

        let first = registry.register(path.clone(), remote_a, None, None).unwrap();
        let second = registry.register(path, remote_b, None, None).unwrap();

        assert_ne!(first, second);
        assert_eq!(registry.carriers.len(), 1);
        assert_eq!(registry.paths.len(), 2);
    }

    #[tokio::test]
    async fn path_registry_keeps_shared_carrier_until_last_path_is_removed() {
        let local: SocketAddr = "127.0.0.1:31007".parse().unwrap();
        let remote_a: SocketAddr = "127.0.0.1:32007".parse().unwrap();
        let remote_b: SocketAddr = "127.0.0.1:32008".parse().unwrap();
        let path: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        let first = registry.register(path.clone(), remote_a, None, None).unwrap();
        let second = registry.register(path, remote_b, None, None).unwrap();

        assert!(!registry.unregister(first));
        assert_eq!(registry.carriers.len(), 1);
        assert_eq!(registry.paths, HashSet::from([second]));

        assert!(registry.unregister(second));
        assert!(registry.carriers.is_empty());
        assert!(registry.paths.is_empty());
    }

    #[tokio::test]
    async fn path_registry_removes_every_path_owned_by_a_failed_carrier() {
        let local_a: SocketAddr = "127.0.0.1:31030".parse().unwrap();
        let local_b: SocketAddr = "127.0.0.1:31031".parse().unwrap();
        let remote_a: SocketAddr = "127.0.0.1:32030".parse().unwrap();
        let remote_b: SocketAddr = "127.0.0.1:32031".parse().unwrap();
        let remote_c: SocketAddr = "127.0.0.1:32032".parse().unwrap();
        let carrier_a: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local_a,
            sent: Mutex::new(Vec::new()),
        });
        let carrier_b: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local_b,
            sent: Mutex::new(Vec::new()),
        });
        let failed_id = carrier_id(&carrier_a);
        let mut registry = MpPathRegistry::new(test_manager());
        let key_a = registry.register(carrier_a.clone(), remote_a, None, None).unwrap();
        let key_b = registry.register(carrier_a, remote_b, None, None).unwrap();
        let survivor = registry.register(carrier_b, remote_c, None, None).unwrap();

        let mut removed = registry.take_carrier_paths(failed_id);
        removed.sort_by_key(|key| (key.local_addr, key.remote_addr));
        let mut expected = vec![key_a, key_b];
        expected.sort_by_key(|key| (key.local_addr, key.remote_addr));

        assert_eq!(removed, expected);
        assert_eq!(registry.paths, HashSet::from([survivor]));
        assert_eq!(registry.carriers.len(), 1);
        assert!(registry.carrier_for(local_b, remote_c).is_some());
    }

    #[tokio::test]
    async fn path_registry_does_not_route_an_unregistered_remote_endpoint() {
        let local: SocketAddr = "127.0.0.1:31009".parse().unwrap();
        let registered_remote: SocketAddr = "127.0.0.1:32009".parse().unwrap();
        let unregistered_remote: SocketAddr = "127.0.0.1:32010".parse().unwrap();
        let path: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        registry.register(path, registered_remote, None, None).unwrap();

        assert!(registry.carrier_for(local, registered_remote).is_some());
        assert!(registry.carrier_for(local, unregistered_remote).is_none());
    }

    #[tokio::test]
    async fn path_registry_routes_server_initial_path_after_remote_is_learned() {
        let local: SocketAddr = "127.0.0.1:31011".parse().unwrap();
        let learned_remote: SocketAddr = "127.0.0.1:32011".parse().unwrap();
        let path: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let mut registry = MpPathRegistry::new(test_manager());
        registry
            .register(path, unspecified_for(local), None, None)
            .unwrap();

        assert!(registry.carrier_for(local, learned_remote).is_some());
    }

    #[tokio::test]
    async fn session_handle_forwards_dynamic_path_to_driver() {
        let local: SocketAddr = "127.0.0.1:31003".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:32003".parse().unwrap();
        let path = Arc::new(MockDatagramPath {
            local_addr: local,
            sent: Mutex::new(Vec::new()),
        });
        let (session, mut commands) = driver_command_channel();

        let driver = tokio::spawn(async move {
            let Some(DriverCommand::AddPath {
                path,
                remote: requested_remote,
                nic_scope,
                result,
            }) = commands.recv().await
            else {
                panic!("missing add-path command");
            };
            assert_eq!(path.local_addr(), local);
            assert_eq!(requested_remote, remote);
            assert!(nic_scope.is_none());
            result.send(Ok(())).unwrap();
        });

        session.add_path(path, remote, None).await.unwrap();
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn session_handle_forwards_easytier_peer_removal_to_driver() {
        let (session, mut commands) = driver_command_channel();

        session.shutdown();

        assert!(matches!(
            commands.recv().await,
            Some(DriverCommand::Shutdown)
        ));
    }

    #[tokio::test]
    async fn session_handle_forwards_path_telemetry_request_to_driver() {
        let (session, mut commands) = driver_command_channel();
        let expected = vec![MpPathTelemetry {
            local_addr: "127.0.0.1:31015".parse().unwrap(),
            remote_addr: "127.0.0.1:32015".parse().unwrap(),
            validation_state: tquic::PathState::Validated,
            bandwidth_model_valid: true,
            btlbw: 123_000_000,
            delivery_rate: 120_000_000,
            app_limited: false,
            sample_age_micros: Some(1_000),
            congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
            observed_local_addr: None,
            scheduler_target_rate_bps: Some(80_000_000),
            min_rtt_micros: 18_000,
            windowed_min_rtt_micros: 19_000,
            backed_off: false,
            srtt_micros: 20_000,
            sent_bytes: 10_000,
            recv_bytes: 9_000,
            lost_bytes: 100,
            acked_bytes: 8_000,
            max_inflight_bytes: 15_000,
            cwnd_bytes: 60_000,
            pacing_rate_bps: 130_000_000,
        }];
        let driver_expected = expected.clone();
        let driver = tokio::spawn(async move {
            let Some(DriverCommand::SnapshotPaths { result }) = commands.recv().await else {
                panic!("missing path telemetry command");
            };
            result.send(Ok(driver_expected)).unwrap();
        });

        assert_eq!(session.path_telemetry().await.unwrap(), expected);
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn session_handle_forwards_path_targets_to_driver() {
        let (session, mut commands) = driver_command_channel();
        let expected = vec![MpPathTarget {
            local_addr: "127.0.0.1:31019".parse().unwrap(),
            remote_addr: "127.0.0.1:32019".parse().unwrap(),
            rate: Some(50_000_000),
            standby: false,
        }];
        let driver_expected = expected.clone();
        let driver = tokio::spawn(async move {
            let Some(DriverCommand::SetPathTargets { targets, result }) = commands.recv().await
            else {
                panic!("missing path-target command");
            };
            assert_eq!(targets, driver_expected);
            result.send(Ok(())).unwrap();
        });

        session.set_path_targets(expected).await.unwrap();
        driver.await.unwrap();
    }

    #[test]
    fn registered_path_targets_skip_a_path_retired_before_the_control_tick() {
        let live = MpPathTarget {
            local_addr: "127.0.0.1:31020".parse().unwrap(),
            remote_addr: "127.0.0.1:32020".parse().unwrap(),
            rate: Some(50_000_000),
            standby: false,
        };
        let retired = MpPathTarget {
            local_addr: "127.0.0.1:31021".parse().unwrap(),
            remote_addr: "127.0.0.1:32021".parse().unwrap(),
            rate: Some(25_000_000),
            standby: false,
        };

        let retained = registered_path_targets(vec![live, retired], |local, remote| {
            (local, remote) == (live.local_addr, live.remote_addr)
        });

        assert_eq!(retained, vec![live]);
    }

    #[tokio::test]
    async fn session_handle_forwards_remove_path_to_driver() {
        let (session, mut commands) = driver_command_channel();
        let local_addr = "127.0.0.1:31021".parse().unwrap();
        let remote_addr = "127.0.0.1:32021".parse().unwrap();
        let driver = tokio::spawn(async move {
            let Some(DriverCommand::RemovePath {
                local_addr: requested_local,
                remote_addr: requested_remote,
                result,
            }) = commands.recv().await
            else {
                panic!("missing remove-path command");
            };
            assert_eq!(requested_local, local_addr);
            assert_eq!(requested_remote, remote_addr);
            result.send(Ok(())).unwrap();
        });

        session.remove_path(local_addr, remote_addr).await.unwrap();
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn session_handle_drains_path_events_from_driver() {
        let (session, mut commands) = driver_command_channel();
        let expected = vec![MpPathEvent::Down(PathKey {
            carrier_id: CarrierId(77),
            local_addr: "127.0.0.1:31022".parse().unwrap(),
            remote_addr: "127.0.0.1:32022".parse().unwrap(),
        })];
        let driver_expected = expected.clone();
        let driver = tokio::spawn(async move {
            let Some(DriverCommand::TakePathEvents { result }) = commands.recv().await else {
                panic!("missing take-path-events command");
            };
            result.send(driver_expected).unwrap();
        });

        assert_eq!(session.take_path_events().await.unwrap(), expected);
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn session_handle_forwards_runtime_scheduler_change() {
        let (session, mut commands) = driver_command_channel();
        let expected = MpQuicSessionConfig {
            algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
            lambda: 0.2,
            congestion_control: CongestionControlProfile::Cubic,
            brutal_bps: 0,
            brutal_disable_loss_compensation: false,
            establishment_timeout: std::time::Duration::from_secs(10),
            sqm_enabled: false,
            data_plane: false,
        };
        let driver = tokio::spawn(async move {
            let Some(DriverCommand::SetScheduler { runtime, result }) = commands.recv().await
            else {
                panic!("missing scheduler command");
            };
            assert_eq!(runtime, expected);
            result.send(Ok(())).unwrap();
        });

        session.set_scheduler(expected).await.unwrap();
        driver.await.unwrap();
    }

    fn spec(port: u16) -> (SocketAddr, SocketAddr) {
        (
            format!("127.0.0.1:{port}").parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        )
    }

    fn validated(idle_ms: u64) -> PathHealth {
        PathHealth::Validated {
            idle: std::time::Duration::from_millis(idle_ms),
        }
    }

    #[test]
    fn path_death_is_decided_by_time_not_by_pto_runs() {
        let paths = [(spec(1), validated(10)), (spec(2), validated(1_500))];
        assert!(paths_to_retire(&paths, PATH_IDLE_TIMEOUT).is_empty());

        let paths = [(spec(1), validated(10)), (spec(2), validated(46_000))];
        assert_eq!(paths_to_retire(&paths, PATH_IDLE_TIMEOUT), vec![spec(2)]);
    }

    #[test]
    fn the_last_usable_path_is_never_retired_for_silence() {
        let paths = [(spec(1), validated(60_000)), (spec(2), validated(90_000))];
        assert!(paths_to_retire(&paths, PATH_IDLE_TIMEOUT).is_empty());
        // Unvalidated paths do not count as usable.
        let paths = [(spec(1), validated(60_000)), (spec(2), PathHealth::Pending)];
        assert!(paths_to_retire(&paths, PATH_IDLE_TIMEOUT).is_empty());
    }

    fn opened(spec: (SocketAddr, SocketAddr), serial: u64) -> tquic::PathLifecycleEvent {
        tquic::PathLifecycleEvent::Opened {
            local: spec.0,
            remote: spec.1,
            serial,
        }
    }

    fn abandoned(
        spec: (SocketAddr, SocketAddr),
        serial: u64,
        by_peer: bool,
    ) -> tquic::PathLifecycleEvent {
        tquic::PathLifecycleEvent::Abandoned {
            local: spec.0,
            remote: spec.1,
            serial,
            scid_seq: None,
            dcid_seq: None,
            by_peer,
        }
    }

    fn discarded(spec: (SocketAddr, SocketAddr), serial: u64) -> tquic::PathLifecycleEvent {
        tquic::PathLifecycleEvent::Discarded {
            local: spec.0,
            remote: spec.1,
            serial,
            scid_seq: None,
            dcid_seq: None,
        }
    }

    #[test]
    fn paths_the_peer_abandoned_or_tquic_dropped_are_retired_once() {
        let specs = [spec(1), spec(2), spec(3)];
        let mut bound = BoundPaths::new();
        let events = [
            opened(spec(1), 0),
            opened(spec(2), 1),
            opened(spec(3), 2),
            abandoned(spec(2), 1, true),
            discarded(spec(2), 1),
            discarded(spec(3), 2),
        ];
        assert_eq!(
            specs_to_retire_for_events(&events, &specs, &mut bound),
            vec![spec(2), spec(3)]
        );
        assert_eq!(bound, BoundPaths::from([(spec(1), 0)]));
    }

    #[test]
    fn a_path_this_end_abandoned_is_not_reported_as_the_peers() {
        let specs = [spec(1), spec(2)];
        let mut bound = BoundPaths::from([(spec(1), 0), (spec(2), 1)]);
        let events = [abandoned(spec(2), 1, false), discarded(spec(2), 1)];
        assert!(specs_to_retire_for_events(&events, &specs, &mut bound).is_empty());
    }

    #[test]
    fn events_of_an_earlier_mount_never_retire_the_new_one() {
        // The 4-tuple was mounted again (spec 2 now unbound), and the events of
        // the old path arrive late, even after the new path opened.
        let specs = [spec(1), spec(2)];
        let mut bound = BoundPaths::from([(spec(1), 0)]);
        let late = [abandoned(spec(2), 1, true), discarded(spec(2), 1)];
        assert!(specs_to_retire_for_events(&late, &specs, &mut bound).is_empty());

        let events = [opened(spec(2), 5), abandoned(spec(2), 1, true), discarded(spec(2), 1)];
        assert!(specs_to_retire_for_events(&events, &specs, &mut bound).is_empty());
        assert_eq!(bound.get(&spec(2)), Some(&5));

        // The new path's own abandon does.
        let events = [abandoned(spec(2), 5, true)];
        assert_eq!(
            specs_to_retire_for_events(&events, &specs, &mut bound),
            vec![spec(2)]
        );
    }

    #[test]
    fn a_path_that_opened_and_went_away_between_two_looks_is_still_retired() {
        let specs = [spec(1), spec(2)];
        let mut bound = BoundPaths::from([(spec(1), 0)]);
        let events = [opened(spec(2), 3), abandoned(spec(2), 3, true), discarded(spec(2), 3)];
        assert_eq!(
            specs_to_retire_for_events(&events, &specs, &mut bound),
            vec![spec(2)]
        );
    }

    #[test]
    fn telemetry_mapping_converts_bbr_rates_to_bits_and_keeps_sample_fields() {
        let local = "127.0.0.1:31017".parse().unwrap();
        let remote = "127.0.0.1:32017".parse().unwrap();
        let stats = tquic::PathStats {
            bandwidth_model_valid: true,
            btlbw: 222_000_000,
            latest_delivery_rate: 210_000_000,
            delivery_rate_sample_app_limited: false,
            delivery_rate_sample_time_valid: true,
            delivery_rate_sample_age: 2_000,
            congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
            scheduler_target_rate_valid: true,
            scheduler_target_rate: 77_000_000,
            min_rtt: 12_000,
            windowed_min_rtt: 13_000,
            srtt: 15_000,
            sent_bytes: 30_000,
            recv_bytes: 20_000,
            lost_bytes: 2_400,
            lost_data_bytes: 1_000,
            max_inflight: 45_000,
            ..tquic::PathStats::default()
        };

        let telemetry =
            path_telemetry_from_stats(local, remote, tquic::PathState::Validated, &stats);

        // TQUIC's bandwidth model is bytes/sec; telemetry is bits/sec.
        assert_eq!(telemetry.btlbw, 1_776_000_000);
        assert_eq!(telemetry.delivery_rate, 1_680_000_000);
        assert_eq!(telemetry.sample_age_micros, Some(2_000));
        assert_eq!(
            telemetry.congestion_control_state,
            tquic::CongestionControlState::ProbeBandwidth
        );
        // 77_000_000 bytes/sec (TQUIC's convention) -> 616_000_000 bits/sec
        // (MpPathTelemetry's convention, MP_SQM_PLAN.md S2.4 review).
        assert_eq!(telemetry.scheduler_target_rate_bps, Some(616_000_000));
        assert_eq!(telemetry.min_rtt_micros, 12_000);
        assert_eq!(telemetry.windowed_min_rtt_micros, 13_000);
        assert_eq!(telemetry.srtt_micros, 15_000);
        // Lost PMTU probes (the other 1_400 lost bytes) are not path loss.
        assert_eq!(telemetry.lost_bytes, 1_000);
        assert_eq!(telemetry.max_inflight_bytes, 45_000);
    }

    #[test]
    fn tquic_cc_profile_mapping_preserves_bbr_default_and_exposes_real_algorithms() {
        assert_eq!(
            tquic_congestion_control(CongestionControlProfile::EngineDefault),
            tquic::CongestionControlAlgorithm::Bbr
        );
        assert_eq!(
            tquic_congestion_control(CongestionControlProfile::Cubic),
            tquic::CongestionControlAlgorithm::Cubic
        );
        assert_eq!(
            tquic_congestion_control(CongestionControlProfile::Bbr3),
            tquic::CongestionControlAlgorithm::Bbr3
        );
        assert_eq!(
            tquic_congestion_control(CongestionControlProfile::Copa),
            tquic::CongestionControlAlgorithm::Copa
        );
        assert_eq!(
            tquic_congestion_control(CongestionControlProfile::Brutal),
            tquic::CongestionControlAlgorithm::Brutal
        );
    }

    #[test]
    fn brutal_resolves_up_mbps_into_bytes_per_sec_and_disable_loss_compensation_from_params_json()
     {
        let mut config = crate::common::config::gen_default_mp_config();
        config.congestion_control = "brutal".into();
        config.congestion_control_params_json =
            r#"{"up_mbps": 20, "disable_loss_compensation": true}"#.into();

        let runtime =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap();

        assert_eq!(runtime.congestion_control, CongestionControlProfile::Brutal);
        // 20 Mbit/s -> 2_500_000 bytes/sec (TQUIC's brutal_bps convention).
        // Getting this backwards (treating up_mbps numerically as bytes/sec)
        // was a real review finding: it would pace at 8x the configured rate.
        assert_eq!(runtime.brutal_bps, 2_500_000);
        assert!(runtime.brutal_disable_loss_compensation);
    }

    #[test]
    fn brutal_without_up_mbps_sends_at_the_default_rate() {
        let mut config = crate::common::config::gen_default_mp_config();
        config.congestion_control = "brutal".into();
        config.congestion_control_params_json = "{}".into();

        let runtime =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap();
        // 50 Mbit/s -> 6_250_000 bytes/sec (TQUIC's brutal_bps convention).
        assert_eq!(runtime.brutal_bps, 6_250_000);

        config.congestion_control_params_json = r#"{"up_mbps": -3}"#.into();
        let error =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap_err();
        assert!(error.to_string().contains("up_mbps"), "{error}");
    }

    #[test]
    fn non_brutal_profiles_leave_brutal_params_at_zero() {
        let mut config = crate::common::config::gen_default_mp_config();
        config.congestion_control = "cubic".into();

        let runtime =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap();
        assert_eq!(runtime.brutal_bps, 0);
        assert!(!runtime.brutal_disable_loss_compensation);
    }

    #[test]
    fn client_and_server_accept_brutal_before_endpoint_creation() {
        let runtime = MpQuicSessionConfig {
            congestion_control: CongestionControlProfile::Brutal,
            brutal_bps: 5_000_000,
            ..Default::default()
        };
        let client = client_config(runtime).unwrap();
        let server = server_config(runtime).unwrap();
        drop((client, server));
    }

    #[test]
    fn standalone_mpquic_applies_cc_when_dynamic_mp_manager_is_disabled() {
        let base = MpQuicSessionConfig {
            algorithm: crate::tunnel::mp_plugin::MpAlgorithm::MinRtt,
            lambda: 0.25,
            ..Default::default()
        };
        let mut config = crate::common::config::gen_default_mp_config();
        config.enabled = false;
        config.packet_scheduler = "redundant".into();
        config.congestion_control = "cubic".into();
        config.establishment_timeout_ms = 27_000;

        let runtime = apply_standalone_transport_config(base, &config).unwrap();

        assert_eq!(runtime.congestion_control, CongestionControlProfile::Cubic);
        assert_eq!(
            runtime.establishment_timeout,
            std::time::Duration::from_secs(27)
        );
        assert_eq!(runtime.algorithm, base.algorithm);
        assert_eq!(runtime.lambda, base.lambda);
    }

    /// MP_SQM_PLAN.md S2.5 item 3c: `apply_congestion_control_from_mp_config`
    /// is the one function both the standalone and MP-managed session
    /// builders route through (`apply_standalone_transport_config` and
    /// `mp_session.rs::quic_config` respectively), so setting `sqm_enabled`
    /// here is what keeps both session kinds in sync with `MpConfig.sqm.
    /// enabled` without a second copy of this logic.
    #[test]
    fn apply_congestion_control_from_mp_config_propagates_sqm_enabled() {
        let mut config = crate::common::config::gen_default_mp_config();
        config.sqm = Some(crate::proto::common::MpSqmConfig {
            enabled: true,
            target_ms: 5,
            interval_ms: 100,
            ..Default::default()
        });
        let runtime =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap();
        assert!(runtime.sqm_enabled, "sqm.enabled=true must set runtime.sqm_enabled");

        config.sqm.as_mut().unwrap().enabled = false;
        let runtime =
            apply_congestion_control_from_mp_config(MpQuicSessionConfig::default(), &config)
                .unwrap();
        assert!(!runtime.sqm_enabled, "sqm.enabled=false must clear runtime.sqm_enabled");
    }

    /// MP_SQM_PLAN.md S2.5 item 3c: the SQM duplex buffer must be strictly
    /// smaller than the default, and the default path must be unaffected.
    #[test]
    fn duplex_buf_bytes_shrinks_only_when_sqm_is_enabled() {
        assert_eq!(duplex_buf_bytes(false), DUPLEX_BUF);
        assert!(duplex_buf_bytes(true) < DUPLEX_BUF);
    }

    #[test]
    fn client_and_server_accept_the_same_non_default_cc_before_endpoint_creation() {
        let runtime = MpQuicSessionConfig {
            congestion_control: CongestionControlProfile::Cubic,
            ..Default::default()
        };
        let client = client_config(runtime).unwrap();
        let server = server_config(runtime).unwrap();
        // Config deliberately has no public getter for recovery internals.
        // Construction through both factories proves the adapter calls the
        // concrete TQUIC setter before either endpoint factory consumes it;
        // the mapping above asserts the exact installed enum.
        drop((client, server));
    }

    #[test]
    fn mpquic_pingpong() {
        RUNTIME.block_on(async {
            let listener = MpQuicTunnelListener::new("mpquic://127.0.0.1:22011".parse().unwrap());
            let connector = MpQuicTunnelConnector::new("mpquic://127.0.0.1:22011".parse().unwrap());
            _tunnel_pingpong(listener, connector).await
        });
    }

    /// Grey-box: real Tokio runtime, real loopback UDP sockets and a real
    /// TQUIC client/server handshake. No mock socket, executor or transport is
    /// involved. Both the legacy-compatible default and a non-default CUBIC
    /// profile must preserve payload integrity over the actual QUIC stream.
    #[test]
    fn mpquic_loopback_udp_payload_sha_for_default_and_cubic() {
        RUNTIME.block_on(async {
            for (port, cc) in [
                (22041, CongestionControlProfile::EngineDefault),
                (22042, CongestionControlProfile::Cubic),
            ] {
                let runtime = MpQuicSessionConfig {
                    congestion_control: cc,
                    ..Default::default()
                };
                let url: url::Url = format!("mpquic://127.0.0.1:{port}").parse().unwrap();
                let mut listener = MpQuicTunnelListener::new_with_runtime(url.clone(), runtime);
                listener.listen().await.unwrap();
                let accept = tokio::spawn(async move {
                    let tunnel = listener.accept().await.unwrap();
                    let (mut recv, mut send) = tunnel.split();
                    let packet =
                        tokio::time::timeout(std::time::Duration::from_secs(5), recv.next())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    send.send(packet).await.unwrap();
                    send.flush().await.unwrap();
                });
                let mut connector = MpQuicTunnelConnector::new_with_runtime(url, runtime);
                let tunnel = connector.connect().await.unwrap();
                // ZCPacket itself has a bounded body; 1 KiB crosses the real
                // QUIC stream/framing path without violating that packet API.
                let payload = format!("real-loopback-{cc:?}-{}", "x".repeat(1024));
                let expected = Sha256::digest(payload.as_bytes());
                let (mut recv, mut send) = tunnel.split();
                send.send(ZCPacket::new_with_payload(payload.as_bytes()))
                    .await
                    .unwrap();
                let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(echoed.payload().len(), payload.len());
                assert_eq!(Sha256::digest(echoed.payload()), expected);
                accept.await.unwrap();
            }
        });
    }

    /// Grey-box: same shape as `mpquic_loopback_udp_payload_sha_for_default_
    /// and_cubic`, but for Brutal (MP_SQM_PLAN.md S2.4). Brutal's configured
    /// rate (well above the tiny test payload) must not stop it from actually
    /// carrying real bytes end to end over a real handshake.
    #[test]
    fn mpquic_loopback_udp_payload_sha_for_brutal() {
        RUNTIME.block_on(async {
            let runtime = MpQuicSessionConfig {
                congestion_control: CongestionControlProfile::Brutal,
                brutal_bps: 20_000_000,
                ..Default::default()
            };
            let url: url::Url = "mpquic://127.0.0.1:22043".parse().unwrap();
            let mut listener = MpQuicTunnelListener::new_with_runtime(url.clone(), runtime);
            listener.listen().await.unwrap();
            let accept = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, mut send) = tunnel.split();
                let packet = tokio::time::timeout(std::time::Duration::from_secs(5), recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                send.send(packet).await.unwrap();
                send.flush().await.unwrap();
            });
            let mut connector = MpQuicTunnelConnector::new_with_runtime(url, runtime);
            let tunnel = connector.connect().await.unwrap();
            let payload = format!("real-loopback-brutal-{}", "x".repeat(1024));
            let expected = Sha256::digest(payload.as_bytes());
            let (mut recv, mut send) = tunnel.split();
            send.send(ZCPacket::new_with_payload(payload.as_bytes()))
                .await
                .unwrap();
            let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(echoed.payload().len(), payload.len());
            assert_eq!(Sha256::digest(echoed.payload()), expected);
            accept.await.unwrap();
        });
    }

    /// One attempt of the goodput measurement below: a real loopback UDP
    /// handshake, then a discarded warm-up followed by a measured, saturated
    /// one-way transfer under Brutal, returning the achieved bits/sec. Each
    /// attempt binds its own port so a retry never races a not-yet-released
    /// socket from a prior attempt.
    async fn measure_brutal_loopback_goodput_bps(port: u16, up_mbps: f64) -> f64 {
        let runtime = MpQuicSessionConfig {
            congestion_control: CongestionControlProfile::Brutal,
            brutal_bps: crate::tunnel::mp_plugin::brutal_mbps_to_bytes_per_sec(up_mbps),
            ..Default::default()
        };
        let url: url::Url = format!("mpquic://127.0.0.1:{port}").parse().unwrap();
        let mut listener = MpQuicTunnelListener::new_with_runtime(url.clone(), runtime);
        listener.listen().await.unwrap();

        let received_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let received_bytes_reader = received_bytes.clone();
        let accept = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            let (mut recv, _send) = tunnel.split();
            while let Some(Ok(packet)) = recv.next().await {
                received_bytes_reader.fetch_add(
                    packet.payload().len() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        });

        let mut connector = MpQuicTunnelConnector::new_with_runtime(url, runtime);
        let tunnel = connector.connect().await.unwrap();
        let (_recv, mut send) = tunnel.split();

        let payload = vec![0u8; 1200];
        // Discard an unmeasured warm-up: the first stretch is dominated by
        // handshake/pipe/stream ramp-up overhead, not by Brutal's
        // steady-state pacing, so averaging it into the measurement window
        // makes the assertion measure ramp-up speed instead of the
        // configured rate (empirically: bucketed samples taken every ~3.5s
        // showed ~6.4 Mbit/s for the first bucket including t=0, then
        // ~7.0-7.1 Mbit/s for every bucket after -- i.e. steady state is
        // reached well within 3s).
        //
        // MP_SQM_PLAN.md S2.5 batch 4 shrank this to 2s warmup / 4s window
        // (down from 5s/8s) on the theory that once this test was `#[ignore]
        // `d and moved to a dedicated serial gate step, it no longer needed
        // margin for `--test-threads=4` contention. That theory had two
        // holes, found during the S2.5-batch-4 regression investigation
        // (`.88`, 2026-09-29, A/B against 45d1454 with per-phase `eprintln!`
        // timing -- see PROJECT_journal.md): (1) this host has real
        // scheduling jitter (multi-second `feed()` stalls) even with this
        // test running completely alone, not just under
        // `--test-threads=4` -- the shrunk 4s window has much less room to
        // average that out than the old 8s one did, so the *same* absolute
        // jitter now eats a much bigger fraction of the measured average;
        // (2) 2s of warm-up is *less* than the "well within 3s" ramp-up time
        // documented right above, not "comfortably past" it as the removed
        // comment claimed -- an arithmetic mistake, not a new finding -- so
        // the 4s window could start averaging before the connection had
        // actually reached steady state. Restored to the original 5s/8s:
        // proven margin against both, confirmed by the same A/B (3/3 runs
        // comfortably within tolerance at 5s/8s vs. one outright failure and
        // two barely-passing runs at 2s/4s on an otherwise idle machine).
        // None of S2.5's actual SQM/autorate/duplex-buffer changes are
        // implicated: this test's session never has SQM enabled
        // (`MpQuicSessionConfig::default()` -> `sqm_enabled: false`), so
        // none of those gated changes apply to it.
        let warmup = std::time::Duration::from_secs(5);
        let warmup_start = std::time::Instant::now();
        while warmup_start.elapsed() < warmup {
            send.feed(ZCPacket::new_with_payload(&payload)).await.unwrap();
        }
        let bytes_before = received_bytes.load(std::sync::atomic::Ordering::Relaxed);

        let duration = std::time::Duration::from_secs(8);
        let start = std::time::Instant::now();
        while start.elapsed() < duration {
            send.feed(ZCPacket::new_with_payload(&payload)).await.unwrap();
        }
        let elapsed = start.elapsed();
        send.close().await.unwrap();
        accept.await.unwrap();

        let bytes_after = received_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let measured_bytes = bytes_after.saturating_sub(bytes_before);
        (measured_bytes as f64 * 8.0) / elapsed.as_secs_f64()
    }

    /// Grey-box goodput assertion (MP_SQM_PLAN.md S2.4 review item 5): a real
    /// loopback UDP handshake, saturated one-way transfer under Brutal
    /// configured for a modest 8 Mbit/s, must deliver goodput within +/-15%
    /// of that target. This is the test that actually catches the Mbit/s-vs-
    /// bytes/sec conversion bug (item 2): getting it backwards paces at 8x
    /// the target, landing far outside this window either way (measuring
    /// ~1 Mbit/s if the GUI's `up_mbps` were misread as bytes/sec, or ~64
    /// Mbit/s if bytes/sec were misread as Mbit/s), not just a slightly
    /// wrong number the tolerance might absorb.
    ///
    /// `#[ignore]`d and run serially by the gate's dedicated second step
    /// (MP_SQM_PLAN.md S2.5: `cargo test ... -- --ignored goodput
    /// --test-threads=1`), not in the default `--test-threads=4` run: this is
    /// a real-time wall-clock measurement, and sharing a CPU with three other
    /// concurrent test threads was observed empirically to drag an otherwise
    /// correct run below the tolerance band. Up to 3 attempts (restored from
    /// a 2-attempt/2s-warmup/4s-window batch-4 shrink that turned out to be
    /// too tight for this host's own baseline scheduling jitter even running
    /// alone -- see the root-cause comment on `measure_brutal_loopback_
    /// goodput_bps`'s warm-up): a units bug (the thing this test exists to
    /// catch) is off by a fixed 8x factor and fails identically every
    /// attempt regardless of window size; transient scheduler jitter does
    /// not, and 3 attempts against an 8s window is the config this test ran
    /// with, reliably, for all of S2.1 through S2.4.
    #[test]
    #[ignore = "timing-sensitive; run serially via gate step 2"]
    fn mpquic_loopback_udp_brutal_goodput_tracks_configured_up_mbps() {
        RUNTIME.block_on(async {
            let up_mbps = 8.0;
            let target_bps = up_mbps * 1_000_000.0;
            let mut last_achieved = 0.0;
            for attempt in 0..3 {
                let port = 22044 + attempt;
                last_achieved = measure_brutal_loopback_goodput_bps(port, up_mbps).await;
                if last_achieved >= target_bps * 0.85 && last_achieved <= target_bps * 1.15 {
                    return;
                }
            }
            panic!(
                "achieved {last_achieved:.0} bps not within +/-15% of target {target_bps:.0} bps \
                 (up_mbps={up_mbps}) after 3 attempts"
            );
        });
    }

    #[test]
    fn mpquic_accept_reports_remote_addr() {
        RUNTIME.block_on(async {
            let mut listener =
                MpQuicTunnelListener::new("mpquic://127.0.0.1:22015".parse().unwrap());
            listener.listen().await.unwrap();

            let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
            let mut connector =
                MpQuicTunnelConnector::new("mpquic://127.0.0.1:22015".parse().unwrap());
            let client = connector.connect().await.unwrap();
            let (_client_recv, mut client_send) = client.split();
            client_send
                .send(ZCPacket::new_with_payload(b"open server stream"))
                .await
                .unwrap();
            let server = tokio::time::timeout(std::time::Duration::from_secs(5), accepted)
                .await
                .unwrap()
                .unwrap();

            let info = server.info().expect("accepted MPQUIC tunnel info");
            assert!(
                info.remote_addr.is_some(),
                "accepted MPQUIC tunnel must report its peer address"
            );
            assert!(
                info.resolved_remote_addr.is_some(),
                "accepted MPQUIC tunnel must report its resolved peer address"
            );
            drop(server);
        });
    }

    #[test]
    fn mpquic_bench() {
        RUNTIME.block_on(async {
            let listener = MpQuicTunnelListener::new("mpquic://127.0.0.1:22012".parse().unwrap());
            let connector = MpQuicTunnelConnector::new("mpquic://127.0.0.1:22012".parse().unwrap());
            _tunnel_bench(listener, connector).await
        });
    }

    async fn real_udp_path_pair() -> (
        Arc<dyn MpDatagramPath>,
        SocketAddr,
        Arc<dyn MpDatagramPath>,
        SocketAddr,
    ) {
        let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        // Production MP listeners and ordinary UDP carriers use recv_from /
        // send_to. Keeping the test unconnected also avoids turning an ICMP
        // response from a transient validation packet into a terminal recv
        // error for an otherwise healthy carrier.
        let client_path: Arc<dyn MpDatagramPath> = Arc::new(
            SharedUnconnectedUdpDatagramPath::new_with_guard(client_socket, None).unwrap(),
        );
        let server_path: Arc<dyn MpDatagramPath> = Arc::new(
            SharedUnconnectedUdpDatagramPath::new_with_guard(server_socket, None).unwrap(),
        );
        (client_path, client_addr, server_path, server_addr)
    }

    async fn wait_for_two_validated_paths(session: &MpSessionHandle) -> Vec<MpPathTelemetry> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let paths = session.path_telemetry().await.unwrap();
                if paths.len() == 2
                    && paths
                        .iter()
                        .all(|path| path.validation_state == tquic::PathState::Validated)
                {
                    break paths;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both real UDP paths must validate")
    }

    /// Grey-box N=2 proof: two independent pairs of real loopback UDP sockets
    /// carry one TQUIC connection. The second carrier is registered through the
    /// same dynamic `add_path` API used by direct and hole-punch providers. A
    /// real round-robin scheduler must transmit substantial post-validation
    /// traffic on both paths while the reliable QUIC stream preserves every
    /// EasyTier packet byte-for-byte. No mock socket or executor participates.
    #[test]
    fn mpquic_real_udp_two_path_payload_and_telemetry() {
        RUNTIME.block_on(async {
            let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
                real_udp_path_pair().await;
            let (client_secondary, client_secondary_addr, server_secondary, server_secondary_addr) =
                real_udp_path_pair().await;
            let (client_primary_again, server_primary_again) =
                (client_primary.clone(), server_primary.clone());
            let runtime = MpQuicSessionConfig {
                algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
                ..Default::default()
            };
            let client_remote_url: url::Url =
                format!("mpquic://{server_primary_addr}").parse().unwrap();
            let server_remote_url: url::Url =
                format!("mpquic://{client_primary_addr}").parse().unwrap();

            let server_task = tokio::spawn(async move {
                session_from_datagram_paths_with_config(
                    true,
                    vec![(server_primary, None)],
                    client_primary_addr,
                    server_remote_url,
                    "mpquic",
                    runtime,
                    EgressQualityManager::new(EgressQualityConfig::default()),
                    None,
                )
                .await
            });
            let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
                false,
                vec![(client_primary, None)],
                server_primary_addr,
                client_remote_url,
                "mpquic",
                runtime,
                EgressQualityManager::new(EgressQualityConfig::default()),
                None,
            )
            .await
            .unwrap();
            let (mut client_recv, mut client_send) = client_tunnel.split();

            // A server-side TQUIC stream is created only after the client puts
            // actual stream data on the wire. This mirrors the listener's real
            // accept semantics and also proves the primary carrier before N=2.
            let bootstrap = b"real-udp-primary-bootstrap";
            client_send
                .send(ZCPacket::new_with_payload(bootstrap))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
            let (mut server_recv, mut server_send) = server_tunnel.split();
            let bootstrap_packet =
                tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(bootstrap_packet.payload(), bootstrap);
            server_send.send(bootstrap_packet).await.unwrap();
            server_send.flush().await.unwrap();
            let bootstrap_echo =
                tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(bootstrap_echo.payload(), bootstrap);

            // The offer that lost a simultaneous open re-offers the session's
            // own path: accepted as the path it already is, not a failure.
            server_handle
                .add_path(server_primary_again, client_primary_addr, None)
                .await
                .expect("re-offering the session's own path is not an error");
            client_handle
                .add_path(client_primary_again, server_primary_addr, None)
                .await
                .expect("re-offering the session's own path is not an error");

            // The server must arm its carrier before the client emits the
            // PATH_CHALLENGE for the new address pair.
            server_handle
                .add_path(server_secondary, client_secondary_addr, None)
                .await
                .unwrap();
            client_handle
                .add_path(client_secondary, server_secondary_addr, None)
                .await
                .unwrap();

            wait_for_two_validated_paths(&server_handle).await;
            let baseline = wait_for_two_validated_paths(&client_handle)
                .await
                .into_iter()
                .map(|path| (path.local_addr, path.sent_bytes))
                .collect::<HashMap<_, _>>();

            const PACKETS: usize = 128;
            let expected_payloads = (0..PACKETS)
                .map(|sequence| {
                    format!("n2-real-udp-{sequence:04}-{}", "x".repeat(900)).into_bytes()
                })
                .collect::<Vec<_>>();
            let (release_echo, keep_echo_alive) = oneshot::channel();
            let echo = tokio::spawn(async move {
                for _ in 0..PACKETS {
                    let packet =
                        tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    server_send.send(packet).await.unwrap();
                }
                server_send.flush().await.unwrap();
                // Retain both server tunnel halves until the client has taken
                // its final path snapshot. Dropping them here would correctly
                // send FIN and race the telemetry command against driver exit.
                let _ = keep_echo_alive.await;
            });

            for payload in &expected_payloads {
                client_send
                    .send(ZCPacket::new_with_payload(payload))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();
            for expected in &expected_payloads {
                let echoed =
                    tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                assert_eq!(echoed.payload().len(), expected.len());
                assert_eq!(Sha256::digest(echoed.payload()), Sha256::digest(expected));
            }
            let traffic = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let paths = client_handle.path_telemetry().await.unwrap();
                    let deltas = paths
                        .iter()
                        .map(|path| {
                            path.sent_bytes.saturating_sub(
                                baseline.get(&path.local_addr).copied().unwrap_or_default(),
                            )
                        })
                        .collect::<Vec<_>>();
                    if paths.len() == 2 && deltas.iter().all(|delta| *delta > 8 * 1024) {
                        break (paths, deltas);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("round-robin must carry post-validation traffic on both UDP paths");
            eprintln!(
                "N=2 real UDP validated: primary={client_primary_addr}, secondary={client_secondary_addr}, sent_byte_deltas={:?}",
                traffic.1
            );
            assert_eq!(traffic.0.len(), 2);
            assert!(traffic.0.iter().all(|path| {
                path.validation_state == tquic::PathState::Validated
                    && (path.local_addr == client_primary_addr
                        || path.local_addr == client_secondary_addr)
            }));

            let _ = release_echo.send(());
            echo.await.unwrap();
            client_handle.shutdown();
            server_handle.shutdown();
        });
    }
    /// A datagram carrier whose traffic can be switched off in both
    /// directions, to black-hole one path of a session.
    struct SwitchedPath {
        inner: Arc<dyn MpDatagramPath>,
        dark: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for SwitchedPath {
        fn local_addr(&self) -> SocketAddr {
            self.inner.local_addr()
        }

        fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
            if self.dark.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(payload.len());
            }
            self.inner.try_send_to(payload, remote)
        }

        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            loop {
                let received = self.inner.recv_from(buf).await?;
                if !self.dark.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok(received);
                }
            }
        }
    }

    /// A connected client/server session over one real loopback path pair,
    /// with the echo of one packet proving it.
    struct LivePair {
        _client_tunnel: Box<dyn Tunnel>,
        _server_tunnel: Box<dyn Tunnel>,
        client_recv: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>,
        client_send: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>,
        server_recv: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>,
        server_send: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>,
        client_handle: MpSessionHandle,
        server_handle: MpSessionHandle,
    }

    async fn live_pair() -> LivePair {
        live_pair_with(|client_primary| client_primary).await
    }

    async fn live_pair_with(
        wrap_client: impl FnOnce(Arc<dyn MpDatagramPath>) -> Arc<dyn MpDatagramPath>,
    ) -> LivePair {
        let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
            real_udp_path_pair().await;
        let client_primary = wrap_client(client_primary);
        let runtime = MpQuicSessionConfig {
            algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
            ..Default::default()
        };
        let client_remote_url: url::Url =
            format!("mpquic://{server_primary_addr}").parse().unwrap();
        let server_remote_url: url::Url =
            format!("mpquic://{client_primary_addr}").parse().unwrap();
        let server_task = tokio::spawn(async move {
            session_from_datagram_paths_with_config(
                true,
                vec![(server_primary, None)],
                client_primary_addr,
                server_remote_url,
                "mpquic",
                runtime,
                EgressQualityManager::new(EgressQualityConfig::default()),
                None,
            )
            .await
        });
        let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
            false,
            vec![(client_primary, None)],
            server_primary_addr,
            client_remote_url,
            "mpquic",
            runtime,
            EgressQualityManager::new(EgressQualityConfig::default()),
            None,
        )
        .await
        .unwrap();
        let (mut client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(b"live-pair-bootstrap"))
            .await
            .unwrap();
        client_send.flush().await.unwrap();
        let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
        let (mut server_recv, mut server_send) = server_tunnel.split();
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_send.send(first).await.unwrap();
        server_send.flush().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        LivePair {
            _client_tunnel: client_tunnel,
            _server_tunnel: server_tunnel,
            client_recv,
            client_send,
            server_recv,
            server_send,
            client_handle,
            server_handle,
        }
    }

    /// Mount one more real loopback path pair on both ends (server first, so
    /// its carrier is armed before the client's PATH_CHALLENGE).
    async fn mount_pair(
        pair: &LivePair,
        wrap: impl Fn(Arc<dyn MpDatagramPath>) -> Arc<dyn MpDatagramPath>,
    ) -> (SocketAddr, SocketAddr, Result<(), TunnelError>) {
        let (client_path, client_addr, server_path, server_addr) = real_udp_path_pair().await;
        pair.server_handle
            .add_path(wrap(server_path), client_addr, None)
            .await
            .unwrap();
        let result = pair
            .client_handle
            .add_path(wrap(client_path), server_addr, None)
            .await;
        (client_addr, server_addr, result)
    }

    /// A datagram carrier whose receive side fails on demand, like a socket
    /// whose interface went away.
    struct BreakableReceivePath {
        inner: Arc<dyn MpDatagramPath>,
        broken: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for BreakableReceivePath {
        fn local_addr(&self) -> SocketAddr {
            self.inner.local_addr()
        }

        fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
            self.inner.try_send_to(payload, remote)
        }

        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            tokio::select! {
                received = self.inner.recv_from(buf) => received,
                _ = self.broken.notified() => Err(std::io::Error::other("interface gone")),
            }
        }
    }

    #[test]
    fn last_path_grace_is_three_probe_timeouts_but_at_least_a_second() {
        assert_eq!(last_path_grace(0), std::time::Duration::from_secs(1));
        assert_eq!(last_path_grace(50_000), std::time::Duration::from_secs(1));
        // srtt 200 ms: pto 600 ms, three of them
        assert_eq!(
            last_path_grace(200_000),
            std::time::Duration::from_micros(1_800_000)
        );
    }

    #[test]
    fn a_failure_takes_the_last_path_only_when_nothing_else_is_left() {
        let a: (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
        let b: (SocketAddr, SocketAddr) = ("127.0.0.1:3".parse().unwrap(), "127.0.0.1:4".parse().unwrap());
        assert!(failure_takes_last_path(&[a], &[a]));
        assert!(failure_takes_last_path(&[a, b], &[b, a]));
        assert!(!failure_takes_last_path(&[a, b], &[a]));
        assert!(!failure_takes_last_path(&[], &[a]));
    }

    /// S-I18: the only path's socket failing does not close the session at
    /// once. The path is reported down so a replacement is asked for, and a
    /// replacement that validates inside the grace period keeps the session
    /// and its data flowing.
    #[test]
    fn mpquic_last_path_failure_waits_for_a_replacement_path() {
        RUNTIME.block_on(async {
            let broken = Arc::new(tokio::sync::Notify::new());
            let wrap_broken = broken.clone();
            let mut pair = live_pair_with(move |inner| {
                Arc::new(BreakableReceivePath { inner, broken: wrap_broken })
            })
            .await;
            broken.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let events = pair.client_handle.take_path_events().await.unwrap();
            assert!(
                events.iter().any(|event| matches!(event, MpPathEvent::Down(_))),
                "the failed last path is reported down: {events:?}"
            );
            // still open: nothing arrives, and nothing says it ended
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), pair.client_recv.next())
                    .await
                    .is_err()
            );
            let (_, _, added) = mount_pair(&pair, |path| path).await;
            added.unwrap();
            // past the grace period the replacement keeps it alive
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            pair.client_send
                .send(ZCPacket::new_with_payload(b"after-replacement"))
                .await
                .unwrap();
            pair.client_send.flush().await.unwrap();
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), pair.server_recv.next())
                .await
                .expect("the replacement path carries data")
                .unwrap()
                .unwrap();
            assert_eq!(got.payload(), b"after-replacement");
        });
    }

    /// S-I18: with no replacement inside the grace period the session closes
    /// with NO_VIABLE_PATH instead of waiting for the idle timeout.
    #[test]
    fn mpquic_last_path_failure_closes_when_no_replacement_comes() {
        RUNTIME.block_on(async {
            let broken = Arc::new(tokio::sync::Notify::new());
            let wrap_broken = broken.clone();
            let mut pair = live_pair_with(move |inner| {
                Arc::new(BreakableReceivePath { inner, broken: wrap_broken })
            })
            .await;
            broken.notify_waiters();
            let ended = tokio::time::timeout(std::time::Duration::from_secs(6), async {
                loop {
                    match pair.client_recv.next().await {
                        None | Some(Err(_)) => break,
                        Some(Ok(_)) => {}
                    }
                }
            })
            .await;
            assert!(ended.is_ok(), "the session outlived its grace period");
        });
    }

    /// F4 (a): an `add_path` TQUIC refuses leaves no trace in the path list
    /// and raises no path event.
    #[test]
    fn mpquic_refused_add_path_leaves_no_phantom_path() {
        RUNTIME.block_on(async {
            let pair = live_pair().await;
            // The connection holds as many paths as connection IDs it allows.
            let mut mounted = Vec::new();
            let mut refused = None;
            for _ in 0..MP_ACTIVE_CONNECTION_ID_LIMIT {
                let (client_addr, _, result) = mount_pair(&pair, |path| path).await;
                match result {
                    Ok(()) => mounted.push(client_addr),
                    Err(error) => {
                        // P4-C: the refusal is recognisable, so the caller can
                        // queue the open instead of giving the path up.
                        assert!(is_no_free_path_slot(&error), "{error:?}");
                        refused = Some(client_addr);
                        break;
                    }
                }
                // Let the path validate so it holds its connection ID.
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        let paths = pair.client_handle.path_telemetry().await.unwrap();
                        if paths.len() == mounted.len() + 1
                            && paths
                                .iter()
                                .all(|path| path.validation_state == tquic::PathState::Validated)
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("a mounted path validates");
            }
            let refused = refused.expect("the connection must run out of path slots");

            // The next driver ticks go by; the refused path never shows up.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let paths = pair.client_handle.path_telemetry().await.unwrap();
            assert_eq!(paths.len(), mounted.len() + 1);
            assert!(paths.iter().all(|path| path.local_addr != refused));
            assert!(pair.client_handle.take_path_events().await.unwrap().is_empty());
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }

    /// noq `ClosePathError::LastOpenPath`: removing the session's only path is
    /// refused and the path stays usable.
    #[test]
    fn mpquic_remove_path_keeps_the_last_open_path() {
        RUNTIME.block_on(async {
            let mut pair = live_pair().await;
            let paths = pair.client_handle.path_telemetry().await.unwrap();
            assert_eq!(paths.len(), 1);
            let (local, remote) = (paths[0].local_addr, paths[0].remote_addr);

            let error = pair
                .client_handle
                .remove_path(local, remote)
                .await
                .expect_err("the only path of the session must not be removed");
            assert!(is_last_open_path(&error), "{error:?}");

            // The path is still there, not abandoned: it carries data.
            let paths = pair.client_handle.path_telemetry().await.unwrap();
            assert_eq!(paths.len(), 1);
            assert!(pair.client_handle.take_path_events().await.unwrap().is_empty());
            pair.client_send
                .send(ZCPacket::new_with_payload(b"after-refused-removal"))
                .await
                .unwrap();
            pair.client_send.flush().await.unwrap();
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), pair.server_recv.next())
                .await
                .expect("the kept path carries data")
                .unwrap()
                .unwrap();
            assert_eq!(got.payload(), b"after-refused-removal");
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }

    /// The session's validated path is its last open one even while another
    /// path sits in the list unanswered; the unanswered one can go any time.
    #[test]
    fn mpquic_remove_path_counts_only_validated_paths() {
        RUNTIME.block_on(async {
            let pair = live_pair().await;
            let first = pair.client_handle.path_telemetry().await.unwrap();
            let (p0_local, p0_remote) = (first[0].local_addr, first[0].remote_addr);
            // P1: the client offers it, nobody on the server side answers.
            let (client_path, p1_local, _server_path, p1_remote) = real_udp_path_pair().await;
            let _ = pair.client_handle.add_path(client_path, p1_remote, None).await;
            let paths = pair.client_handle.path_telemetry().await.unwrap();
            assert_eq!(paths.len(), 2);
            assert!(
                paths
                    .iter()
                    .any(|path| path.local_addr == p1_local
                        && path.validation_state != tquic::PathState::Validated)
            );

            let error = pair
                .client_handle
                .remove_path(p0_local, p0_remote)
                .await
                .expect_err("the only validated path must stay");
            assert!(is_last_open_path(&error), "{error:?}");
            pair.client_handle
                .remove_path(p1_local, p1_remote)
                .await
                .expect("an unanswered path can always be removed");
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }

    /// With two paths one can be removed; the one left is then the last.
    #[test]
    fn mpquic_remove_path_refuses_only_the_remaining_path() {
        RUNTIME.block_on(async {
            let pair = live_pair().await;
            let first = pair.client_handle.path_telemetry().await.unwrap();
            let (first_local, first_remote) = (first[0].local_addr, first[0].remote_addr);
            let (client_addr, server_addr, result) = mount_pair(&pair, |path| path).await;
            result.unwrap();
            wait_for_two_validated_paths(&pair.client_handle).await;
            wait_for_two_validated_paths(&pair.server_handle).await;

            pair.client_handle
                .remove_path(client_addr, server_addr)
                .await
                .expect("one of two paths can be removed");
            let error = pair
                .client_handle
                .remove_path(first_local, first_remote)
                .await
                .expect_err("the path left is the last one");
            assert!(is_last_open_path(&error), "{error:?}");
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }

    /// F4 (b): a path the peer abandoned is retired once: it leaves the path
    /// list and raises exactly one `Down`.
    #[test]
    fn mpquic_peer_abandoned_path_goes_down_exactly_once() {
        RUNTIME.block_on(async {
            let pair = live_pair().await;
            let (client_addr, server_addr, result) = mount_pair(&pair, |path| path).await;
            result.unwrap();
            wait_for_two_validated_paths(&pair.client_handle).await;
            wait_for_two_validated_paths(&pair.server_handle).await;

            pair.client_handle
                .remove_path(client_addr, server_addr)
                .await
                .unwrap();

            let mut downs = Vec::new();
            let gone = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    downs.extend(pair.server_handle.take_path_events().await.unwrap());
                    let paths = pair.server_handle.path_telemetry().await.unwrap();
                    if paths.len() == 1 && !downs.is_empty() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
            assert!(gone.is_ok(), "the server must retire the abandoned path");

            // Long enough for the path to have drained and been dropped inside
            // TQUIC: nothing more is reported.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            downs.extend(pair.server_handle.take_path_events().await.unwrap());
            assert_eq!(downs.len(), 1, "{downs:?}");
            let MpPathEvent::Down(key) = &downs[0];
            assert_eq!((key.local_addr, key.remote_addr), (server_addr, client_addr));
            let paths = pair.server_handle.path_telemetry().await.unwrap();
            assert_eq!(paths.len(), 1);
            assert!(paths.iter().all(|path| path.local_addr != server_addr));
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }

    /// Defect 25 at session level: one of two real paths goes dark in the
    /// middle of a reliable transfer. The transfer finishes over the other
    /// path in seconds, not after the idle timeout, and the dark path is
    /// still there (only time retires it).
    #[test]
    fn mpquic_black_holed_path_does_not_hold_up_the_transfer() {
        RUNTIME.block_on(async {
            let mut pair = live_pair().await;
            let dark = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let switch = dark.clone();
            let (client_addr, _, result) = mount_pair(&pair, move |inner| {
                Arc::new(SwitchedPath {
                    inner,
                    dark: switch.clone(),
                })
            })
            .await;
            result.unwrap();
            wait_for_two_validated_paths(&pair.client_handle).await;
            wait_for_two_validated_paths(&pair.server_handle).await;

            const PACKETS: usize = 1500;
            const SIZE: usize = 1200;
            let mut client_send = pair.client_send;
            let sender = tokio::spawn(async move {
                for i in 0..PACKETS {
                    client_send
                        .send(ZCPacket::new_with_payload(&[(i % 251) as u8; SIZE]))
                        .await
                        .unwrap();
                }
                client_send.flush().await.unwrap();
                client_send
            });

            let mut received = 0usize;
            let mut dark_since = None;
            while received < PACKETS {
                let packet = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    pair.server_recv.next(),
                )
                .await
                .expect("the transfer stalled behind the black-holed path")
                .unwrap()
                .unwrap();
                assert_eq!(packet.payload().len(), SIZE);
                received += 1;
                if received == 100 && dark_since.is_none() {
                    // The path carries data when it goes dark.
                    let paths = pair.client_handle.path_telemetry().await.unwrap();
                    let carried = paths
                        .iter()
                        .find(|path| path.local_addr == client_addr)
                        .map_or(0, |path| path.sent_bytes);
                    assert!(carried > 8 * 1024, "{carried}");
                    dark.store(true, std::sync::atomic::Ordering::Relaxed);
                    dark_since = Some(std::time::Instant::now());
                }
            }
            let took = dark_since.unwrap().elapsed();
            assert!(took < std::time::Duration::from_secs(5), "{took:?}");

            // Not retired: far below the idle timeout.
            let paths = pair.client_handle.path_telemetry().await.unwrap();
            assert!(paths.iter().any(|path| path.local_addr == client_addr));
            assert!(pair.client_handle.take_path_events().await.unwrap().is_empty());
            let _client_send = sender.await.unwrap();
            pair.client_handle.shutdown();
            pair.server_handle.shutdown();
        });
    }


    /// Reliable data-plane streams stay byte-exact while one of two paths
    /// keeps blacking out (back-off, resume): every frame that arrives
    /// arrives once, intact and in per-flow order, both ways at once
    /// (2026-10-09: quinn of ET's QUIC proxy saw duplicated packets and
    /// "unsent packet acked" over a live LAN + relay session, and uploads
    /// stalled). The only frames missing are the ones the sender's stream
    /// queues dropped on purpose (COBALT on queueing time, CAKE_SQM_PLAN.md
    /// B5), and the sender counts every one of them.
    #[test]
    fn mpquic_data_plane_streams_stay_exact_while_a_path_flaps() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        const FRAMES: u32 = 20_000;
        const SIZE: usize = 1200;
        const BUCKETS: u32 = 4;

        fn frame(seq: u32) -> Vec<u8> {
            let mut body = seq.to_be_bytes().to_vec();
            body.extend((0..SIZE - 4).map(|i| {
                (seq.wrapping_mul(2_654_435_761).wrapping_add(i as u32 * 40_503) >> 7) as u8
            }));
            body
        }

        async fn pump(
            mut send: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>,
            label: &'static str,
        ) -> Result<std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>, String> {
            for seq in 0..FRAMES {
                send.send(tagged_packet(&frame(seq), TrafficClass::Tcp, (seq % BUCKETS) as u8))
                    .await
                    .map_err(|e| format!("{label}: send {seq}: {e:?}"))?;
            }
            send.flush().await.map_err(|e| format!("{label}: flush: {e:?}"))?;
            Ok(send)
        }

        /// Reads until the stream has been quiet for 4 s; returns how many
        /// distinct frames arrived.
        async fn drain(
            recv: &mut std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>,
            label: &'static str,
        ) -> Result<usize, String> {
            // Keeps reading after a bad frame: a reader that stops would
            // block the peer's driver on a full pipe and stall the other
            // direction too.
            let mut seen = std::collections::HashSet::new();
            let mut last = [None::<u32>; BUCKETS as usize];
            let mut first_error = None;
            while seen.len() < FRAMES as usize {
                let Ok(packet) =
                    tokio::time::timeout(std::time::Duration::from_secs(4), recv.next()).await
                else {
                    break;
                };
                let packet = packet
                    .ok_or_else(|| format!("{label}: stream ended"))?
                    .map_err(|e| format!("{label}: {e:?}"))?;
                let body = packet.payload();
                if body.len() < 4 {
                    continue; // bootstrap/echo traffic
                }
                let seq = u32::from_be_bytes(body[..4].try_into().unwrap());
                let bucket = (seq % BUCKETS) as usize;
                let error = if body != frame(seq).as_slice() {
                    Some(format!("{label}: frame {seq} corrupted (len {})", body.len()))
                } else if !seen.insert(seq) {
                    Some(format!("{label}: frame {seq} delivered twice"))
                } else if last[bucket].is_some_and(|prev| prev > seq) {
                    Some(format!("{label}: bucket {bucket} reordered {:?} -> {seq}", last[bucket]))
                } else {
                    last[bucket] = Some(seq);
                    None
                };
                first_error = first_error.or(error);
            }
            first_error.map_or(Ok(seen.len()), Err)
        }

        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                reliable_stream_idle_ms: 200,
                ..Default::default()
            });
            let base = MpQuicSessionConfig {
                algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
                ..Default::default()
            };
            let ((mut server_recv, server_send), server_handle, (mut client_recv, client_send), client_handle) =
                dp_session_pair_over(real_udp_path_pair().await, base, Some(policy.clone()), Some(policy))
                    .await;
            wait_negotiated(&server_handle, "datagram").await;
            wait_negotiated(&client_handle, "datagram").await;

            let dark = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let switched = |inner| -> Arc<dyn MpDatagramPath> {
                Arc::new(SwitchedPath { inner, dark: dark.clone() })
            };
            let (client_path, client_addr, server_path, server_addr) = real_udp_path_pair().await;
            server_handle
                .add_path(switched(server_path), client_addr, None)
                .await
                .unwrap();
            client_handle
                .add_path(switched(client_path), server_addr, None)
                .await
                .unwrap();
            wait_for_two_validated_paths(&client_handle).await;
            wait_for_two_validated_paths(&server_handle).await;

            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flapper = {
                let (dark, done) = (dark.clone(), done.clone());
                tokio::spawn(async move {
                    let mut round = 0u64;
                    while !done.load(std::sync::atomic::Ordering::Relaxed) {
                        tokio::time::sleep(std::time::Duration::from_millis(400 + round % 5 * 150)).await;
                        dark.store(true, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_millis(300 + round % 4 * 300)).await;
                        dark.store(false, std::sync::atomic::Ordering::Relaxed);
                        round += 1;
                    }
                    round
                })
            };

            let up = tokio::spawn(pump(client_send, "client send"));
            let down = tokio::spawn(pump(server_send, "server send"));
            let (to_server, to_client) = tokio::join!(
                drain(&mut server_recv, "client->server"),
                drain(&mut client_recv, "server->client")
            );
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            let flaps = flapper.await.unwrap();
            let finished = |task: tokio::task::JoinHandle<Result<_, String>>| async move {
                match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                    Ok(result) => result.unwrap().err(),
                    Err(_) => Some("sender still blocked".to_string()),
                }
            };
            let (up, down) = (finished(up).await, finished(down).await);
            let status = |handle: &MpSessionHandle| {
                let handle = handle.clone();
                async move {
                    tokio::time::timeout(std::time::Duration::from_secs(2), handle.data_plane_status())
                        .await
                        .ok()
                        .and_then(Result::ok)
                }
            };
            let (server_status, client_status) =
                (status(&server_handle).await, status(&client_handle).await);
            let dropped = |status: &Option<MpDataPlaneStatus>| {
                status
                    .as_ref()
                    .map(|status| status.stream_aqm_drops + status.stream_overlimit_drops)
            };
            assert!(
                to_server.is_ok() && to_client.is_ok() && up.is_none() && down.is_none(),
                "{to_server:?} {to_client:?} {up:?} {down:?} after {flaps} flaps;                  server {server_status:?} / client {client_status:?}",
            );
            // Nothing is lost silently: what did not arrive was counted by the
            // sender's stream queues.
            let (to_server, to_client) = (to_server.unwrap() as u64, to_client.unwrap() as u64);
            assert_eq!(
                to_server + dropped(&client_status).unwrap(),
                FRAMES as u64,
                "client->server: {to_server} arrived, client status {client_status:?}"
            );
            assert_eq!(
                to_client + dropped(&server_status).unwrap(),
                FRAMES as u64,
                "server->client: {to_client} arrived, server status {server_status:?}"
            );
            assert!(flaps >= 2, "the path must flap during the transfer ({flaps})");
            client_handle.shutdown();
            server_handle.shutdown();
        });
    }

    /// A relay next-hop path has a fixed 4-tuple: after it was removed, the
    /// same 4-tuple must be mountable again as a new QUIC path (the previous
    /// one is dropped, its connection IDs retired and replaced).
    #[test]
    fn mpquic_real_udp_path_can_be_remounted_on_the_same_four_tuple() {
        RUNTIME.block_on(async {
            let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
                real_udp_path_pair().await;
            let (client_secondary, client_secondary_addr, server_secondary, server_secondary_addr) =
                real_udp_path_pair().await;
            let runtime = MpQuicSessionConfig {
                algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
                ..Default::default()
            };
            let client_remote_url: url::Url =
                format!("mpquic://{server_primary_addr}").parse().unwrap();
            let server_remote_url: url::Url =
                format!("mpquic://{client_primary_addr}").parse().unwrap();

            let server_task = tokio::spawn(async move {
                session_from_datagram_paths_with_config(
                    true,
                    vec![(server_primary, None)],
                    client_primary_addr,
                    server_remote_url,
                    "mpquic",
                    runtime,
                    EgressQualityManager::new(EgressQualityConfig::default()),
                    None,
                )
                .await
            });
            let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
                false,
                vec![(client_primary, None)],
                server_primary_addr,
                client_remote_url,
                "mpquic",
                runtime,
                EgressQualityManager::new(EgressQualityConfig::default()),
                None,
            )
            .await
            .unwrap();
            let (mut client_recv, mut client_send) = client_tunnel.split();
            client_send
                .send(ZCPacket::new_with_payload(b"remount-bootstrap"))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
            let (mut server_recv, mut server_send) = server_tunnel.split();
            let first = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            server_send.send(first).await.unwrap();
            server_send.flush().await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();

            // Mount, validate, remove, and mount the same 4-tuple again.
            for round in 0..3 {
                server_handle
                    .add_path(server_secondary.clone(), client_secondary_addr, None)
                    .await
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(15), async {
                    loop {
                        // The client's offer fails with "no free QUIC path
                        // slot" until the peer has replaced the retired
                        // connection ID: retry, as the path manager does.
                        if client_handle
                            .add_path(client_secondary.clone(), server_secondary_addr, None)
                            .await
                            .is_ok()
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("round {round}: the 4-tuple could not be mounted again"));
                wait_for_two_validated_paths(&server_handle).await;
                wait_for_two_validated_paths(&client_handle).await;

                client_handle
                    .remove_path(client_secondary_addr, server_secondary_addr)
                    .await
                    .unwrap();
                server_handle
                    .remove_path(server_secondary_addr, client_secondary_addr)
                    .await
                    .unwrap();
            }
            client_handle.shutdown();
            server_handle.shutdown();
        });
    }

    /// The client's egress scope for a `None`-binding carrier is
    /// `EgressStableId::Fallback` keyed by local address (see
    /// `governed_sender::scope_for`); this reproduces that same scope so a
    /// budget set on it here is visible to the client's own `DatagramSender`
    /// through the shared ledger.
    fn fallback_scope_for(local_addr: SocketAddr) -> EgressScope {
        EgressScope {
            stable_id: EgressStableId::Fallback {
                platform: std::env::consts::OS.to_string(),
                opaque: format!("mpquic-carrier:{local_addr}"),
            },
            direction: EgressDirection::Egress,
            generation: 0,
        }
    }

    /// MP_SQM_PLAN.md §4.4 (b): a real CUBIC-governed mpquic session under a
    /// tight egress budget, sustained for 6s (>= the plan's 5s floor). Real
    /// client/server TQUIC handshake, real loopback UDP, real wall clock --
    /// the client's egress ledger is set far below what CUBIC alone would
    /// ramp cwnd to, so the *governor*, not the congestion window, is the
    /// bottleneck actually under test.
    ///
    /// Reports achieved-vs-target throughput, srtt and lost_bytes so a
    /// human can compare this run's numbers against the same test run
    /// against step-3 (pre-3b) behavior. Getting "step-3" numbers requires
    /// no separate checkout: `DatagramSender::can_send_data` and
    /// `on_packets_send_sparse` only exist because we override the trait's
    /// always-admit/prefix defaults, and `set_send_batch_size(1)` is one
    /// line in `apply_common_config` -- reverting those specific lines
    /// (leaving the vendor/tquic fork bump in place, since it is
    /// behavior-neutral until something overrides its new defaults)
    /// reproduces step-3 behavior exactly for an A/B re-run of this same
    /// test, with no separate tree needed.
    #[test]
    fn cubic_under_tight_egress_budget_converges_without_bufferbloat() {
        RUNTIME.block_on(async {
            const TARGET_BYTES_PER_SEC: u64 = 40_000;
            const WINDOW: std::time::Duration = std::time::Duration::from_secs(6);
            const PAYLOAD_LEN: usize = 1200;
            // However long the send loop below takes to hand bytes to TQUIC,
            // there must always be more already-queued data than the
            // governor could possibly drain within `WINDOW` -- otherwise an
            // empty send buffer, not the governor, would be why the
            // measured rate stops climbing.
            const SAFETY_MARGIN: u64 = 3;

            let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
                real_udp_path_pair().await;

            let client_manager = EgressQualityManager::new(EgressQualityConfig::default());
            let egress = client_manager.handle_for(fallback_scope_for(client_primary_addr));
            // A declared capacity of the NIC: it also bounds the WAN scope
            // the queue moves to once the peer reports the public address.
            client_manager.set_static_ceiling(
                None,
                HashMap::from([(
                    egress.scope().stable_id.clone(),
                    WireBitrate(TARGET_BYTES_PER_SEC * 8),
                )]),
            );

            let runtime = MpQuicSessionConfig {
                congestion_control: CongestionControlProfile::Cubic,
                ..Default::default()
            };
            let client_remote_url: url::Url =
                format!("mpquic://{server_primary_addr}").parse().unwrap();
            let server_remote_url: url::Url =
                format!("mpquic://{client_primary_addr}").parse().unwrap();

            let server_task = tokio::spawn(async move {
                session_from_datagram_paths_with_config(
                    true,
                    vec![(server_primary, None)],
                    client_primary_addr,
                    server_remote_url,
                    "mpquic",
                    runtime,
                    EgressQualityManager::new(EgressQualityConfig::default()),
                    None,
                )
                .await
            });
            let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
                false,
                vec![(client_primary, None)],
                server_primary_addr,
                client_remote_url,
                "mpquic",
                runtime,
                client_manager.clone(),
                None,
            )
            .await
            .unwrap();
            let (client_recv, mut client_send) = client_tunnel.split();

            let bootstrap = b"cubic-tight-budget-bootstrap";
            client_send
                .send(ZCPacket::new_with_payload(bootstrap))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
            let (mut server_recv, server_send) = server_tunnel.split();
            let bootstrap_packet =
                tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(bootstrap_packet.payload(), bootstrap);

            // Drain the server's receive side in the background. ACKs are
            // generated at the transport layer regardless of application
            // consumption, but an un-drained duplex pipe between the
            // server's driver and its `Tunnel` half (`DUPLEX_BUF`, 256 KiB)
            // would still eventually stall the driver from handing off
            // further received bytes once this test's several-hundred-KiB
            // payload exceeds it.
            let drain = tokio::spawn(async move {
                let _server_send = server_send;
                while let Some(Ok(_)) = server_recv.next().await {}
            });

            let baseline = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must be present")
                .sent_bytes;

            // What the egress's CAKE queue let out, in wire bytes: the budget's unit.
            let wire_sent = || cake_status(&egress).map_or(0, |cake| cake.sent_bytes);
            let wire_baseline = wire_sent();
            let total_bytes = TARGET_BYTES_PER_SEC * WINDOW.as_secs() * SAFETY_MARGIN;
            let packet_count = (total_bytes / PAYLOAD_LEN as u64) as usize;
            let payload = vec![0xABu8; PAYLOAD_LEN];
            for _ in 0..packet_count {
                client_send
                    .send(ZCPacket::new_with_payload(&payload))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();

            // Measure the real, wall-clock-paced wire rate over `WINDOW`,
            // decoupled from however long the submit loop above took: the
            // governor (via the data gate and `on_packets_send_sparse`),
            // not the application write loop, is what actually paces bytes
            // onto the wire.
            tokio::time::sleep(WINDOW).await;
            let after = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must still be present");

            let achieved_bytes_per_sec = (wire_sent() - wire_baseline) as f64 / WINDOW.as_secs_f64();
            let target = TARGET_BYTES_PER_SEC as f64;
            let sent_delta = after.sent_bytes - baseline;
            println!(
                "cubic tight-budget: target={target:.0} B/s achieved={achieved_bytes_per_sec:.0} B/s srtt={}us lost_bytes={} sent_delta={sent_delta} max_inflight_bytes={}",
                after.srtt_micros, after.lost_bytes, after.max_inflight_bytes,
            );
            assert!(
                achieved_bytes_per_sec > target * 0.9,
                "governed CUBIC sender starved: achieved {achieved_bytes_per_sec:.0} B/s vs target {target:.0} B/s"
            );
            assert!(
                achieved_bytes_per_sec < target * 1.1,
                "governed CUBIC sender exceeded its budget by more than 10%: achieved {achieved_bytes_per_sec:.0} B/s vs target {target:.0} B/s"
            );
            // No network loss was injected: the loss is CAKE dropping what CUBIC
            // sent above the shaped rate (its congestion signal), and it must
            // stay a small share, or CUBIC is not converging to the rate.
            assert!(
                (after.lost_bytes as f64) < sent_delta as f64 * 0.3,
                "CUBIC lost {} of {sent_delta} bytes to the egress queue",
                after.lost_bytes
            );
            assert!(
                after.srtt_micros < 200_000,
                "srtt grew past 200ms ({}us), which would indicate local bufferbloat from \
                 over-generation ahead of the governor rather than the governor cleanly pacing \
                 the wire",
                after.srtt_micros
            );
            // srtt/wire-rate alone barely discriminate the 3b fix on loopback,
            // where the gap between "governed" and "ungoverned generation" is
            // mostly ACK delay, not queueing: the governor still paces what
            // actually reaches the wire either way, so throughput converges
            // similarly in both cases. `max_inflight_bytes` does not -- TQUIC
            // marks a packet in-flight at generation time (before
            // `on_packets_send`/`on_packets_send_sparse` ever runs), so if the
            // send path generates many packets ahead of a stale governor
            // answer (e.g. a large `set_send_batch_size`) before draining any
            // of them, this high-water mark balloons even though the wire
            // rate still looks paced. Bound it well above real steady-state
            // in-flight (a handful of MTU-sized packets on loopback) but
            // still far below the ~720 KB of data this test ever hands TQUIC,
            // so an over-generation regression that queues most of it inside
            // TQUIC rather than at the application is caught.
            assert!(
                after.max_inflight_bytes < 50_000,
                "max_inflight_bytes={} is far above steady-state loopback in-flight; TQUIC's \
                 send path is generating packets well ahead of the governor's actual admission \
                 decisions instead of pacing generation to match it",
                after.max_inflight_bytes
            );

            drop(client_send);
            drop(client_recv);
            client_handle.shutdown();
            server_handle.shutdown();
            let _ = drain.await;
        });
    }

    /// MP_SQM_PLAN.md S2.1's core RED spec: a real, already-running,
    /// standalone `mpquic://` session governed by a static ceiling (built
    /// the same way `GlobalCtx::new` builds one from
    /// `Flags::egress_wire_limit_bps` -- construction-time, not an explicit
    /// `set_budget` call) converges to that ceiling, and then -- with NO
    /// reconnect/restart of the tunnel -- `EgressQualityManager::
    /// set_static_ceiling`'s live re-cap converges it to a new, lower
    /// ceiling within a few seconds. Real client/server TQUIC handshake,
    /// real loopback UDP, real wall clock, same shape as
    /// `cubic_under_tight_egress_budget_converges_without_bufferbloat`
    /// above.
    #[test]
    fn standalone_mpquic_hot_recap_converges_to_a_new_static_ceiling_without_restart() {
        RUNTIME.block_on(async {
            const INITIAL_TARGET_BYTES_PER_SEC: u64 = 100_000; // 800 kbit/s
            const RECAPPED_TARGET_BYTES_PER_SEC: u64 = 50_000; // 400 kbit/s
            const INITIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
            const RECAP_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);
            const PAYLOAD_LEN: usize = 1200;
            const SAFETY_MARGIN: u64 = 3;

            let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
                real_udp_path_pair().await;

            let client_manager = EgressQualityManager::new(EgressQualityConfig {
                // The S1.3 "接通" path: baked in at construction, exactly
                // like a real `GlobalCtx` built from
                // `Flags::egress_wire_limit_bps` -- the hot re-cap below
                // must work against this same origin, not only against an
                // explicit `set_budget` call.
                static_wire_ceiling: Some(WireBitrate(INITIAL_TARGET_BYTES_PER_SEC * 8)),
                ..EgressQualityConfig::default()
            });

            let runtime = MpQuicSessionConfig {
                congestion_control: CongestionControlProfile::Cubic,
                ..Default::default()
            };
            let client_remote_url: url::Url =
                format!("mpquic://{server_primary_addr}").parse().unwrap();
            let server_remote_url: url::Url =
                format!("mpquic://{client_primary_addr}").parse().unwrap();

            let server_task = tokio::spawn(async move {
                session_from_datagram_paths_with_config(
                    true,
                    vec![(server_primary, None)],
                    client_primary_addr,
                    server_remote_url,
                    "mpquic",
                    runtime,
                    EgressQualityManager::new(EgressQualityConfig::default()),
                    None,
                )
                .await
            });
            let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
                false,
                vec![(client_primary, None)],
                server_primary_addr,
                client_remote_url,
                "mpquic",
                runtime,
                client_manager.clone(),
                None,
            )
            .await
            .unwrap();
            let (client_recv, mut client_send) = client_tunnel.split();

            let bootstrap = b"hot-recap-bootstrap";
            client_send
                .send(ZCPacket::new_with_payload(bootstrap))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
            let (mut server_recv, server_send) = server_tunnel.split();
            let bootstrap_packet =
                tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(bootstrap_packet.payload(), bootstrap);

            let drain = tokio::spawn(async move {
                let _server_send = server_send;
                while let Some(Ok(_)) = server_recv.next().await {}
            });

            let payload = vec![0xABu8; PAYLOAD_LEN];

            // --- Phase 1: converge to the initial (construction-time) ceiling.
            let baseline = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must be present")
                .sent_bytes;
            let phase1_total_bytes =
                INITIAL_TARGET_BYTES_PER_SEC * INITIAL_WINDOW.as_secs() * SAFETY_MARGIN;
            let phase1_packet_count = (phase1_total_bytes / PAYLOAD_LEN as u64) as usize;
            for _ in 0..phase1_packet_count {
                client_send
                    .send(ZCPacket::new_with_payload(&payload))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();
            tokio::time::sleep(INITIAL_WINDOW).await;
            let after_phase1 = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must still be present")
                .sent_bytes;
            let phase1_achieved =
                (after_phase1 - baseline) as f64 / INITIAL_WINDOW.as_secs_f64();
            let phase1_target = INITIAL_TARGET_BYTES_PER_SEC as f64;
            println!(
                "hot-recap phase1 (initial ceiling): target={phase1_target:.0} B/s achieved={phase1_achieved:.0} B/s"
            );
            assert!(
                phase1_achieved > phase1_target * 0.9 && phase1_achieved < phase1_target * 1.1,
                "phase1 did not converge to the initial ceiling: target={phase1_target:.0} B/s \
                 achieved={phase1_achieved:.0} B/s"
            );

            // --- Phase 2: live hot-recap to a lower ceiling, same session,
            // same tunnel, no reconnect -- this is the actual behavior under
            // test.
            client_manager.set_static_ceiling(
                Some(WireBitrate(RECAPPED_TARGET_BYTES_PER_SEC * 8)),
                std::collections::HashMap::new(),
            );
            let phase2_total_bytes =
                RECAPPED_TARGET_BYTES_PER_SEC * RECAP_WINDOW.as_secs() * SAFETY_MARGIN;
            let phase2_packet_count = (phase2_total_bytes / PAYLOAD_LEN as u64) as usize;
            for _ in 0..phase2_packet_count {
                client_send
                    .send(ZCPacket::new_with_payload(&payload))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();
            let before_phase2 = after_phase1;
            tokio::time::sleep(RECAP_WINDOW).await;
            let after_phase2 = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must still be present after the hot recap")
                .sent_bytes;
            let phase2_achieved =
                (after_phase2 - before_phase2) as f64 / RECAP_WINDOW.as_secs_f64();
            let phase2_target = RECAPPED_TARGET_BYTES_PER_SEC as f64;
            println!(
                "hot-recap phase2 (recapped ceiling): target={phase2_target:.0} B/s achieved={phase2_achieved:.0} B/s"
            );
            assert!(
                phase2_achieved > phase2_target * 0.9 && phase2_achieved < phase2_target * 1.1,
                "phase2 (after live set_static_ceiling, no restart) did not converge to the new \
                 ceiling within {RECAP_WINDOW:?}: target={phase2_target:.0} B/s \
                 achieved={phase2_achieved:.0} B/s"
            );

            drop(client_send);
            drop(client_recv);
            client_handle.shutdown();
            server_handle.shutdown();
            let _ = drain.await;
        });
    }

    /// MP_SQM_PLAN.md §4.4 (b)/S1.1: a governor `ApplyCeiling` at the lowest
    /// rate a real deployment could configure must not let the connection
    /// idle-time out, because Control traffic (ACKs for whatever the peer
    /// keeps sending) must keep flowing even while a competing Data
    /// obligation is rate-limited to a near standstill -- that is the data
    /// gate's whole reason to exist (`send_frames` writes ACK/CLOSE/
    /// PATH_CHALLENGE/HANDSHAKE_DONE/CRYPTO/PING outside it).
    ///
    /// S1.1 removed `BudgetDisposition::ExplicitPause` -- the old, distinct
    /// disposition that hard-blocked `Data` at a literal 0 bps ceiling
    /// regardless of remaining headroom, a case production never actually
    /// reaches (every real caller reaches this only through
    /// `EgressQualityConfig::static_wire_ceiling`/`set_budget`, neither of
    /// which the codebase ever drives to exactly zero). `Some(0)` is now an
    /// ordinary (if extreme) `ApplyCeiling(WireBitrate(0))`: headroom-based,
    /// not hard-blocked. This test uses a small burst (`tiny_config` below)
    /// so the pre-existing token pool cannot itself carry the pending Data
    /// past the low ceiling, keeping the same discriminating power the old
    /// literal-zero-bps version had.
    ///
    /// Waits past the actual configured `max_idle_timeout`
    /// (`apply_common_config`'s hardcoded 30s), not a shortened stand-in --
    /// this proves the real deployed value survives a real pause, not an
    /// easier one substituted for test speed.
    #[test]
    fn minimum_rate_ceiling_survives_past_idle_timeout_while_control_bytes_keep_growing() {
        RUNTIME.block_on(async {
            const WAIT: std::time::Duration = std::time::Duration::from_secs(34);
            const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

            let (client_primary, client_primary_addr, server_primary, server_primary_addr) =
                real_udp_path_pair().await;

            // A small burst that holds barely more than one MTU plus a
            // modest control reserve: the pre-loaded token pool must not by
            // itself be enough to carry the pending Data below past the low
            // ceiling this test sets after bootstrap.
            let tiny_config = EgressQualityConfig {
                ..EgressQualityConfig::default()
            };
            let client_manager = EgressQualityManager::new(tiny_config);

            let runtime = MpQuicSessionConfig::default();
            let client_remote_url: url::Url =
                format!("mpquic://{server_primary_addr}").parse().unwrap();
            let server_remote_url: url::Url =
                format!("mpquic://{client_primary_addr}").parse().unwrap();

            let server_task = tokio::spawn(async move {
                session_from_datagram_paths_with_config(
                    true,
                    vec![(server_primary, None)],
                    client_primary_addr,
                    server_remote_url,
                    "mpquic",
                    runtime,
                    EgressQualityManager::new(EgressQualityConfig::default()),
                    None,
                )
                .await
            });
            let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
                false,
                vec![(client_primary, None)],
                server_primary_addr,
                client_remote_url,
                "mpquic",
                runtime,
                client_manager.clone(),
                None,
            )
            .await
            .unwrap();
            let (mut client_recv, mut client_send) = client_tunnel.split();

            let bootstrap = b"explicit-pause-bootstrap";
            client_send
                .send(ZCPacket::new_with_payload(bootstrap))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
            let (mut server_recv, mut server_send) = server_tunnel.split();
            let bootstrap_packet =
                tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(bootstrap_packet.payload(), bootstrap);

            // Drop the client's egress ceiling to the lowest rate this layer
            // can express (`ApplyCeiling(WireBitrate(0))` -- rounds to 0
            // transport bytes/s, so it never refills again). Control keeps
            // its own reserved credit (`tiny_config`'s 1,800-byte
            // `control_reserve_bytes`) regardless of how much competing Data
            // is pending; a real deployment's "must not idle-timeout while
            // severely rate-limited" guarantee depends on that reserved
            // credit, not on the ceiling rate itself.
            client_manager
                .handle_for(fallback_scope_for(client_primary_addr))
                .set_budget(Some(WireBitrate(0)))
                .unwrap();

            // Drain whatever the client receives so the driver's duplex
            // pipe never backs up; this test asserts on telemetry, not on
            // payload content.
            let client_drain =
                tokio::spawn(async move { while let Some(Ok(_)) = client_recv.next().await {} });

            let baseline = client_handle
                .path_telemetry()
                .await
                .unwrap()
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must be present")
                .sent_bytes;

            // The client also queues its own Data while paused, and does not
            // stop trying: without the data gate (`can_send_data`), TQUIC
            // would coalesce this pending STREAM data into the very same
            // OneRTT packets it uses to carry the ACKs above. The governor
            // classifies any such packet `PacketBudgetClass::Data` (see
            // `on_packets_send_sparse`); `tiny_config`'s small burst means
            // the Data headroom left after the pause (1,800 bytes) is spent
            // by the first handful of these 200-byte chunks, and the
            // never-refilling zero-rate ceiling then makes every later one
            // `Blocked` -- trapping the ACK behind it and stalling
            // `sent_bytes` for the rest of the window unless Control is kept
            // separate. With the gate, `send_frames` skips
            // `try_write_buffered_frames`/`try_write_stream_frames` entirely
            // for OneRTT/ZeroRTT packets while the gate is closed, so this
            // pending data can never get coalesced with a Control-only ACK
            // packet in the first place.
            let pending_client_data = vec![0xCDu8; 200];
            for _ in 0..20 {
                client_send
                    .send(ZCPacket::new_with_payload(&pending_client_data))
                    .await
                    .unwrap();
            }

            // The server keeps sending small packets throughout the pause
            // so the client has something to ACK. A truly idle connection
            // (nothing arriving in either direction) has nothing to ACK --
            // "control bytes keep growing" would otherwise only be about
            // the handshake, not this mechanism.
            let keepalive_deadline = tokio::time::Instant::now() + WAIT;
            let keepalive = tokio::spawn(async move {
                let mut sequence = 0u64;
                while tokio::time::Instant::now() < keepalive_deadline {
                    let payload = format!("keepalive-{sequence}");
                    if server_send
                        .send(ZCPacket::new_with_payload(payload.as_bytes()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    sequence += 1;
                    tokio::time::sleep(KEEPALIVE_INTERVAL).await;
                }
                server_send
            });

            tokio::time::sleep(WAIT).await;

            let after = client_handle
                .path_telemetry()
                .await
                .expect(
                    "driver must still be alive -- an idle-timed-out connection would have torn \
                     the driver down",
                )
                .into_iter()
                .find(|path| path.local_addr == client_primary_addr)
                .expect("primary path must still be present after the pause");

            println!(
                "minimum rate ceiling: sent_bytes {} -> {} over {WAIT:?} (mostly Control -- Data \
                 headroom exhausted early and never refills at this ceiling), \
                 validation_state={:?}",
                baseline, after.sent_bytes, after.validation_state,
            );
            // A bare `>` would also pass on a trivial few-byte artifact that
            // does not actually demonstrate sustained Control flow. With
            // ~68 keepalives over `WAIT` at `KEEPALIVE_INTERVAL`, a healthy
            // client ACKs far more than this floor; picking a number well
            // below that (rather than the raw expected total) keeps the
            // assertion robust to real scheduling jitter while still failing
            // hard on the "nothing got out" case the reverted gate produces.
            assert!(
                after.sent_bytes > baseline + 500,
                "client sent only {} bytes across the whole pause window (baseline {baseline}) \
                 -- either nothing needed acking (test setup bug) or the data gate/control-class \
                 path failed to keep control traffic alive while competing Data was pending",
                after.sent_bytes
            );
            assert_eq!(
                after.validation_state,
                tquic::PathState::Validated,
                "path must remain validated -- an idle timeout would have torn the path/\
                 connection down instead"
            );

            let _server_send = keepalive.await.unwrap();
            client_handle.shutdown();
            server_handle.shutdown();
            let _ = client_drain.await;
            drop(server_recv);
        });
    }

    // -- One shaped egress shared by several sessions (MP_WORKLIST row 39) --

    /// One NIC every client session below sends through: they all resolve to
    /// this scope, so they share its one ledger the way MP sessions to
    /// different peers share a real NIC.
    fn shared_nic_scope() -> EgressScope {
        EgressScope {
            stable_id: EgressStableId::Fallback {
                platform: std::env::consts::OS.to_string(),
                opaque: "shared-test-nic".to_string(),
            },
            direction: EgressDirection::Egress,
            generation: 0,
        }
    }

    type BoxSink = std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>;
    type BoxStream = std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>;

    struct ShapedSession {
        client_send: BoxSink,
        client_handle: MpSessionHandle,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        server_recv: BoxStream,
        server_handle: MpSessionHandle,
        _client_recv: BoxStream,
        _server_send: BoxSink,
    }

    /// A real client/server session over loopback whose client sends
    /// through `manager`'s `shared_nic_scope()` ledger.
    async fn shaped_session(manager: Arc<EgressQualityManager>, name: &str) -> ShapedSession {
        shaped_session_with(manager, name, MpQuicSessionConfig::default()).await
    }

    async fn shaped_session_with(
        manager: Arc<EgressQualityManager>,
        name: &str,
        runtime: MpQuicSessionConfig,
    ) -> ShapedSession {
        let (client_path, client_addr, server_path, server_addr) = real_udp_path_pair().await;
        let server_task = tokio::spawn(async move {
            session_from_datagram_paths_with_config(
                true,
                vec![(server_path, None)],
                client_addr,
                format!("mpquic://{client_addr}").parse().unwrap(),
                "mpquic",
                runtime,
                EgressQualityManager::new(EgressQualityConfig::default()),
                None,
            )
            .await
        });
        let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
            false,
            vec![(client_path, Some(shared_nic_scope()))],
            server_addr,
            format!("mpquic://{server_addr}").parse().unwrap(),
            "mpquic",
            runtime,
            manager,
            None,
        )
        .await
        .unwrap();
        let (client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(name.as_bytes()))
            .await
            .unwrap();
        client_send.flush().await.unwrap();
        let (server_tunnel, server_handle) = server_task.await.unwrap().unwrap();
        let (mut server_recv, server_send) = server_tunnel.split();
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first.payload(), name.as_bytes());
        ShapedSession {
            client_send,
            client_handle,
            client_addr,
            server_addr,
            server_recv,
            server_handle,
            _client_recv: client_recv,
            _server_send: server_send,
        }
    }

    fn shared_nic_manager(bytes_per_sec: u64) -> Arc<EgressQualityManager> {
        let manager = EgressQualityManager::new(EgressQualityConfig {
            ..EgressQualityConfig::default()
        });
        manager
            .handle_for(shared_nic_scope())
            .set_budget(Some(WireBitrate(bytes_per_sec * 8)))
            .unwrap();
        manager
    }

    /// Bytes the server's path received: what left the shaped egress. (The
    /// client's own `sent_bytes` also counts what the egress queue dropped.)
    async fn delivered_bytes(server_handle: &MpSessionHandle, server_addr: SocketAddr) -> u64 {
        server_handle
            .path_telemetry()
            .await
            .unwrap()
            .into_iter()
            .find(|path| path.local_addr == server_addr)
            .expect("path must be present")
            .recv_bytes
    }

    /// Keeps a client sending 1200-byte packets until `stop`. Reports the
    /// longest time one send waited for the session to take it (without
    /// SQM the driver moves the pipe into TQUIC's stream buffer as fast as
    /// it can, so this is that buffer draining, not a stall).
    fn saturate(
        mut send: BoxSink,
        stop: tokio::time::Instant,
    ) -> tokio::task::JoinHandle<(BoxSink, std::time::Duration)> {
        tokio::spawn(async move {
            let payload = vec![0xABu8; 1200];
            let mut longest = std::time::Duration::ZERO;
            while tokio::time::Instant::now() < stop {
                let started = tokio::time::Instant::now();
                if send.send(ZCPacket::new_with_payload(&payload)).await.is_err() {
                    break;
                }
                longest = longest.max(started.elapsed());
            }
            (send, longest)
        })
    }

    fn drain(
        mut recv: BoxStream,
    ) -> tokio::task::JoinHandle<BoxStream> {
        tokio::spawn(async move {
            while let Some(Ok(_)) = recv.next().await {}
            recv
        })
    }

    /// A session sending one packet every 100 ms keeps a low latency while
    /// another session saturates the same shaped egress, and the bulk
    /// session keeps the egress busy meanwhile: the egress queue serves a
    /// sparse flow ahead of a bulk flow's backlog (RFC 8290 new-flow
    /// priority).
    fn sparse_beside_bulk(probe_len: usize) {
        RUNTIME.block_on(async {
            const RATE: u64 = 200_000;
            const PROBES: u32 = 40;
            let manager = shared_nic_manager(RATE);
            let bulk = shaped_session(manager.clone(), "bulk").await;
            let mut sparse = shaped_session(manager.clone(), "sparse").await;

            let stop = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
            let bulk_sender = saturate(bulk.client_send, stop);
            let bulk_drain = drain(bulk.server_recv);
            // Let the bulk session fill the egress first.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let bulk_before = delivered_bytes(&bulk.server_handle, bulk.server_addr).await;
            let window = Instant::now();

            let sent_at = Arc::new(Mutex::new(HashMap::<u32, Instant>::new()));
            let mut server_recv = sparse.server_recv;
            let sent_at_rx = sent_at.clone();
            let receiver = tokio::spawn(async move {
                let mut latencies = Vec::new();
                while latencies.len() < PROBES as usize {
                    let Ok(Some(Ok(packet))) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        server_recv.next(),
                    )
                    .await
                    else {
                        break;
                    };
                    let seq = u32::from_be_bytes(packet.payload()[..4].try_into().unwrap());
                    let sent = sent_at_rx.lock().unwrap()[&seq];
                    latencies.push(sent.elapsed());
                }
                (latencies, server_recv)
            });
            for seq in 0..PROBES {
                let mut payload = seq.to_be_bytes().to_vec();
                payload.resize(probe_len, 0);
                sent_at.lock().unwrap().insert(seq, Instant::now());
                sparse
                    .client_send
                    .send(ZCPacket::new_with_payload(&payload))
                    .await
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let (mut latencies, _server_recv) = receiver.await.unwrap();
            let bulk_rate = (delivered_bytes(&bulk.server_handle, bulk.server_addr).await
                - bulk_before) as f64
                / window.elapsed().as_secs_f64();
            let (_bulk_send, stalled) = bulk_sender.await.unwrap();
            println!(
                "sparse {probe_len} B beside bulk at {RATE} B/s: {} probes, bulk {bulk_rate:.0} B/s, \
                 longest bulk send {stalled:?}",
                latencies.len(),
            );
            assert_eq!(latencies.len(), PROBES as usize, "every probe must arrive");
            latencies.sort();
            let median = latencies[latencies.len() / 2];
            let p90 = latencies[latencies.len() * 9 / 10];
            println!(
                "sparse {probe_len} B: median={median:?} p90={p90:?} max={:?}",
                latencies.last().unwrap()
            );
            assert!(
                bulk_rate > RATE as f64 * 0.7,
                "the bulk session left the shaped egress idle: {bulk_rate:.0} B/s"
            );
            // One 1250-byte bulk packet takes ~6 ms at this rate; a sparse
            // flow waits for at most about one of them.
            assert!(
                p90 < std::time::Duration::from_millis(30),
                "sparse probes waited behind the bulk session: median={median:?} p90={p90:?}"
            );

            bulk.client_handle.shutdown();
            bulk.server_handle.shutdown();
            sparse.client_handle.shutdown();
            sparse.server_handle.shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), bulk_drain).await;
        });
    }

    /// One session alone on a shaped egress fills it.
    fn bulk_alone(congestion_control: CongestionControlProfile) {
        RUNTIME.block_on(async {
            const RATE: u64 = 200_000;
            const WINDOW: std::time::Duration = std::time::Duration::from_secs(4);
            let manager = shared_nic_manager(RATE);
            let runtime = MpQuicSessionConfig {
                congestion_control,
                ..Default::default()
            };
            let bulk = shaped_session_with(manager.clone(), "alone", runtime).await;
            let stop = tokio::time::Instant::now() + WINDOW + std::time::Duration::from_secs(2);
            let sender = saturate(bulk.client_send, stop);
            // Payload bytes the application received: unlike the path's
            // bytes, resent data counts once.
            let payload = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let mut server_recv = bulk.server_recv;
            let payload_rx = payload.clone();
            let drained = tokio::spawn(async move {
                while let Some(Ok(packet)) = server_recv.next().await {
                    payload_rx.fetch_add(
                        packet.payload().len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            });
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let before = delivered_bytes(&bulk.server_handle, bulk.server_addr).await;
            let payload_before = payload.load(std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(WINDOW).await;
            let rate = (delivered_bytes(&bulk.server_handle, bulk.server_addr).await - before) as f64
                / WINDOW.as_secs_f64();
            let goodput = (payload.load(std::sync::atomic::Ordering::Relaxed) - payload_before) as f64
                / WINDOW.as_secs_f64();
            let (_send, stalled) = sender.await.unwrap();
            let path = path_of(&bulk.client_handle, bulk.client_addr).await;
            println!(
                "one {} session at {RATE} B/s: {rate:.0} B/s (payload {goodput:.0} B/s), longest send {stalled:?}, srtt={}us min_rtt={}us lost={} max_inflight={}",
                congestion_control.as_str(),
                path.srtt_micros,
                path.min_rtt_micros,
                path.lost_bytes,
                path.max_inflight_bytes,
            );
            let queue = super::cake_status(&manager.handle_for(shared_nic_scope())).unwrap();
            println!(
                "egress queue: dropped={} overlimit={} memory peak/limit={}/{} peak_delay={}us",
                queue.dropped_packets,
                queue.overlimit_drops,
                queue.memory_peak,
                queue.memory_limit,
                queue.peak_delay_us,
            );
            assert!(
                rate > RATE as f64 * 0.85,
                "one session left the shaped egress idle: {rate:.0} B/s"
            );
            // A responsive session is held back by COBALT's drops, never by a
            // full queue: overflow drops also raise BLUE's random drop
            // probability, which then stays up until the queue runs empty.
            assert_eq!(
                queue.overlimit_drops, 0,
                "one responsive session overflowed the egress queue's memory ({}/{})",
                queue.memory_peak, queue.memory_limit,
            );
            bulk.client_handle.shutdown();
            bulk.server_handle.shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drained).await;
        });
    }

    #[test]
    fn one_default_cc_session_fills_a_shaped_egress() {
        bulk_alone(CongestionControlProfile::EngineDefault);
    }

    #[test]
    fn one_cubic_session_fills_a_shaped_egress() {
        bulk_alone(CongestionControlProfile::Cubic);
    }

    #[test]
    fn small_packets_stay_fast_beside_a_bulk_session_on_one_shaped_egress() {
        sparse_beside_bulk(64);
    }

    #[test]
    fn full_size_packets_stay_fast_beside_a_bulk_session_on_one_shaped_egress() {
        sparse_beside_bulk(1200);
    }

    async fn path_of(handle: &MpSessionHandle, local: SocketAddr) -> MpPathTelemetry {
        handle
            .path_telemetry()
            .await
            .unwrap()
            .into_iter()
            .find(|path| path.local_addr == local)
            .expect("path must be present")
    }

    /// Two sessions saturating one shaped egress each get about half of it,
    /// and together they use about all of it.
    fn two_bulk(congestion_control: CongestionControlProfile) {
        RUNTIME.block_on(async {
            const RATE: u64 = 200_000;
            const SECONDS: u64 = 5;
            let manager = shared_nic_manager(RATE);
            let runtime = MpQuicSessionConfig {
                congestion_control,
                ..Default::default()
            };
            let a = shaped_session_with(manager.clone(), "a", runtime).await;
            let b = shaped_session_with(manager.clone(), "b", runtime).await;

            let stop =
                tokio::time::Instant::now() + std::time::Duration::from_secs(SECONDS + 3);
            let a_sender = saturate(a.client_send, stop);
            let b_sender = saturate(b.client_send, stop);
            let a_drain = drain(a.server_recv);
            let b_drain = drain(b.server_recv);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let a0 = delivered_bytes(&a.server_handle, a.server_addr).await;
            let b0 = delivered_bytes(&b.server_handle, b.server_addr).await;
            let (mut a_last, mut b_last) = (a0, b0);
            let mut per_second = Vec::new();
            for _ in 0..SECONDS {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let a_now = delivered_bytes(&a.server_handle, a.server_addr).await;
                let b_now = delivered_bytes(&b.server_handle, b.server_addr).await;
                per_second.push((a_now - a_last, b_now - b_last));
                (a_last, b_last) = (a_now, b_now);
            }
            let a_rate = (a_last - a0) as f64 / SECONDS as f64;
            let b_rate = (b_last - b0) as f64 / SECONDS as f64;
            let cc = congestion_control.as_str();
            println!(
                "two {cc} bulk sessions at {RATE} B/s: a={a_rate:.0} B/s b={b_rate:.0} B/s, \
                 per second {per_second:?}"
            );
            for (name, path) in [
                ("a", path_of(&a.client_handle, a.client_addr).await),
                ("b", path_of(&b.client_handle, b.client_addr).await),
            ] {
                println!(
                    "  {cc} {name}: srtt={}us min_rtt={}us btlbw={} delivery_rate={} \
                     app_limited={} lost={} max_inflight={} state={:?}",
                    path.srtt_micros,
                    path.min_rtt_micros,
                    path.btlbw,
                    path.delivery_rate,
                    path.app_limited,
                    path.lost_bytes,
                    path.max_inflight_bytes,
                    path.congestion_control_state,
                );
            }
            let ratio = a_rate / b_rate;
            assert!(
                (0.8..=1.25).contains(&ratio),
                "unfair split of one shaped egress: a={a_rate:.0} B/s b={b_rate:.0} B/s"
            );
            assert!(
                a_rate + b_rate > RATE as f64 * 0.85,
                "the two sessions left the shaped egress idle: a={a_rate:.0} B/s b={b_rate:.0} B/s"
            );

            let (_a_send, a_stalled) = a_sender.await.unwrap();
            let (_b_send, b_stalled) = b_sender.await.unwrap();
            println!("longest sends: a={a_stalled:?} b={b_stalled:?}");
            for handle in [a.client_handle, a.server_handle, b.client_handle, b.server_handle] {
                handle.shutdown();
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), a_drain).await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), b_drain).await;
        });
    }

    /// With shaping to Autorate (always on), two sessions sharing an egress that has
    /// no real bottleneck behind it keep sending near Autorate's ceiling: the
    /// time packets wait in our own egress queue is not the link's queue, so
    /// it must not read as bufferbloat and talk Autorate down.
    #[test]
    fn enforced_autorate_does_not_mistake_its_own_queue_for_bufferbloat() {
        RUNTIME.block_on(async {
            const CEILING_BPS: u64 = 400_000;
            let manager = EgressQualityManager::new(EgressQualityConfig {
                estimator: crate::common::egress_quality::SqmConfig {
                    bw_max_bps: CEILING_BPS,
                    ..Default::default()
                },
                ..EgressQualityConfig::default()
            });
            let a = shaped_session(manager.clone(), "a").await;
            let b = shaped_session(manager.clone(), "b").await;

            let stop = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
            let a_sender = saturate(a.client_send, stop);
            let b_sender = saturate(b.client_send, stop);
            let a_drain = drain(a.server_recv);
            let b_drain = drain(b.server_recv);
            // Autorate ticks as the standalone sampler does, a bit faster.
            let sample = |handle: &MpSessionHandle| {
                handle.request_autorate_sample();
            };
            let mut rates = Vec::new();
            let (mut a_last, mut b_last) = (0, 0);
            for second in 0..10u32 {
                for _ in 0..4 {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    sample(&a.client_handle);
                    sample(&b.client_handle);
                }
                let a_now = delivered_bytes(&a.server_handle, a.server_addr).await;
                let b_now = delivered_bytes(&b.server_handle, b.server_addr).await;
                if second > 0 {
                    rates.push(a_now - a_last + b_now - b_last);
                }
                (a_last, b_last) = (a_now, b_now);
            }
            let estimate = manager.handle_for(shared_nic_scope()).autorate_estimate();
            let a_path = path_of(&a.client_handle, a.client_addr).await;
            println!(
                "enforced autorate, ceiling {CEILING_BPS} bps: bytes per second {rates:?}, \
                 estimate {estimate:?}, a srtt={}us min_rtt={}us",
                a_path.srtt_micros, a_path.min_rtt_micros
            );
            let last: u64 = rates[rates.len() - 4..].iter().sum::<u64>() / 4;
            assert!(
                last as f64 > CEILING_BPS as f64 / 8.0 * 0.7,
                "Autorate talked itself down on a link with no queue but ours: \
                 {last} B/s in the last 4 s, ceiling {} B/s",
                CEILING_BPS / 8
            );

            let _ = a_sender.await;
            let _ = b_sender.await;
            for handle in [a.client_handle, a.server_handle, b.client_handle, b.server_handle] {
                handle.shutdown();
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), a_drain).await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), b_drain).await;
        });
    }

    #[test]
    fn two_default_cc_sessions_split_one_shaped_egress_evenly() {
        two_bulk(CongestionControlProfile::EngineDefault);
    }

    #[test]
    fn two_cubic_sessions_split_one_shaped_egress_evenly() {
        two_bulk(CongestionControlProfile::Cubic);
    }


    /// Without the data plane every inner flow of a session shares one QUIC
    /// stream. With SQM on, the frames wait in front of it per inner flow
    /// (`fair_pipe`), so two flows share the shaped egress evenly although
    /// one sends three times the other's rate. A first-in first-out pipe
    /// gives them 3:1.
    #[test]
    fn sqm_without_data_plane_shares_the_stream_between_inner_flows() {
        RUNTIME.block_on(async {
            const RATE: u64 = 200_000;
            const SECONDS: u64 = 5;
            const FLOW_A: u32 = 0x1111_1111;
            const FLOW_B: u32 = 0x2222_2222;
            let manager = shared_nic_manager(RATE);
            let runtime = MpQuicSessionConfig {
                sqm_enabled: true,
                ..Default::default()
            };
            let session = shaped_session_with(manager, "fair", runtime).await;

            let received = Arc::new([
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ]);
            let mut server_recv = session.server_recv;
            let counted = received.clone();
            let receiver = tokio::spawn(async move {
                while let Some(Ok(packet)) = server_recv.next().await {
                    let flow = usize::from(packet.payload().first() == Some(&b'B'));
                    counted[flow].fetch_add(
                        packet.payload().len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            });

            // Flow A offers three frames for each one of flow B, about five
            // times the egress's rate together, in the order they would
            // leave a host's queue.
            let stop = tokio::time::Instant::now() + std::time::Duration::from_secs(SECONDS + 2);
            let mut send = session.client_send;
            let sender = tokio::spawn(async move {
                let frame = |flow: u32, mark: u8| {
                    let mut packet = ZCPacket::new_with_payload(&vec![mark; 1200]);
                    packet.set_mp_dataplane_tag(Some((0, flow)));
                    packet
                };
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
                while tokio::time::Instant::now() < stop {
                    tick.tick().await;
                    for _ in 0..2 {
                        for (flow, mark) in
                            [(FLOW_A, b'A'), (FLOW_A, b'A'), (FLOW_A, b'A'), (FLOW_B, b'B')]
                        {
                            if send.send(frame(flow, mark)).await.is_err() {
                                return send;
                            }
                        }
                    }
                }
                send
            });

            // Let the queues settle, then count what the egress delivers.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let load = |flow: usize| received[flow].load(std::sync::atomic::Ordering::Relaxed);
            let (a0, b0) = (load(0), load(1));
            tokio::time::sleep(std::time::Duration::from_secs(SECONDS)).await;
            let (a, b) = (load(0) - a0, load(1) - b0);
            let share_a = a as f64 / (a + b) as f64;
            println!("flow a {a} B, flow b {b} B in {SECONDS} s, a's share {share_a:.3}");
            assert!(
                a + b > RATE * SECONDS * 6 / 10,
                "the egress sat idle: {a} + {b} B in {SECONDS} s"
            );
            assert!(
                (0.4..=0.6).contains(&share_a),
                "one flow took the stream: a {a} B, b {b} B, a's share {share_a:.3}"
            );

            let _ = sender.await;
            session.client_handle.shutdown();
            session.server_handle.shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await;
        });
    }

    /// A data-plane session over loopback whose client sends through
    /// `manager`'s `shared_nic_scope()` ledger, negotiated to datagrams.
    async fn shaped_data_plane_session(
        manager: Arc<EgressQualityManager>,
        policy: Arc<DataPlanePolicy>,
    ) -> ShapedSession {
        let (client_path, client_addr, server_path, server_addr) = real_udp_path_pair().await;
        let runtime = MpQuicSessionConfig {
            data_plane: true,
            ..Default::default()
        };
        let server_policy = policy.clone();
        let server_task = tokio::spawn(async move {
            session_from_datagram_paths_with_config(
                true,
                vec![(server_path, None)],
                client_addr,
                format!("mpquic://{client_addr}").parse().unwrap(),
                "mpquic",
                runtime,
                EgressQualityManager::new(EgressQualityConfig::default()),
                Some(server_policy),
            )
            .await
        });
        let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
            false,
            vec![(client_path, Some(shared_nic_scope()))],
            server_addr,
            format!("mpquic://{server_addr}").parse().unwrap(),
            "mpquic",
            runtime,
            manager,
            Some(policy.clone()),
        )
        .await
        .unwrap();
        let caps = Some(crate::tunnel::mp_dataplane::LOCAL_DATAPLANE_CAPS);
        client_handle.set_data_plane(policy.clone(), caps);
        let (client_recv, client_send) = client_tunnel.split();
        let (server_tunnel, server_handle) =
            tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
                .await
                .expect("server session ready")
                .unwrap()
                .unwrap();
        server_handle.set_data_plane(policy, caps);
        let (server_recv, server_send) = server_tunnel.split();
        wait_negotiated(&client_handle, "datagram").await;
        wait_negotiated(&server_handle, "datagram").await;
        ShapedSession {
            client_send,
            client_handle,
            client_addr,
            server_addr,
            server_recv,
            server_handle,
            _client_recv: client_recv,
            _server_send: server_send,
        }
    }

    /// Two datagram-class inner flows, one offering three times the other's
    /// rate, share a shaped egress evenly: the frames wait per flow in the
    /// queue in front of QUIC (`pre_quic_cake`), where COBALT drops the
    /// overload on queueing time, not in the ET pipe or QUIC's drop-oldest
    /// datagram queue.
    #[test]
    fn data_plane_datagram_classes_share_the_egress_between_inner_flows() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            const RATE: u64 = 200_000;
            const SECONDS: u64 = 5;
            const FLOW_A: u32 = 0x1111_1111;
            const FLOW_B: u32 = 0x2222_2222;
            let manager = shared_nic_manager(RATE);
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                ..Default::default()
            });
            let session = shaped_data_plane_session(manager, policy).await;

            let received = Arc::new([
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ]);
            let mut server_recv = session.server_recv;
            let counted = received.clone();
            let receiver = tokio::spawn(async move {
                while let Some(Ok(packet)) = server_recv.next().await {
                    let flow = usize::from(packet.payload().first() == Some(&b'B'));
                    counted[flow].fetch_add(
                        packet.payload().len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            });

            // Flow A offers three frames for each one of flow B, about four
            // times the egress's rate together.
            let stop = tokio::time::Instant::now() + std::time::Duration::from_secs(SECONDS + 2);
            let mut send = session.client_send;
            let sender = tokio::spawn(async move {
                let frame = |flow: u32, mark: u8| {
                    let mut packet = ZCPacket::new_with_payload(&vec![mark; 1000]);
                    packet.set_mp_dataplane_tag(Some((TrafficClass::Udp.tag(), flow)));
                    packet
                };
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
                while tokio::time::Instant::now() < stop {
                    tick.tick().await;
                    for _ in 0..2 {
                        for (flow, mark) in
                            [(FLOW_A, b'A'), (FLOW_A, b'A'), (FLOW_A, b'A'), (FLOW_B, b'B')]
                        {
                            if send.send(frame(flow, mark)).await.is_err() {
                                return send;
                            }
                        }
                    }
                }
                send
            });

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let load = |flow: usize| received[flow].load(std::sync::atomic::Ordering::Relaxed);
            let (a0, b0) = (load(0), load(1));
            tokio::time::sleep(std::time::Duration::from_secs(SECONDS)).await;
            let (a, b) = (load(0) - a0, load(1) - b0);
            let share_a = a as f64 / (a + b) as f64;
            println!("flow a {a} B, flow b {b} B in {SECONDS} s, a's share {share_a:.3}");
            assert!(
                a + b > RATE * SECONDS * 6 / 10,
                "the egress sat idle: {a} + {b} B in {SECONDS} s"
            );
            assert!(
                (0.4..=0.6).contains(&share_a),
                "one flow took the egress: a {a} B, b {b} B, a's share {share_a:.3}"
            );
            // The overload was dropped by the queue's COBALT on queueing
            // time, not by QUIC's drop-oldest datagram queue.
            let status = session.client_handle.data_plane_status().await.unwrap();
            println!("client status: {status:?}");
            assert_eq!(status.dgram_queue_dropped, 0, "QUIC's own queue dropped");
            assert!(
                status.dgram_aqm_drops + status.dgram_overlimit_drops > 0,
                "nothing was dropped by the queue in front of QUIC: {status:?}"
            );

            let _ = sender.await;
            session.client_handle.shutdown();
            session.server_handle.shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await;
        });
    }

    // -- MP_SQM_PLAN.md S2.10/S2.11: datagram data plane over real loopback UDP --

    fn dp_policy(config: crate::proto::common::MpDataPlaneConfig) -> Arc<DataPlanePolicy> {
        Arc::new(DataPlanePolicy::from_config(&config).unwrap())
    }

    fn tagged_packet(
        payload: &[u8],
        class: crate::tunnel::mp_dataplane::TrafficClass,
        bucket: u8,
    ) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.set_mp_dataplane_tag(Some((class.tag(), bucket as u32)));
        packet
    }

    /// One client/server session pair over a real loopback UDP path. `None`
    /// builds that side as a legacy (single stream) session. The client's
    /// bootstrap packet makes a legacy server ready and is echoed back.
    async fn dp_session_pair(
        server_dp: Option<Arc<DataPlanePolicy>>,
        client_dp: Option<Arc<DataPlanePolicy>>,
    ) -> (SplitTunnel, MpSessionHandle, SplitTunnel, MpSessionHandle) {
        dp_session_pair_over(
            real_udp_path_pair().await,
            MpQuicSessionConfig::default(),
            server_dp,
            client_dp,
        )
        .await
    }

    /// `dp_session_pair` over a given path pair and base session config;
    /// `client_addr` is the client endpoint as the server sees it (after any
    /// NAT).
    async fn dp_session_pair_over(
        paths: (
            Arc<dyn MpDatagramPath>,
            SocketAddr,
            Arc<dyn MpDatagramPath>,
            SocketAddr,
        ),
        base: MpQuicSessionConfig,
        server_dp: Option<Arc<DataPlanePolicy>>,
        client_dp: Option<Arc<DataPlanePolicy>>,
    ) -> (SplitTunnel, MpSessionHandle, SplitTunnel, MpSessionHandle) {
        dp_session_pair_managed(
            paths,
            base,
            server_dp,
            client_dp,
            EgressQualityManager::new(EgressQualityConfig::default()),
            EgressQualityManager::new(EgressQualityConfig::default()),
        )
        .await
    }

    /// `dp_session_pair_over` with the egress managers of both ends given, so
    /// a test can reach their egresses.
    async fn dp_session_pair_managed(
        (client_path, client_addr, server_path, server_addr): (
            Arc<dyn MpDatagramPath>,
            SocketAddr,
            Arc<dyn MpDatagramPath>,
            SocketAddr,
        ),
        base: MpQuicSessionConfig,
        server_dp: Option<Arc<DataPlanePolicy>>,
        client_dp: Option<Arc<DataPlanePolicy>>,
        server_manager: Arc<EgressQualityManager>,
        client_manager: Arc<EgressQualityManager>,
    ) -> (SplitTunnel, MpSessionHandle, SplitTunnel, MpSessionHandle) {
        let runtime = |dp: &Option<Arc<DataPlanePolicy>>| MpQuicSessionConfig {
            data_plane: dp.is_some(),
            ..base
        };
        let server_runtime = runtime(&server_dp);
        let client_runtime = runtime(&client_dp);
        let server_url: url::Url = format!("mpquic://{client_addr}").parse().unwrap();
        let client_url: url::Url = format!("mpquic://{server_addr}").parse().unwrap();
        let server_policy = server_dp.clone();
        let server_task = tokio::spawn(async move {
            session_from_datagram_paths_with_config(
                true,
                vec![(server_path, None)],
                client_addr,
                server_url,
                "mpquic",
                server_runtime,
                server_manager,
                server_policy,
            )
            .await
        });
        let (client_tunnel, client_handle) = session_from_datagram_paths_with_config(
            false,
            vec![(client_path, None)],
            server_addr,
            client_url,
            "mpquic",
            client_runtime,
            client_manager,
            client_dp.clone(),
        )
        .await
        .unwrap();
        let caps = Some(crate::tunnel::mp_dataplane::LOCAL_DATAPLANE_CAPS);
        if let Some(policy) = client_dp {
            client_handle.set_data_plane(policy, caps);
        }
        let (mut client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(b"dp-bootstrap"))
            .await
            .unwrap();
        client_send.flush().await.unwrap();
        let (server_tunnel, server_handle) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_task,
        )
        .await
        .expect("server session ready")
        .unwrap()
        .unwrap();
        if let Some(policy) = server_dp {
            server_handle.set_data_plane(policy, caps);
        }
        let (mut server_recv, mut server_send) = server_tunnel.split();
        let bootstrap = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await
            .expect("bootstrap reaches the server")
            .unwrap()
            .unwrap();
        assert_eq!(bootstrap.payload(), b"dp-bootstrap");
        server_send.send(bootstrap).await.unwrap();
        server_send.flush().await.unwrap();
        let echo = tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
            .await
            .expect("bootstrap echo reaches the client")
            .unwrap()
            .unwrap();
        assert_eq!(echo.payload(), b"dp-bootstrap");
        (
            (server_recv, server_send),
            server_handle,
            (client_recv, client_send),
            client_handle,
        )
    }

    /// Application receive backpressure must only stop application delivery,
    /// not ACK/timer processing or the authoritative shutdown command.
    #[test]
    fn an_unread_tunnel_does_not_block_driver_commands() {
        use std::time::Duration;
        RUNTIME.block_on(async {
            for data_plane in [false, true] {
                let policy = data_plane.then(|| dp_policy(crate::proto::common::MpDataPlaneConfig {
                    enabled: true,
                    ..Default::default()
                }));
                let ((server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                    dp_session_pair(policy.clone(), policy).await;
                // Hold the receive half without polling it. More than the
                // duplex capacity arrives over real UDP and a QUIC stream.
                let writer = tokio::spawn(async move {
                    for _ in 0..1024 {
                        if client_send.send(tagged_packet(&[0x5a; 1400], crate::tunnel::mp_dataplane::TrafficClass::Tcp, 1)).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::time::sleep(Duration::from_millis(500)).await;
                let snapshot = tokio::time::timeout(Duration::from_secs(1), server_handle.path_telemetry()).await;
                server_handle.shutdown();
                let shutdown = tokio::time::timeout(Duration::from_secs(1), async {
                    while !server_handle.is_closed() {
                        tokio::task::yield_now().await;
                    }
                }).await;
                writer.abort();
                let _ = writer.await;
                client_handle.shutdown();
                drop(server_recv);
                assert!(snapshot.is_ok_and(|result| result.is_ok()),
                    "data_plane={data_plane}: an unread application blocked telemetry");
                assert!(shutdown.is_ok(),
                    "data_plane={data_plane}: an unread application blocked shutdown");
            }
        });
    }

    #[test]
    fn a_paused_tunnel_reader_resumes_without_losing_or_repeating_bytes() {
        use std::time::Duration;
        RUNTIME.block_on(async {
            let ((mut server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                dp_session_pair(None, None).await;
            let writer = tokio::spawn(async move {
                for sequence in 0..512u32 {
                    let mut payload = vec![0x5a; 1400];
                    payload[..4].copy_from_slice(&sequence.to_le_bytes());
                    client_send.send(ZCPacket::new_with_payload(&payload)).await.unwrap();
                }
                client_send
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Keep the sender alive while its final buffered bytes arrive.
            let client_send = tokio::time::timeout(Duration::from_secs(15), async {
                for sequence in 0..512u32 {
                    let packet = server_recv.next().await.unwrap().unwrap();
                    let payload = packet.payload();
                    assert_eq!(payload.len(), 1400);
                    assert_eq!(&payload[..4], &sequence.to_le_bytes());
                    assert!(payload[4..].iter().all(|byte| *byte == 0x5a));
                }
                writer.await.unwrap()
            }).await.expect("application delivery did not resume after backpressure");
            server_handle.shutdown();
            client_handle.shutdown();
            drop(client_send);
        });
    }

    async fn wait_negotiated(handle: &MpSessionHandle, expected: &str) -> MpDataPlaneStatus {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = handle.data_plane_status().await.unwrap();
                if status.negotiated == expected {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("data plane never negotiated {expected}"))
    }

    fn class_status<'a>(
        status: &'a MpDataPlaneStatus,
        class: &str,
    ) -> &'a crate::proto::api::instance::MpClassStatus {
        status.classes.iter().find(|c| c.class == class).unwrap()
    }

    /// Datagram classes travel as QUIC DATAGRAMs, a `reliable_stream` class
    /// on its own stream, and every frame arrives whole in the ET pipe.
    #[test]
    fn mpquic_data_plane_datagram_and_reliable_stream_round_trip() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                class_policies: vec![crate::proto::common::MpClassPolicy {
                    class: "tcp".into(),
                    mode: "reliable_stream".into(),
                    ..Default::default()
                }],
                ..Default::default()
            });
            let ((mut server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                dp_session_pair(Some(policy.clone()), Some(policy)).await;
            wait_negotiated(&client_handle, "datagram").await;

            const PER_CLASS: usize = 40;
            for i in 0..PER_CLASS {
                let udp = format!("udp-{i:03}-{}", "u".repeat(600));
                let tcp = format!("tcp-{i:03}-{}", "t".repeat(600));
                client_send
                    .send(tagged_packet(udp.as_bytes(), TrafficClass::Udp, 1))
                    .await
                    .unwrap();
                client_send
                    .send(tagged_packet(tcp.as_bytes(), TrafficClass::Tcp, (i % 3) as u8))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();

            let mut tcp_seen = Vec::new();
            let mut udp_seen = 0;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while tcp_seen.len() < PER_CLASS || udp_seen < PER_CLASS {
                    let packet = server_recv.next().await.unwrap().unwrap();
                    let payload = String::from_utf8(packet.payload().to_vec()).unwrap();
                    if payload.starts_with("tcp-") {
                        tcp_seen.push(payload);
                    } else {
                        assert!(payload.starts_with("udp-"), "{payload}");
                        udp_seen += 1;
                    }
                }
            })
            .await;
            // Reliable streams lose nothing and keep per-flow order.
            assert_eq!(tcp_seen.len(), PER_CLASS);
            for bucket in 0..3 {
                let order = tcp_seen
                    .iter()
                    .map(|p| p[4..7].parse::<usize>().unwrap())
                    .filter(|i| i % 3 == bucket)
                    .collect::<Vec<_>>();
                assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
            }
            // Datagrams on loopback: nothing should be lost, allow a margin.
            assert!(udp_seen >= PER_CLASS * 9 / 10, "udp_seen={udp_seen}");

            let status = client_handle.data_plane_status().await.unwrap();
            assert_eq!(status.negotiated, "datagram");
            assert!(status.max_datagram_bytes >= 1200, "{status:?}");
            let tcp = class_status(&status, "tcp");
            assert_eq!((tcp.mode.as_str(), tcp.tx_packets), ("reliable_stream", PER_CLASS as u64));
            assert!(tcp.open_streams >= 1 && tcp.open_streams <= 3, "{tcp:?}");
            let udp = class_status(&status, "udp");
            assert_eq!((udp.mode.as_str(), udp.tx_packets), ("datagram", PER_CLASS as u64));
            let server_status = server_handle.data_plane_status().await.unwrap();
            let received: u64 = server_status.classes.iter().map(|c| c.rx_packets).sum();
            assert!(received >= (PER_CLASS + udp_seen) as u64);
        });
    }

    /// The same traffic the other way: streams the server opens must reach
    /// the client (2026-10-08: TCP from the server end of a live session
    /// never arrived while datagrams did).
    #[test]
    fn mpquic_data_plane_reliable_streams_from_the_server_reach_the_client() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                class_policies: vec![crate::proto::common::MpClassPolicy {
                    class: "tcp".into(),
                    mode: "reliable_stream".into(),
                    ..Default::default()
                }],
                ..Default::default()
            });
            let ((_server_recv, mut server_send), server_handle, (mut client_recv, _client_send), client_handle) =
                dp_session_pair(Some(policy.clone()), Some(policy)).await;
            wait_negotiated(&server_handle, "datagram").await;
            wait_negotiated(&client_handle, "datagram").await;

            const PER_CLASS: usize = 40;
            for i in 0..PER_CLASS {
                let tcp = format!("tcp-{i:03}-{}", "t".repeat(600));
                server_send
                    .send(tagged_packet(tcp.as_bytes(), TrafficClass::Tcp, (i % 3) as u8))
                    .await
                    .unwrap();
            }
            server_send.flush().await.unwrap();

            let mut tcp_seen = 0;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while tcp_seen < PER_CLASS {
                    let packet = client_recv.next().await.unwrap().unwrap();
                    if packet.payload().starts_with(b"tcp-") {
                        tcp_seen += 1;
                    }
                }
            })
            .await;
            let server_status = server_handle.data_plane_status().await.unwrap();
            let client_status = client_handle.data_plane_status().await.unwrap();
            assert_eq!(
                tcp_seen,
                PER_CLASS,
                "server tcp {:?} / client tcp {:?}",
                class_status(&server_status, "tcp"),
                class_status(&client_status, "tcp")
            );
        });
    }

    /// A stream the server opens after the client opened one of its own must
    /// still arrive. TQUIC used to move its next local stream id past every
    /// peer stream, so once the client's stream 8 arrived the server's next
    /// id was 12, a client id it may not open. Reusing a live stream hid
    /// that; once idle streams were reaped, a datagram session has no primary
    /// stream on the server and every later server stream frame was dropped
    /// (2026-10-08: TCP from local to .99 stalled for good, ping fine).
    #[test]
    fn mpquic_data_plane_server_opens_streams_after_the_client_did() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                class_policies: vec![crate::proto::common::MpClassPolicy {
                    class: "tcp".into(),
                    mode: "reliable_stream".into(),
                    ..Default::default()
                }],
                reliable_stream_idle_ms: 200,
                ..Default::default()
            });
            let ((mut server_recv, mut server_send), server_handle, (mut client_recv, mut client_send), client_handle) =
                dp_session_pair(Some(policy.clone()), Some(policy)).await;
            wait_negotiated(&server_handle, "datagram").await;
            wait_negotiated(&client_handle, "datagram").await;

            async fn one_way(
                send: &mut std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>,
                recv: &mut std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>,
                label: &str,
                bucket: u8,
            ) -> bool {
                let body = format!("tcp-{label}-{}", "t".repeat(600));
                send.send(tagged_packet(body.as_bytes(), TrafficClass::Tcp, bucket))
                    .await
                    .unwrap();
                send.flush().await.unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    loop {
                        let packet = recv.next().await.unwrap().unwrap();
                        if packet.payload().starts_with(body.as_bytes()) {
                            return;
                        }
                    }
                })
                .await
                .is_ok()
            }

            // Server stream 1, then client stream 8 (its 0 is the primary).
            assert!(one_way(&mut server_send, &mut client_recv, "s0", 0).await);
            assert!(one_way(&mut client_send, &mut server_recv, "c0", 0).await);
            // Both idle streams get reaped (housekeeping runs once a second),
            // so a new server flow needs a new server stream.
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            let delivered = one_way(&mut server_send, &mut client_recv, "s1", 1).await;
            let server_status = server_handle.data_plane_status().await.unwrap();
            let client_status = client_handle.data_plane_status().await.unwrap();
            assert!(
                delivered,
                "server tcp {:?} / client tcp {:?}",
                class_status(&server_status, "tcp"),
                class_status(&client_status, "tcp")
            );
        });
    }

    /// Oversize policy `fragment`: a frame larger than one datagram is split
    /// and reassembled whole.
    #[test]
    fn mpquic_data_plane_fragments_oversize_frames() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                oversize: "fragment".into(),
                ..Default::default()
            });
            let ((mut server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                dp_session_pair(Some(policy.clone()), Some(policy)).await;
            wait_negotiated(&client_handle, "datagram").await;
            // Larger than any datagram: the UDP payload itself is capped at 1472.
            let big = (0..1472 + 200)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>();
            assert!(big.len() < MAX_PACKET_SIZE - 64);
            client_send
                .send(tagged_packet(&big, TrafficClass::Udp, 0))
                .await
                .unwrap();
            client_send.flush().await.unwrap();
            let packet = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                .await
                .expect("reassembled frame arrives")
                .unwrap()
                .unwrap();
            assert_eq!(packet.payload(), &big[..]);
            assert!(client_handle.data_plane_status().await.unwrap().frag_sent >= 2);
            assert_eq!(server_handle.data_plane_status().await.unwrap().frag_reassembled, 1);
        });
    }

    /// Oversize policy `icmp_ptb` (the default, RFC 9484 Section 10.1): a
    /// packet that does not fit one datagram is dropped and counted, never
    /// sent on a stream. The packets after it keep arriving in order, and
    /// no stream was opened for the oversize one.
    #[test]
    fn mpquic_data_plane_drops_an_oversize_packet_instead_of_streaming_it() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                ..Default::default()
            });
            let ((mut server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                dp_session_pair(Some(policy.clone()), Some(policy)).await;
            wait_negotiated(&client_handle, "datagram").await;

            // Larger than any datagram: the UDP payload itself is capped at 1472.
            let mut labels = vec![format!("big-{}", "b".repeat(1600))];
            labels.extend((0..20).map(|i| format!("small-{i:02}")));
            for label in &labels {
                client_send
                    .send(tagged_packet(label.as_bytes(), TrafficClass::Udp, 3))
                    .await
                    .unwrap();
                client_send.flush().await.unwrap();
            }
            let mut received = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while received.len() < labels.len() {
                    let packet = server_recv.next().await.unwrap().unwrap();
                    received.push(String::from_utf8_lossy(packet.payload()).to_string());
                }
            })
            .await;
            let client_status = client_handle.data_plane_status().await.unwrap();
            assert_eq!(
                received,
                labels[1..].to_vec(),
                "the oversize packet must not arrive (client {client_status:?}, server {:?})",
                server_handle.data_plane_status().await.unwrap()
            );
            assert_eq!(client_status.oversize_dropped, 1, "{client_status:?}");
        });
    }

    /// A data-plane session and a legacy one interoperate on the single
    /// stream in both roles, byte for byte (MP_SQM_PLAN.md principle 4).
    #[test]
    fn mpquic_data_plane_falls_back_to_the_stream_with_a_legacy_peer() {
        use crate::tunnel::mp_dataplane::TrafficClass;
        RUNTIME.block_on(async {
            for (server_dp, client_dp) in [(true, false), (false, true)] {
                let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                    enabled: true,
                    ..Default::default()
                });
                let ((mut server_recv, mut server_send), server_handle, (mut client_recv, mut client_send), client_handle) = dp_session_pair(
                    server_dp.then(|| policy.clone()),
                    client_dp.then(|| policy.clone()),
                )
                .await;
                let dp_handle = if server_dp { &server_handle } else { &client_handle };
                let status = wait_negotiated(dp_handle, "stream_fallback").await;
                assert!(status.fallback_reason.contains("max_datagram_frame_size"), "{status:?}");
                let legacy_handle = if server_dp { &client_handle } else { &server_handle };
                assert_eq!(
                    legacy_handle.data_plane_status().await.unwrap().negotiated,
                    "disabled"
                );

                let payloads = (0..64)
                    .map(|i| format!("legacy-{i:03}-{}", "p".repeat(700)).into_bytes())
                    .collect::<Vec<_>>();
                for payload in &payloads {
                    client_send
                        .send(tagged_packet(payload, TrafficClass::Udp, 0))
                        .await
                        .unwrap();
                }
                client_send.flush().await.unwrap();
                for payload in &payloads {
                    let packet =
                        tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    assert_eq!(packet.payload(), &payload[..]);
                    server_send.send(tagged_packet(payload, TrafficClass::Udp, 0)).await.unwrap();
                }
                server_send.flush().await.unwrap();
                for payload in &payloads {
                    let packet =
                        tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    assert_eq!(packet.payload(), &payload[..]);
                }
            }
        });
    }

    /// OWD_AUTORATE_PLAN.md 2 (R2), two real ends over loopback, real CAKE on
    /// both: A's offered datagram load is far above A's own egress ceiling, so
    /// A's CAKE holds a standing queue, and the ACKs of B's data wait in it.
    /// B's round trips then show A's queue, which is not B's link: B's
    /// Autorate must not cut its estimate for it (RFC 6817 Section 3.1: the
    /// data direction's one-way delay, not the round trip).
    #[test]
    fn a_peers_standing_queue_does_not_cut_our_estimate() {
        // CAKE holds about two packets of backlog per path (S-I12), so the
        // standing delay is that backlog over A's ceiling: 150 kbit/s gives a
        // queue of 90 ms or more, which B's round trips then show.
        a_peers_standing_queue_leaves_our_estimate(150_000, false);
    }

    #[test]
    fn a_peers_standing_queue_does_not_cut_our_estimate_with_sqm() {
        a_peers_standing_queue_leaves_our_estimate(150_000, true);
    }

    /// The reproduction of MP_WORKLIST.md row 53 (P0): with A's ceiling so low
    /// that its queue grows to about a second, B's one-way delay probes were
    /// held back by the datagram bypass breaker (on without SQM), B's Autorate
    /// fell back to the round trip, which holds A's queue for B's ACKs, and cut
    /// its estimate to 37-40 Mbit/s of 50.
    #[test]
    fn a_peers_second_long_standing_queue_does_not_cut_our_estimate() {
        a_peers_standing_queue_leaves_our_estimate(100_000, false);
    }

    #[test]
    fn a_peers_second_long_standing_queue_does_not_cut_our_estimate_with_sqm() {
        a_peers_standing_queue_leaves_our_estimate(100_000, true);
    }

    /// `a_ceiling_bps`: A's egress ceiling, wire bits per second;
    /// `sqm_enabled`: the sessions' SQM setting (it turns the bypass breaker off).
    fn a_peers_standing_queue_leaves_our_estimate(a_ceiling_bps: u64, sqm_enabled: bool) {
        use crate::common::egress_quality::autorate::DEFAULT_AUTORATE_START_BPS;
        use crate::tunnel::mp_dataplane::TrafficClass;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        RUNTIME.block_on(async {
            let paths = real_udp_path_pair().await;
            let (b_addr, a_addr) = (paths.1, paths.3);
            let a_manager = EgressQualityManager::new(EgressQualityConfig::default());
            let b_manager = EgressQualityManager::new(EgressQualityConfig::default());
            let a_nic = a_manager.handle_for(fallback_scope_for(a_addr));
            a_nic.set_budget(Some(WireBitrate(a_ceiling_bps))).unwrap();
            let b_nic = b_manager.handle_for(fallback_scope_for(b_addr));

            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                ..Default::default()
            });
            let ((mut a_recv, a_send), a_handle, (mut b_recv, mut b_send), b_handle) =
                dp_session_pair_managed(
                    paths,
                    MpQuicSessionConfig { sqm_enabled, ..Default::default() },
                    Some(policy.clone()),
                    Some(policy),
                    a_manager,
                    b_manager,
                )
                .await;
            wait_negotiated(&a_handle, "datagram").await;
            wait_negotiated(&b_handle, "datagram").await;
            let mut a_send = Some(a_send);
            let drains = [
                tokio::spawn(async move { while let Some(Ok(_)) = a_recv.next().await {} }),
                tokio::spawn(async move { while let Some(Ok(_)) = b_recv.next().await {} }),
            ];

            // B alone first, so its minimum round trip is the idle one.
            let stop = Arc::new(AtomicBool::new(false));
            let mut a_load = None;
            let started = Instant::now();
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            let mut sampled = 0u32;
            // The smoothed round trip follows the queue, which swings; the
            // premise is about the largest it reached.
            let mut peak_srtt = 0u64;
            while started.elapsed() < Duration::from_secs(11) {
                tick.tick().await;
                if a_load.is_none() && started.elapsed() > Duration::from_millis(1_500) {
                    // ~4.8 Mbit/s offered into a 0.15 Mbit/s egress.
                    let stop = stop.clone();
                    let mut a_send = a_send.take().unwrap();
                    a_load = Some(tokio::spawn(async move {
                        let mut every = tokio::time::interval(Duration::from_millis(2));
                        let payload = [0xABu8; 1200];
                        while !stop.load(Ordering::Relaxed) {
                            every.tick().await;
                            if a_send.send(tagged_packet(&payload, TrafficClass::Udp, 1)).await.is_err() {
                                break;
                            }
                        }
                        a_send
                    }));
                }
                // ~320 kbit/s from B.
                b_send
                    .send(tagged_packet(&[0xCDu8; 1000], TrafficClass::Udp, 2))
                    .await
                    .unwrap();
                if started.elapsed() > Duration::from_millis(1_000 * (sampled as u64 + 1)) {
                    sampled += 1;
                    assert!(b_handle.request_autorate_sample());
                    if let Ok(telemetry) = b_handle.path_telemetry().await {
                        peak_srtt = peak_srtt.max(telemetry[0].srtt_micros);
                    }
                }
            }
            stop.store(true, Ordering::Relaxed);

            let queue = cake_status(&a_nic).expect("A's egress queue exists").avg_delay_us;
            let telemetry = b_handle.path_telemetry().await.unwrap();
            let srtt = peak_srtt.max(telemetry[0].srtt_micros);
            let min_rtt = telemetry[0].min_rtt_micros;
            let estimates = b_nic
                .autorate_estimate()
                .map(|estimate| (b_nic.autorate_measured(), estimate.0))
                .into_iter()
                .collect::<Vec<_>>();
            println!(
                "peer queue: A cake avg {queue} us, B srtt {srtt} us min_rtt {min_rtt} us, B estimates {estimates:?}"
            );
            assert!(queue > 50_000, "the premise: A's queue stands (avg {queue} us)");
            assert!(srtt.saturating_sub(min_rtt) > 30_000, "the premise: B's round trips show it ({srtt} us over {min_rtt} us)");
            assert!(!estimates.is_empty(), "B's Autorate never took a sample");
            for (measured, estimate) in estimates {
                assert!(
                    !measured || estimate as f64 >= DEFAULT_AUTORATE_START_BPS as f64 * 0.9,
                    "A's queue cut B's estimate to {estimate} bit/s"
                );
            }
            if let Some(load) = a_load {
                drop(load.await);
            }
            drop(b_send);
            a_handle.shutdown();
            b_handle.shutdown();
            for drain in drains {
                drain.abort();
            }
        });
    }

    /// Receive-side application backpressure is not network queueing. Probes
    /// already received by QUIC must retain their arrival time while the ET
    /// application pipe is full (RFC 6817 Section 2.3).
    #[test]
    fn application_backpressure_does_not_inflate_one_way_delay() {
        use crate::common::egress_quality::QueueDelaySource;
        use crate::tunnel::mp_dataplane::TrafficClass;
        use std::time::Duration;

        RUNTIME.block_on(async {
            let paths = real_udp_path_pair().await;
            let client_manager = EgressQualityManager::new(EgressQualityConfig::default());
            let client_nic = client_manager.handle_for(fallback_scope_for(paths.1));
            let policy = dp_policy(crate::proto::common::MpDataPlaneConfig {
                enabled: true,
                ..Default::default()
            });
            let ((mut server_recv, _server_send), server_handle,
                 (_client_recv, mut client_send), client_handle) = dp_session_pair_managed(
                paths, MpQuicSessionConfig::default(),
                Some(policy.clone()), Some(policy),
                EgressQualityManager::new(EgressQualityConfig::default()), client_manager,
            ).await;
            wait_negotiated(&client_handle, "datagram").await;
            // Establish an idle base before filling the receiver's ET pipe.
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            let idle = client_nic.publish(0, None).unwrap();
            assert_eq!(idle.source, QueueDelaySource::OneWay);
            let load = tokio::spawn(async move {
                for _ in 0..8192 {
                    if client_send.send(tagged_packet(&[0x5a; 1400], TrafficClass::Tcp, 1))
                        .await.is_err() {
                        break;
                    }
                }
                client_send
            });
            tokio::time::sleep(Duration::from_millis(800)).await;
            let telemetry = client_handle.path_telemetry().await.unwrap();
            assert!(telemetry.iter().map(|p| p.sent_bytes).sum::<u64>() > 128 * 1024,
                    "the load must exceed the unread application pipe");
            let drain = tokio::spawn(async move {
                while let Some(Ok(_)) = server_recv.next().await {}
            });
            let mut peak_queue_us = 0;
            let mut samples = 0;
            let until = Instant::now() + Duration::from_secs(1);
            while Instant::now() < until {
                let sample = client_nic.publish(0, None).unwrap();
                if sample.source == QueueDelaySource::OneWay {
                    samples += 1;
                    peak_queue_us = peak_queue_us.max(sample.queue_delay_us);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            load.abort();
            drain.abort();
            client_handle.shutdown();
            server_handle.shutdown();
            println!("application backlog: {samples} one-way samples, peak {peak_queue_us} us");
            assert!(samples > 0, "the delayed probes must actually be reported");
            assert!(peak_queue_us < 50_000,
                    "application backlog read as {peak_queue_us} us of network queue");
        });
    }

    /// The bypass breaker is off exactly when the session has SQM (CAKE below).
    #[test]
    fn datagram_bypass_breaker_is_off_with_sqm() {
        let with = |sqm_enabled| MpQuicSessionConfig {
            sqm_enabled,
            data_plane: true,
            ..Default::default()
        };
        assert!(!datagram_bypass_breaker(with(true)));
        assert!(datagram_bypass_breaker(with(false)));
    }

    #[test]
    fn data_plane_session_config_sets_datagram_transport_parameters() {
        let runtime = MpQuicSessionConfig {
            data_plane: true,
            ..Default::default()
        };
        drop((client_config(runtime).unwrap(), server_config(runtime).unwrap()));
        assert!(!MpQuicSessionConfig::default().data_plane);
    }

    /// Grey-box tests on real kernel links: client and server namespaces
    /// joined through a router namespace (`crate::tests::create_netns`, with
    /// the host ends moved into the router so the root namespace is left
    /// alone). `tc netem` / `iptables` SNAT run on the router's links.
    /// Root only: `sudo <test binary> --ignored mpquic_greybox`.
    #[cfg(target_os = "linux")]
    mod greybox {
        use super::*;
        use crate::common::netns::NetNS;
        use crate::tests::{create_netns, del_netns, get_host_veth_name};
        use crate::tunnel::mp_dataplane::TrafficClass;
        use std::net::IpAddr;
        use std::time::Duration;

        const CLIENT_NS: &str = "gbc";
        const SERVER_NS: &str = "gbs";
        const ROUTER_NS: &str = "gbr";
        const WAN1: &str = "10.77.9.1";
        const WAN2: &str = "10.77.9.3";

        fn run(args: &[&str]) {
            let out = std::process::Command::new(args[0])
                .args(&args[1..])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        fn in_ns(ns: &str, args: &[&str]) {
            let mut all = vec!["ip", "netns", "exec", ns];
            all.extend_from_slice(args);
            run(&all);
        }

        struct GreyboxNet;

        impl GreyboxNet {
            /// `netem`: qdisc arguments for both router links. `snat`: like
            /// mwan3 over two WANs, each new connection from the client leaves
            /// through the next of two public IPs (NAT rules see only a
            /// connection's first packet, so `nth` alternates per connection
            /// -- deterministic where mwan3 is random).
            fn new(netem: Option<&str>, snat: bool) -> Self {
                Self::cleanup();
                run(&["ip", "netns", "add", ROUTER_NS]);
                in_ns(ROUTER_NS, &["ip", "link", "set", "lo", "up"]);
                in_ns(ROUTER_NS, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]);
                for (ns, v4, v6, router_addrs) in [
                    (CLIENT_NS, "10.77.1.2/24", "fd77:1::2/64", vec!["10.77.1.1/24"]),
                    (SERVER_NS, "10.77.9.2/24", "fd77:9::2/64", vec!["10.77.9.1/24", "10.77.9.3/24"]),
                ] {
                    create_netns(ns, v4, v6);
                    let host = get_host_veth_name(ns);
                    run(&["ip", "link", "set", host, "netns", ROUTER_NS]);
                    for addr in router_addrs {
                        in_ns(ROUTER_NS, &["ip", "addr", "add", addr, "dev", host]);
                    }
                    in_ns(ROUTER_NS, &["ip", "link", "set", host, "up"]);
                    if let Some(netem) = netem {
                        let mut args = vec!["tc", "qdisc", "add", "dev", host, "root", "netem"];
                        args.extend(netem.split_whitespace());
                        in_ns(ROUTER_NS, &args);
                    }
                }
                in_ns(CLIENT_NS, &["ip", "route", "add", "default", "via", "10.77.1.1"]);
                in_ns(SERVER_NS, &["ip", "route", "add", "default", "via", "10.77.9.1"]);
                if snat {
                    let uplink = get_host_veth_name(SERVER_NS);
                    // The first rule takes every 2nd new connection, the
                    // second rule every connection that falls through.
                    in_ns(
                        ROUTER_NS,
                        &[
                            "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-m",
                            "statistic", "--mode", "nth", "--every", "2", "--packet", "1", "-j",
                            "SNAT", "--to-source", WAN2,
                        ],
                    );
                    in_ns(
                        ROUTER_NS,
                        &[
                            "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-j",
                            "SNAT", "--to-source", WAN1,
                        ],
                    );
                }
                GreyboxNet
            }

            fn cleanup() {
                del_netns(CLIENT_NS);
                del_netns(SERVER_NS);
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", ROUTER_NS])
                    .output();
            }
        }

        impl Drop for GreyboxNet {
            fn drop(&mut self) {
                Self::cleanup();
            }
        }

        fn path_in(ns: &str, ip: &str) -> (Arc<dyn MpDatagramPath>, SocketAddr) {
            let socket = {
                let _guard = NetNS::new(Some(ns.to_owned())).guard();
                std::net::UdpSocket::bind((ip.parse::<IpAddr>().unwrap(), 0)).unwrap()
            };
            socket.set_nonblocking(true).unwrap();
            let socket = Arc::new(UdpSocket::from_std(socket).unwrap());
            let addr = socket.local_addr().unwrap();
            let path: Arc<dyn MpDatagramPath> =
                Arc::new(SharedUnconnectedUdpDatagramPath::new_with_guard(socket, None).unwrap());
            (path, addr)
        }

        fn p99(mut samples: Vec<Duration>) -> Duration {
            samples.sort();
            samples[(samples.len() * 99 / 100).min(samples.len() - 1)]
        }

        /// Small-packet RTTs while a steady bulk flow shares the session,
        /// each ping echoed by the server.
        async fn ping_rtts_beside_bulk(data_plane: bool) -> (Vec<Duration>, usize) {
            const TICKS: u32 = 2000; // 2 ms apart: 4 s, bulk ~4 Mbit/s
            const PING_EVERY: u32 = 5;
            let (client_path, client_addr) = path_in(CLIENT_NS, "10.77.1.2");
            let (server_path, server_addr) = path_in(SERVER_NS, "10.77.9.2");
            let policy = data_plane.then(|| {
                dp_policy(crate::proto::common::MpDataPlaneConfig {
                    enabled: true,
                    ..Default::default()
                })
            });
            let ((mut server_recv, mut server_send), server_handle, (mut client_recv, mut client_send), client_handle) =
                dp_session_pair_over(
                    (client_path, client_addr, server_path, server_addr),
                    MpQuicSessionConfig::default(),
                    policy.clone(),
                    policy,
                )
                .await;
            if data_plane {
                wait_negotiated(&client_handle, "datagram").await;
                wait_negotiated(&server_handle, "datagram").await;
            }

            let echo = tokio::spawn(async move {
                while let Some(Ok(packet)) = server_recv.next().await {
                    if packet.payload().starts_with(b"ping") {
                        let reply = tagged_packet(packet.payload(), TrafficClass::Icmp, 0);
                        if server_send.send(reply).await.is_err() {
                            break;
                        }
                    }
                }
            });
            let sent_at = Arc::new(Mutex::new(HashMap::<u32, Instant>::new()));
            let receiver = {
                let sent_at = sent_at.clone();
                tokio::spawn(async move {
                    let mut rtts = Vec::new();
                    while let Ok(Some(Ok(packet))) =
                        tokio::time::timeout(Duration::from_secs(3), client_recv.next()).await
                    {
                        let Some(seq) = packet
                            .payload()
                            .strip_prefix(b"ping")
                            .and_then(|s| std::str::from_utf8(s).ok()?.parse::<u32>().ok())
                        else {
                            continue;
                        };
                        if let Some(at) = sent_at.lock().unwrap().remove(&seq) {
                            rtts.push(at.elapsed());
                        }
                    }
                    rtts
                })
            };

            let bulk = [b'b'; 1000];
            let mut tick = tokio::time::interval(Duration::from_millis(2));
            let mut pings = 0usize;
            for i in 0..TICKS {
                tick.tick().await;
                client_send
                    .feed(tagged_packet(&bulk, TrafficClass::Udp, 1))
                    .await
                    .unwrap();
                if i % PING_EVERY == 0 {
                    let seq = i / PING_EVERY;
                    sent_at.lock().unwrap().insert(seq, Instant::now());
                    client_send
                        .feed(tagged_packet(format!("ping{seq}").as_bytes(), TrafficClass::Icmp, 0))
                        .await
                        .unwrap();
                    pings += 1;
                }
                client_send.flush().await.unwrap();
            }
            let rtts = receiver.await.unwrap();
            echo.abort();
            client_handle.shutdown();
            server_handle.shutdown();
            (rtts, pings)
        }

        /// MP_SQM_PLAN.md S2.10: with 5% loss each way, small packets on the
        /// datagram data plane are no longer held behind a lost bulk packet's
        /// retransmission, so their p99 RTT is at most half the single
        /// stream's (the head-of-line blocking the data plane removes).
        #[test]
        #[ignore = "root: netns + tc netem"]
        fn mpquic_greybox_datagram_plane_cuts_small_packet_p99_under_loss() {
            RUNTIME.block_on(async {
                let _net = GreyboxNet::new(Some("delay 10ms loss 5%"), false);
                let (stream_rtts, stream_pings) = ping_rtts_beside_bulk(false).await;
                let (dgram_rtts, dgram_pings) = ping_rtts_beside_bulk(true).await;
                let (stream_p99, dgram_p99) = (p99(stream_rtts.clone()), p99(dgram_rtts.clone()));
                println!(
                    "small-packet RTT p99: single stream {stream_p99:?} ({}/{stream_pings} echoed), \
                     datagram {dgram_p99:?} ({}/{dgram_pings} echoed)",
                    stream_rtts.len(),
                    dgram_rtts.len()
                );
                // Reliable: every ping comes back. Datagrams: ~10% lost (5% each way).
                assert_eq!(stream_rtts.len(), stream_pings);
                assert!(dgram_rtts.len() >= dgram_pings * 8 / 10, "{}", dgram_rtts.len());
                assert!(
                    dgram_p99 * 2 <= stream_p99,
                    "datagram p99 {dgram_p99:?} vs single stream {stream_p99:?}"
                );
            });
        }

        /// MP_SQM_PLAN.md S2.14: one host address behind a router that
        /// spreads new connections over two WANs (mwan3). Each path learns its
        /// own WAN from the peer's OBSERVED_ADDRESS, both paths carry bytes,
        /// and the payload arrives intact.
        #[test]
        #[ignore = "root: netns + iptables"]
        fn mpquic_greybox_each_path_learns_its_wan_through_snat() {
            RUNTIME.block_on(async {
                let _net = GreyboxNet::new(None, true);
                // Two sockets on the one client address: two connections to
                // the router, so one per WAN.
                let (client_primary, client_primary_addr) = path_in(CLIENT_NS, "10.77.1.2");
                let (client_secondary, client_secondary_addr) = path_in(CLIENT_NS, "10.77.1.2");
                let (server_primary, server_primary_addr) = path_in(SERVER_NS, "10.77.9.2");
                let (server_secondary, server_secondary_addr) = path_in(SERVER_NS, "10.77.9.2");
                // SNAT keeps a free source port, so the server-side view is known.
                let wan1 = SocketAddr::new(WAN1.parse().unwrap(), client_primary_addr.port());
                let wan2 = SocketAddr::new(WAN2.parse().unwrap(), client_secondary_addr.port());
                let base = MpQuicSessionConfig {
                    algorithm: crate::tunnel::mp_plugin::MpAlgorithm::RoundRobin,
                    ..Default::default()
                };
                let ((mut server_recv, _server_send), server_handle, (_client_recv, mut client_send), client_handle) =
                    dp_session_pair_over(
                        (client_primary, wan1, server_primary, server_primary_addr),
                        base,
                        None,
                        None,
                    )
                    .await;
                server_handle
                    .add_path(server_secondary, wan2, None)
                    .await
                    .unwrap();
                client_handle
                    .add_path(client_secondary, server_secondary_addr, None)
                    .await
                    .unwrap();
                wait_for_two_validated_paths(&client_handle).await;

                let observed = tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let observed = client_handle
                            .path_telemetry()
                            .await
                            .unwrap()
                            .into_iter()
                            .filter_map(|p| p.observed_local_addr.map(|o| (p.local_addr, o)))
                            .collect::<HashMap<_, _>>();
                        if observed.len() == 2 {
                            break observed;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .expect("both paths must receive OBSERVED_ADDRESS");
                assert_eq!(observed[&client_primary_addr], wan1);
                assert_eq!(observed[&client_secondary_addr], wan2);

                let baseline = client_handle
                    .path_telemetry()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|path| (path.local_addr, path.sent_bytes))
                    .collect::<HashMap<_, _>>();
                const PACKETS: usize = 256;
                let mut sent = Sha256::new();
                for sequence in 0..PACKETS {
                    let payload = format!("mwan-{sequence:04}-{}", "w".repeat(900));
                    sent.update(payload.as_bytes());
                    client_send
                        .send(ZCPacket::new_with_payload(payload.as_bytes()))
                        .await
                        .unwrap();
                }
                client_send.flush().await.unwrap();
                let mut received = Sha256::new();
                for _ in 0..PACKETS {
                    let packet = tokio::time::timeout(Duration::from_secs(5), server_recv.next())
                        .await
                        .expect("payload reaches the server")
                        .unwrap()
                        .unwrap();
                    received.update(packet.payload());
                }
                assert_eq!(received.finalize(), sent.finalize());
                for path in client_handle.path_telemetry().await.unwrap() {
                    let carried = path.sent_bytes - baseline[&path.local_addr];
                    assert!(
                        carried > 16 * 1024,
                        "path {} (WAN {:?}) carried only {carried} bytes",
                        path.local_addr,
                        path.observed_local_addr
                    );
                }
                client_handle.shutdown();
                server_handle.shutdown();
            });
        }
    }
}
