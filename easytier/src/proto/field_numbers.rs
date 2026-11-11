//! G1: the fork-only fields in upstream-owned messages live at 1001+. These tests pin the
//! numbers on the wire: the new number is written, and bytes that still use the old number
//! (an unrenumbered peer) decode to the default because the field is ignored.

use std::fmt::Debug;

use prost::Message;

use crate::proto::{
    api::{
        config::{GetConfigResponse, InstanceConfigPatch},
        instance::{GetStatsResponse, MpPeerStatus},
        manage::{NetworkConfig, NetworkInstanceRunningInfo},
    },
    common::{FlagsInConfig, MpConfig, PeerFeatureFlag},
    peer_rpc::{
        DirectConnectedPeerInfo, RoutePeerInfo, SelectPunchListenerRequest,
        SelectPunchListenerResponse, SendPunchPacketBothEasySymRequest,
        SendPunchPacketBothEasySymResponse, SendPunchPacketConeRequest,
        SendPunchPacketEasySymRequest, SendPunchPacketHardSymRequest, TcpHolePunchRequest,
        TcpHolePunchResponse,
    },
};

const VARINT: u32 = 0;
const LEN: u32 = 2;

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn field(tag: u32, wire_type: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = varint(((tag as u64) << 3) | wire_type as u64);
    out.extend_from_slice(payload);
    out
}

/// `msg` has exactly one fork-only field set. It must encode as `new_tag` + `payload`, and the
/// same payload under `old_tag` must be ignored.
fn assert_renumbered<M: Message + Default + PartialEq + Debug>(
    msg: M,
    new_tag: u32,
    old_tag: u32,
    wire_type: u32,
    payload: &[u8],
) {
    let name = std::any::type_name::<M>();
    assert_eq!(
        msg.encode_to_vec(),
        field(new_tag, wire_type, payload),
        "{name} must be written as field {new_tag}"
    );
    assert_eq!(
        M::decode(&field(new_tag, wire_type, payload)[..]).unwrap(),
        msg,
        "{name} must read field {new_tag}"
    );
    assert_eq!(
        M::decode(&field(old_tag, wire_type, payload)[..]).unwrap(),
        M::default(),
        "{name} must ignore the retired field {old_tag}"
    );
}

const X: &[u8] = &[1, b'x'];
const ONE: &[u8] = &[1];
const EMPTY_MSG: &[u8] = &[0];

#[test]
fn flags_in_config_fork_fields() {
    assert_renumbered(
        FlagsInConfig {
            tcp_hole_punch_mode: "x".into(),
            ..Default::default()
        },
        1001,
        44,
        LEN,
        X,
    );
    assert_renumbered(
        FlagsInConfig {
            mp: Some(MpConfig::default()),
            ..Default::default()
        },
        1002,
        45,
        LEN,
        EMPTY_MSG,
    );
    assert_renumbered(
        FlagsInConfig {
            egress_wire_limit_bps: Some(1),
            ..Default::default()
        },
        1003,
        46,
        VARINT,
        ONE,
    );
}

#[test]
fn peer_feature_flag_mp_enabled() {
    assert_renumbered(
        PeerFeatureFlag {
            mp_enabled: true,
            ..Default::default()
        },
        1001,
        12,
        VARINT,
        ONE,
    );
}

#[test]
fn network_config_fork_fields() {
    assert_renumbered(
        NetworkConfig {
            tcp_hole_punch_mode: Some("x".into()),
            ..Default::default()
        },
        1016,
        68,
        LEN,
        X,
    );
    assert_renumbered(
        NetworkConfig {
            mp: Some(MpConfig::default()),
            ..Default::default()
        },
        1017,
        69,
        LEN,
        EMPTY_MSG,
    );
    assert_renumbered(
        NetworkConfig {
            egress_wire_limit_bps: Some(1),
            ..Default::default()
        },
        1018,
        70,
        VARINT,
        ONE,
    );
}

#[test]
fn network_instance_running_info_mp_runtime() {
    assert_renumbered(
        NetworkInstanceRunningInfo {
            mp_runtime: Some(Default::default()),
            ..Default::default()
        },
        1001,
        10,
        LEN,
        EMPTY_MSG,
    );
}

#[test]
fn instance_config_patch_fork_fields() {
    assert_renumbered(
        InstanceConfigPatch {
            mp: Some(MpConfig::default()),
            ..Default::default()
        },
        1001,
        15,
        LEN,
        EMPTY_MSG,
    );
    assert_renumbered(
        InstanceConfigPatch {
            tcp_hole_punch_mode: Some("x".into()),
            ..Default::default()
        },
        1002,
        16,
        LEN,
        X,
    );
    assert_renumbered(
        InstanceConfigPatch {
            egress_wire_limit_bps: Some(1),
            ..Default::default()
        },
        1003,
        17,
        VARINT,
        ONE,
    );
}

#[test]
fn get_config_response_fork_fields() {
    assert_renumbered(
        GetConfigResponse {
            mp_providers: vec!["x".into()],
            ..Default::default()
        },
        1002,
        4,
        LEN,
        X,
    );
    assert_renumbered(
        GetConfigResponse {
            tcp_hole_punch_modes: vec!["x".into()],
            ..Default::default()
        },
        1003,
        5,
        LEN,
        X,
    );
}

#[test]
fn get_stats_response_fork_fields() {
    assert_renumbered(
        GetStatsResponse {
            mp_peers: vec![MpPeerStatus::default()],
            ..Default::default()
        },
        1001,
        2,
        LEN,
        EMPTY_MSG,
    );
}

#[test]
fn route_peer_info_fork_fields() {
    assert_renumbered(
        RoutePeerInfo {
            mp_max_rx_bps: Some(1),
            ..Default::default()
        },
        1001,
        25,
        VARINT,
        ONE,
    );
    assert_renumbered(
        RoutePeerInfo {
            mp_dataplane_caps: Some(1),
            ..Default::default()
        },
        1002,
        26,
        VARINT,
        ONE,
    );
}

#[test]
fn direct_connected_peer_info_est_bw() {
    assert_renumbered(
        DirectConnectedPeerInfo {
            est_bw_bps: Some(1),
            ..Default::default()
        },
        1001,
        2,
        VARINT,
        ONE,
    );
}

#[test]
fn punch_rpc_fork_fields() {
    assert_renumbered(
        SelectPunchListenerRequest {
            use_mp: true,
            ..Default::default()
        },
        1001,
        3,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SelectPunchListenerRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1002,
        4,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SelectPunchListenerRequest {
            mp_provider: "x".into(),
            ..Default::default()
        },
        1003,
        5,
        LEN,
        X,
    );
    assert_renumbered(
        SelectPunchListenerResponse {
            mp_accepted: true,
            ..Default::default()
        },
        1001,
        2,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketConeRequest {
            use_mp: true,
            ..Default::default()
        },
        1001,
        7,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketConeRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1002,
        8,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketConeRequest {
            mp_provider: "x".into(),
            ..Default::default()
        },
        1003,
        9,
        LEN,
        X,
    );
    assert_renumbered(
        SendPunchPacketHardSymRequest {
            use_mp: true,
            ..Default::default()
        },
        1001,
        6,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketHardSymRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1002,
        7,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketEasySymRequest {
            use_mp: true,
            ..Default::default()
        },
        1001,
        7,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketEasySymRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1002,
        8,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketBothEasySymRequest {
            use_mp: true,
            ..Default::default()
        },
        1001,
        6,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketBothEasySymRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1002,
        7,
        VARINT,
        ONE,
    );
    assert_renumbered(
        SendPunchPacketBothEasySymResponse {
            mp_accepted: true,
            ..Default::default()
        },
        1001,
        3,
        VARINT,
        ONE,
    );
}

#[test]
fn tcp_punch_rpc_fork_fields() {
    assert_renumbered(
        TcpHolePunchRequest {
            requester_peer_id: 1,
            ..Default::default()
        },
        1001,
        3,
        VARINT,
        ONE,
    );
    assert_renumbered(
        TcpHolePunchRequest {
            transport_mode: "x".into(),
            ..Default::default()
        },
        1002,
        4,
        LEN,
        X,
    );
    assert_renumbered(
        TcpHolePunchResponse {
            transport_mode: "x".into(),
            ..Default::default()
        },
        1001,
        3,
        LEN,
        X,
    );
}
