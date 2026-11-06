#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
))]
mod darwin;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
mod windows;

mod route;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::process::Command;

use super::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRouteLookup {
    pub output_ifindex: u32,
    pub source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub metric: Option<u32>,
    pub table: Option<u32>,
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_stable_interface_identity(
    interface_index: u32,
) -> Result<(u64, String), String> {
    let luid = win::luid::InterfaceLuid::luid_from_index(interface_index)
        .map_err(|status| format!("ConvertInterfaceIndexToLuid failed: {status}"))?;
    let luid_value = luid.luid().Value;
    let guid = luid
        .get_guid()
        .map_err(|status| format!("ConvertInterfaceLuidToGuid failed: {status}"))?;
    let guid_text = format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7],
    );
    Ok((luid_value, guid_text))
}

#[async_trait]
pub trait IfConfiguerTrait: Send + Sync {
    async fn add_ipv4_route(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
        _cost: Option<i32>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ipv4_route(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn add_ipv4_ip(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn add_ipv6_route(
        &self,
        _name: &str,
        _address: Ipv6Addr,
        _cidr_prefix: u8,
        _cost: Option<i32>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ipv6_route(
        &self,
        _name: &str,
        _address: Ipv6Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn add_ipv6_ip(
        &self,
        _name: &str,
        _address: Ipv6Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn set_link_status(&self, _name: &str, _up: bool) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ip(&self, _name: &str, _ip: Option<Ipv4Inet>) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ipv6(&self, _name: &str, _ip: Option<Ipv6Inet>) -> Result<(), Error> {
        Ok(())
    }
    async fn wait_interface_show(&self, _name: &str) -> Result<(), Error> {
        return Ok(());
    }
    async fn set_mtu(&self, _name: &str, _mtu: u32) -> Result<(), Error> {
        Ok(())
    }
}

fn cidr_to_subnet_mask(prefix_length: u8) -> Ipv4Addr {
    if prefix_length > 32 {
        panic!("Invalid CIDR prefix length");
    }

    let subnet_mask: u32 = (!0u32)
        .checked_shl(32 - u32::from(prefix_length))
        .unwrap_or(0);
    Ipv4Addr::new(
        ((subnet_mask >> 24) & 0xFF) as u8,
        ((subnet_mask >> 16) & 0xFF) as u8,
        ((subnet_mask >> 8) & 0xFF) as u8,
        (subnet_mask & 0xFF) as u8,
    )
}

async fn run_shell_cmd(cmd: &str) -> Result<(), Error> {
    let cmd_out: std::process::Output;
    let stdout: String;
    let stderr: String;
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd_out = Command::new("cmd")
            .stdin(std::process::Stdio::null())
            .arg("/C")
            .arg(cmd)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .await?;
        stdout = crate::utils::string::utf8_or_gbk_to_string(cmd_out.stdout.as_slice());
        stderr = crate::utils::string::utf8_or_gbk_to_string(cmd_out.stderr.as_slice());
    };

    #[cfg(not(target_os = "windows"))]
    {
        cmd_out = Command::new("sh").arg("-c").arg(cmd).output().await?;
        stdout = String::from_utf8_lossy(cmd_out.stdout.as_slice()).to_string();
        stderr = String::from_utf8_lossy(cmd_out.stderr.as_slice()).to_string();
    };

    let ec = cmd_out.status.code();
    let succ = cmd_out.status.success();
    tracing::info!(?cmd, ?ec, ?succ, ?stdout, ?stderr, "run shell cmd");

    if !cmd_out.status.success() {
        return Err(Error::ShellCommandError(stdout + &stderr));
    }
    Ok(())
}

pub struct DummyIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for DummyIfConfiger {}

#[cfg(target_os = "linux")]
pub type IfConfiger = netlink::NetlinkIfConfiger;

#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
))]
pub type IfConfiger = darwin::MacIfConfiger;

#[cfg(target_os = "windows")]
pub type IfConfiger = windows::WindowsIfConfiger;

#[cfg(not(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
)))]
pub type IfConfiger = DummyIfConfiger;

#[cfg(target_os = "windows")]
pub use windows::RegistryManager;

#[cfg(target_os = "linux")]
pub(crate) fn list_ipv6_route_messages()
-> Result<Vec<netlink_packet_route::route::RouteMessage>, Error> {
    netlink::NetlinkIfConfiger::list_ipv6_route_messages()
}

#[cfg(target_os = "linux")]
pub(crate) fn get_interface_index(name: &str) -> Result<u32, Error> {
    netlink::NetlinkIfConfiger::get_interface_index(name)
}

#[cfg(target_os = "linux")]
pub(crate) fn native_route_to(
    target: IpAddr,
    output_ifindex: Option<u32>,
) -> Result<NativeRouteLookup, Error> {
    netlink::NetlinkIfConfiger::route_to(target, output_ifindex)
}

/// Link state of one enumerated interface, for the egress inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InterfaceLinkState {
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub mtu: Option<u32>,
}

/// The interface's MTU where the platform lets us read it (Linux only today).
pub(crate) fn interface_mtu(name: &str) -> Option<u32> {
    #[cfg(target_os = "linux")]
    return netlink::NetlinkIfConfiger::mtu(name)
        .ok()
        .filter(|mtu| *mtu != 0);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        None
    }
}

#[cfg(unix)]
pub(crate) fn interface_link_state(
    interface: &pnet::datalink::NetworkInterface,
) -> InterfaceLinkState {
    // Informational in the inventory.
    let mtu = interface_mtu(&interface.name);
    InterfaceLinkState {
        up: interface.is_up(),
        running: interface.is_running(),
        loopback: interface.is_loopback(),
        mtu,
    }
}

/// pnet/network-interface carry no flags on Windows; ask the interface table.
#[cfg(target_os = "windows")]
pub(crate) fn interface_link_state(
    interface: &pnet::datalink::NetworkInterface,
) -> InterfaceLinkState {
    let row = win::luid::InterfaceLuid::luid_from_index(interface.index)
        .and_then(|luid| luid.get_interface());
    match row {
        Ok(row) => {
            let up = row.OperStatus == winapi::shared::ifdef::IfOperStatusUp;
            InterfaceLinkState {
                up,
                running: up,
                // IF_TYPE_SOFTWARE_LOOPBACK (ipifcons.h).
                loopback: row.Type == 24,
                mtu: (row.Mtu != 0).then_some(row.Mtu),
            }
        }
        Err(_) => InterfaceLinkState {
            up: false,
            running: false,
            loopback: false,
            mtu: None,
        },
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) fn interface_link_state(
    interface: &pnet::datalink::NetworkInterface,
) -> InterfaceLinkState {
    InterfaceLinkState {
        up: interface.is_up(),
        running: interface.is_up(),
        loopback: interface.is_loopback(),
        mtu: None,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn native_route_to(
    target: IpAddr,
    output_ifindex: Option<u32>,
) -> Result<NativeRouteLookup, Error> {
    windows::WindowsIfConfiger::route_to(target, output_ifindex)
}

/// Bytes an interface has sent and received since it came up, from the
/// interface's own counters: all traffic on it, not only ours. The reading
/// cake-autorate takes for its load figure (`cake-autorate.sh` reads
/// `/sys/class/net/<if>/statistics/{rx,tx}_bytes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InterfaceCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl InterfaceCounters {
    /// Bytes added between two readings of one counter. macOS keeps 32-bit
    /// counters (`if_data`), so a reading below an earlier one that fits in 32
    /// bits is a wrap; any other drop is a reset of the interface and counts
    /// as nothing.
    pub(crate) fn delta(previous: u64, now: u64) -> u64 {
        if now >= previous {
            now - previous
        } else if previous <= u64::from(u32::MAX) && now <= u64::from(u32::MAX) {
            u64::from(u32::MAX) + 1 - previous + now
        } else {
            0
        }
    }
}

/// The counters of the interface `stable_id` names, or `None` where the
/// platform gives none (Android, where apps may not query netlink) or the
/// interface cannot be read.
pub(crate) fn interface_counters(
    stable_id: &super::egress_inventory::EgressStableId,
) -> Option<InterfaceCounters> {
    use super::egress_inventory::EgressStableId;
    match stable_id {
        #[cfg(target_os = "linux")]
        EgressStableId::Linux { ifindex, .. } => {
            netlink::NetlinkIfConfiger::link_counters(*ifindex).ok()
        }
        #[cfg(target_os = "windows")]
        EgressStableId::Windows { luid, .. } => {
            // GetIfEntry2 (netioapi.h): OutOctets/InOctets.
            let row = win::luid::InterfaceLuid::new(*luid).get_interface().ok()?;
            Some(InterfaceCounters {
                tx_bytes: row.OutOctets,
                rx_bytes: row.InOctets,
            })
        }
        #[cfg(target_os = "macos")]
        EgressStableId::MacOs { bsd_name, .. } => macos_link_counters(bsd_name),
        _ => None,
    }
}

/// `getifaddrs`' `AF_LINK` entry carries the interface's `if_data`.
#[cfg(target_os = "macos")]
fn macos_link_counters(bsd_name: &str) -> Option<InterfaceCounters> {
    use nix::libc;
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found = None;
    let mut entry = head;
    while !entry.is_null() {
        let ifa = unsafe { &*entry };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() == bsd_name.as_bytes()
            && !ifa.ifa_addr.is_null()
            && !ifa.ifa_data.is_null()
            && i32::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_LINK
        {
            let data = unsafe { &*(ifa.ifa_data as *const libc::if_data) };
            found = Some(InterfaceCounters {
                tx_bytes: u64::from(data.ifi_obytes),
                rx_bytes: u64::from(data.ifi_ibytes),
            });
            break;
        }
        entry = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    found
}

#[cfg(test)]
mod counter_tests {
    use super::InterfaceCounters;

    #[test]
    fn counter_delta_handles_growth_32_bit_wrap_and_reset() {
        assert_eq!(InterfaceCounters::delta(100, 250), 150);
        assert_eq!(InterfaceCounters::delta(u64::from(u32::MAX) - 9, 20), 30);
        assert_eq!(InterfaceCounters::delta(10_000_000_000, 5), 0);
    }
}
