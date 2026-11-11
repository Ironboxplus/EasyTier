use crate::common::ifcfg::win::types::{RouteDataIpv4, RouteDataIpv6};

use super::win::luid::InterfaceLuid;
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows::Win32::NetworkManagement::IpHelper::INTERNAL_IF_OPER_STATUS;
use windows::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::IpHelper::{
        GetBestInterfaceEx, GetBestRoute2, GetIfEntry, MIB_IFROW, MIB_IPFORWARD_ROW2, SetIfEntry,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
    System::Diagnostics::Debug::{
        FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
    },
};
use windows::core::PWSTR;
use winreg::{
    RegKey,
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE},
};

use super::{Error, IfConfiguerTrait, NativeRouteLookup};
pub struct WindowsIfConfiger {}

fn format_win_error(error: u32) -> String {
    // use FormatMessageW to get the error message
    let mut buffer = vec![0; 1024];
    let size = buffer.len() as u32;
    let flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    unsafe {
        FormatMessageW(
            flags,
            None,
            error,
            0,
            PWSTR(buffer.as_mut_ptr()),
            size,
            None,
        );
    }
    let str_end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    format!(
        "{} (code: {})",
        String::from_utf16_lossy(&buffer[..str_end]).trim(),
        error
    )
}

impl WindowsIfConfiger {
    fn socket_address(address: IpAddr) -> SOCKADDR_INET {
        match address {
            IpAddr::V4(address) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1: address.octets()[0],
                                s_b2: address.octets()[1],
                                s_b3: address.octets()[2],
                                s_b4: address.octets()[3],
                            },
                        },
                    },
                    ..Default::default()
                },
            },
            IpAddr::V6(address) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: address.octets(),
                        },
                    },
                    ..Default::default()
                },
            },
        }
    }

    pub(crate) fn ip_address(address: &SOCKADDR_INET) -> Option<IpAddr> {
        let family = unsafe { address.si_family };
        if family == AF_INET {
            let address = unsafe { address.Ipv4 };
            let octets = unsafe { address.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        } else if family == AF_INET6 {
            let address = unsafe { address.Ipv6 };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                address.sin6_addr.u.Byte
            })))
        } else {
            None
        }
    }

    pub(crate) fn route_to(
        target: IpAddr,
        output_ifindex: Option<u32>,
    ) -> Result<NativeRouteLookup, Error> {
        let destination = Self::socket_address(target);
        let output_ifindex = match output_ifindex {
            Some(output_ifindex) => output_ifindex,
            None => {
                let mut best_ifindex = 0;
                let status = unsafe {
                    GetBestInterfaceEx(
                        &destination as *const SOCKADDR_INET as *const SOCKADDR,
                        &mut best_ifindex,
                    )
                };
                if status != NO_ERROR.0 {
                    return Err(Error::RouteError(Some(format!(
                        "GetBestInterfaceEx failed for {target}: {}",
                        format_win_error(status)
                    ))));
                }
                best_ifindex
            }
        };

        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let status = unsafe {
            GetBestRoute2(
                None,
                output_ifindex,
                None,
                &destination,
                0,
                &mut route,
                &mut source,
            )
        };
        if status != NO_ERROR {
            return Err(Error::RouteError(Some(format!(
                "GetBestRoute2 failed for {target} via ifindex {output_ifindex}: {}",
                format_win_error(status.0)
            ))));
        }

        let gateway = Self::ip_address(&route.NextHop).filter(|gateway| !gateway.is_unspecified());
        Ok(NativeRouteLookup {
            output_ifindex: route.InterfaceIndex,
            source: Self::ip_address(&source).filter(|source| !source.is_unspecified()),
            gateway,
            metric: Some(route.Metric),
            table: None,
        })
    }

    pub fn get_interface_index(name: &str) -> Option<u32> {
        crate::arch::windows::find_interface_index(name).ok()
    }

    #[tracing::instrument(err, ret)]
    async fn add_ip_address(name: &str, addr: Ipv4Inet) -> Result<(), Error> {
        let if_index = Self::get_interface_index(name).ok_or(Error::NotFound)?;
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        luid.add_ipv4_address(&addr)
            .map_err(|e| anyhow::anyhow!("Failed to add IPv4 address: {}", format_win_error(e)))?;
        Ok(())
    }

    #[tracing::instrument(err, ret)]
    async fn remove_ip_address(name: &str, addr: Option<Ipv4Inet>) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        if let Some(addr) = addr {
            luid.delete_ipv4_address(&addr).map_err(|e| {
                anyhow::anyhow!("Failed to delete IPv4 address: {}", format_win_error(e))
            })?;
        } else {
            luid.flush_ipv4_addresses().map_err(|e| {
                anyhow::anyhow!("Failed to flush IPv4 addresses: {}", format_win_error(e))
            })?;
        }
        Ok(())
    }

    #[tracing::instrument(err, ret)]
    async fn set_interface_status(name: &str, up: bool) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut if_row = MIB_IFROW {
                wszName: [0; 256],
                dwIndex: if_index,
                dwType: 0,
                dwMtu: 0,
                dwSpeed: 0,
                dwPhysAddrLen: 0,
                bPhysAddr: [0; 8],
                dwAdminStatus: if up { 1 } else { 2 }, // 1 = up, 2 = down
                dwOperStatus: INTERNAL_IF_OPER_STATUS(0),
                dwLastChange: 0,
                dwInOctets: 0,
                dwInUcastPkts: 0,
                dwInNUcastPkts: 0,
                dwInDiscards: 0,
                dwInErrors: 0,
                dwInUnknownProtos: 0,
                dwOutOctets: 0,
                dwOutUcastPkts: 0,
                dwOutNUcastPkts: 0,
                dwOutDiscards: 0,
                dwOutErrors: 0,
                dwOutQLen: 0,
                dwDescrLen: 0,
                bDescr: [0; 256],
            };

            if GetIfEntry(&mut if_row) == NO_ERROR.0 {
                if SetIfEntry(&if_row) == NO_ERROR.0 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Failed to set interface status").into())
                }
            } else {
                Err(anyhow::anyhow!("Failed to get interface entry").into())
            }
        }
    }

    #[tracing::instrument(err, ret)]
    async fn set_interface_mtu(name: &str, mtu: u32) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        luid.set_iface_config(mtu).map_err(|e| {
            anyhow::anyhow!("Failed to set interface config: {}", format_win_error(e))
        })?;
        Ok(())
    }

    #[tracing::instrument(err, ret)]
    async fn add_ipv6_address(name: &str, addr: Ipv6Inet) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        luid.add_ipv6_address(&addr)
            .map_err(|e| anyhow::anyhow!("Failed to add IPv6 address: {}", format_win_error(e)))?;
        Ok(())
    }

    #[tracing::instrument(err, ret)]
    async fn remove_ipv6_address(name: &str, addr: Option<Ipv6Inet>) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        if let Some(addr) = addr {
            luid.delete_ipv6_address(&addr).map_err(|e| {
                anyhow::anyhow!("Failed to delete IPv6 address: {}", format_win_error(e))
            })?;
        } else {
            luid.flush_ipv6_addresses().map_err(|e| {
                anyhow::anyhow!("Failed to flush IPv6 addresses: {}", format_win_error(e))
            })?;
        }
        Ok(())
    }
}

#[async_trait]
impl IfConfiguerTrait for WindowsIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;

        luid.add_routes_ipv4([RouteDataIpv4 {
            destination: Ipv4Inet::new(address, cidr_prefix).unwrap(),
            next_hop: Ipv4Addr::UNSPECIFIED,
            metric: cost.unwrap_or(9000) as u32,
        }])
        .map_err(|e| anyhow::anyhow!("Failed to add route: {}", format_win_error(e)))?;
        Ok(())
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;
        luid.delete_route_ipv4(
            &Ipv4Inet::new(address, cidr_prefix).unwrap(),
            &Ipv4Addr::UNSPECIFIED,
        )
        .map_err(|e| anyhow::anyhow!("Failed to delete route: {}", format_win_error(e)))?;
        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        Self::add_ip_address(name, Ipv4Inet::new(address, cidr_prefix).unwrap()).await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        Self::set_interface_status(name, up).await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        Self::remove_ip_address(name, ip).await
    }

    async fn wait_interface_show(&self, name: &str) -> Result<(), Error> {
        loop {
            if let Some(idx) = Self::get_interface_index(name) {
                tracing::info!(?name, ?idx, "Interface found");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        Self::set_interface_mtu(name, mtu).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        Self::add_ipv6_address(name, Ipv6Inet::new(address, cidr_prefix).unwrap()).await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        Self::remove_ipv6_address(name, ip).await
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;

        luid.add_routes_ipv6([RouteDataIpv6 {
            destination: Ipv6Inet::new(address, cidr_prefix).unwrap(),
            next_hop: Ipv6Addr::UNSPECIFIED,
            metric: cost.unwrap_or(9000) as u32,
        }])
        .map_err(|e| anyhow::anyhow!("Failed to add route: {}", format_win_error(e)))?;
        Ok(())
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let luid = InterfaceLuid::luid_from_index(if_index).map_err(|e| {
            anyhow::anyhow!("Failed to get interface luid: {}", format_win_error(e))
        })?;

        luid.delete_route_ipv6(
            &Ipv6Inet::new(address, cidr_prefix).unwrap(),
            &Ipv6Addr::UNSPECIFIED,
        )
        .map_err(|e| anyhow::anyhow!("Failed to delete route: {}", format_win_error(e)))?;
        Ok(())
    }
}

pub struct RegistryManager;

impl RegistryManager {
    pub const IPV4_TCPIP_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
    pub const IPV6_TCPIP_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";
    pub const NETBT_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_";

    pub fn reg_delete_obsoleted_items(dev_name: &str) -> io::Result<()> {
        use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE, enums::KEY_ALL_ACCESS};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let profiles_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            KEY_ALL_ACCESS,
        )?;
        let unmanaged_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
            KEY_ALL_ACCESS,
        )?;
        // collect subkeys to delete
        let mut keys_to_delete = Vec::new();
        let mut keys_to_delete_unmanaged = Vec::new();
        for subkey_name in profiles_key.enum_keys().filter_map(Result::ok) {
            let subkey = profiles_key.open_subkey(&subkey_name)?;
            // check if ProfileName contains "et"
            match subkey.get_value::<String, _>("ProfileName") {
                Ok(profile_name) => {
                    if profile_name.contains("et_")
                        || (!dev_name.is_empty() && dev_name == profile_name)
                    {
                        keys_to_delete.push(subkey_name);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        for subkey_name in unmanaged_key.enum_keys().filter_map(Result::ok) {
            let subkey = unmanaged_key.open_subkey(&subkey_name)?;
            // check if ProfileName contains "et"
            match subkey.get_value::<String, _>("Description") {
                Ok(profile_name) => {
                    if profile_name.contains("et_")
                        || (!dev_name.is_empty() && dev_name == profile_name)
                    {
                        keys_to_delete_unmanaged.push(subkey_name);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        // delete collected subkeys
        if !keys_to_delete.is_empty() {
            for subkey_name in keys_to_delete {
                match profiles_key.delete_subkey_all(&subkey_name) {
                    Ok(_) => tracing::trace!("Successfully deleted subkey: {}", subkey_name),
                    Err(e) => tracing::error!("Failed to delete subkey {}: {}", subkey_name, e),
                }
            }
        }
        if !keys_to_delete_unmanaged.is_empty() {
            for subkey_name in keys_to_delete_unmanaged {
                match unmanaged_key.delete_subkey_all(&subkey_name) {
                    Ok(_) => tracing::trace!("Successfully deleted subkey: {}", subkey_name),
                    Err(e) => tracing::error!("Failed to delete subkey {}: {}", subkey_name, e),
                }
            }
        }
        Ok(())
    }

    pub fn reg_change_catrgory_in_profile(dev_name: &str) -> io::Result<()> {
        use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE, enums::KEY_ALL_ACCESS};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let profiles_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            KEY_ALL_ACCESS,
        )?;

        for subkey_name in profiles_key.enum_keys().filter_map(Result::ok) {
            let subkey = profiles_key.open_subkey_with_flags(&subkey_name, KEY_ALL_ACCESS)?;
            match subkey.get_value::<String, _>("ProfileName") {
                Ok(profile_name) => {
                    if !dev_name.is_empty() && dev_name == profile_name {
                        match subkey.set_value("Category", &1u32) {
                            Ok(_) => tracing::trace!("Successfully set Category in registry"),
                            Err(e) => tracing::error!("Failed to set Category in registry: {}", e),
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        Ok(())
    }

    // 根据接口名称查找 GUID
    pub fn find_interface_guid(interface_name: &str) -> io::Result<String> {
        // 注册表路径：所有网络接口的根目录
        let network_key_path =
            r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let network_key = hklm.open_subkey_with_flags(network_key_path, KEY_READ)?;

        // 遍历该路径下的所有 GUID 子键
        for guid in network_key.enum_keys().map_while(Result::ok) {
            if let Ok(guid_key) = network_key.open_subkey_with_flags(&guid, KEY_READ) {
                // 检查 Connection/Name 是否匹配目标接口名
                if let Ok(conn_key) = guid_key.open_subkey_with_flags("Connection", KEY_READ)
                    && let Ok(name) = conn_key.get_value::<String, _>("Name")
                    && name == interface_name
                {
                    return Ok(guid);
                }
            }
        }

        // 如果没有找到对应的接口
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Interface not found",
        ))
    }

    // 打开注册表键
    pub fn open_interface_key(interface_guid: &str, prefix: &str) -> io::Result<RegKey> {
        let path = format!(r"{}{}", prefix, interface_guid);
        let hkey_local_machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        hkey_local_machine.open_subkey_with_flags(&path, KEY_WRITE)
    }

    // 禁用动态 DNS 更新
    // disableDynamicUpdates sets the appropriate registry values to prevent the
    // Windows DHCP client from sending dynamic DNS updates for our interface to
    // AD domain controllers.
    pub fn disable_dynamic_updates(interface_guid: &str) -> io::Result<()> {
        let prefixes = [
            Self::IPV4_TCPIP_INTERFACE_PREFIX,
            Self::IPV6_TCPIP_INTERFACE_PREFIX,
        ];

        for prefix in &prefixes {
            let key = match Self::open_interface_key(interface_guid, prefix) {
                Ok(k) => k,
                Err(e) => {
                    // 模拟 mute-key-not-found-if-closing 行为
                    if matches!(e.kind(), io::ErrorKind::NotFound) {
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            key.set_value("RegistrationEnabled", &0u32)?;
            key.set_value("DisableDynamicUpdate", &1u32)?;
            key.set_value("MaxNumberOfAddressesToRegister", &0u32)?;
        }

        Ok(())
    }

    // 设置单个 DWORD 值到指定的注册表路径下
    fn set_single_dword(
        interface_guid: &str,
        prefix: &str,
        value_name: &str,
        data: u32,
    ) -> io::Result<()> {
        let key = match Self::open_interface_key(interface_guid, prefix) {
            Ok(k) => k,
            Err(e) => {
                // 模拟 muteKeyNotFoundIfClosing 行为：忽略 Key Not Found 错误
                return if matches!(e.kind(), io::ErrorKind::NotFound) {
                    Ok(())
                } else {
                    Err(e)
                };
            }
        };

        key.set_value(value_name, &data)?;
        Ok(())
    }

    // 禁用 NetBIOS 名称解析请求
    pub fn disable_netbios(interface_guid: &str) -> io::Result<()> {
        Self::set_single_dword(
            interface_guid,
            Self::NETBT_INTERFACE_PREFIX,
            "NetbiosOptions",
            2,
        )
    }
}
