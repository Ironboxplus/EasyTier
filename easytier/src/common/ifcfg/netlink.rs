use std::{
    ffi::CString,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZero,
    os::fd::AsRawFd,
};

use anyhow::Context;
use async_trait::async_trait;
use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkDeserializable,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkMessage},
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteProtocol,
        RouteScope, RouteType,
    },
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    ifaddrs::getifaddrs,
    libc::{self, Ioctl, SIOCGIFFLAGS, SIOCGIFMTU, SIOCSIFFLAGS, SIOCSIFMTU, ifreq, ioctl},
    net::if_::InterfaceFlags,
    sys::socket::SockaddrLike as _,
};
use pnet::ipnetwork::ip_mask_to_prefix;

use super::{Error, IfConfiguerTrait, InterfaceCounters, NativeRouteLookup, route::Route};

pub(crate) fn dummy_socket() -> Result<std::net::UdpSocket, Error> {
    Ok(std::net::UdpSocket::bind("0:0")?)
}

fn build_ifreq(name: &str) -> ifreq {
    let c_str = CString::new(name).unwrap();
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = c_str.as_bytes_with_nul();
    for (i, &b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn send_netlink_req<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    flags: u16,
) -> Result<Socket, Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut req: NetlinkMessage<T> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(req));
    req.header.flags = flags;

    req.finalize();
    let mut buf = vec![0; req.header.length as _];
    req.serialize(&mut buf);

    tracing::debug!("net link request >>> {:?}", req);
    socket.send(&buf, 0)?;

    Ok(socket)
}

fn send_netlink_req_and_wait_one_resp<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    is_remove: bool,
) -> Result<(), Error> {
    let socket = send_netlink_req(
        req,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REQUEST | if !is_remove { NLM_F_EXCL } else { 0 },
    )?;
    let resp = socket.recv_from_full()?;
    let ret = NetlinkMessage::<T>::deserialize(&resp.0)
        .with_context(|| "Failed to deserialize netlink message")?;

    tracing::debug!("net link response <<< {:?}", ret);

    match ret.payload {
        NetlinkPayload::Error(e) => {
            if e.code == NonZero::new(0) {
                Ok(())
            } else {
                Err(e.to_io().into())
            }
        }
        p => {
            tracing::error!("Unexpected netlink response: {:?}", p);
            Err(anyhow::anyhow!("Unexpected netlink response").into())
        }
    }
}

fn addr_to_ip(addr: RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(addr.into()),
        RouteAddress::Inet6(addr) => Some(addr.into()),
        _ => None,
    }
}

impl From<RouteMessage> for Route {
    fn from(msg: RouteMessage) -> Self {
        let mut gateway = None;
        let mut source = None;
        let mut source_hint = None;
        let mut destination = None;
        let mut ifindex = None;
        let mut metric = None;

        for attr in msg.attributes {
            match attr {
                RouteAttribute::Source(addr) => {
                    source = addr_to_ip(addr);
                }
                RouteAttribute::PrefSource(addr) => {
                    source_hint = addr_to_ip(addr);
                }
                RouteAttribute::Destination(addr) => {
                    destination = addr_to_ip(addr);
                }
                RouteAttribute::Gateway(addr) => {
                    gateway = addr_to_ip(addr);
                }
                RouteAttribute::Oif(i) => {
                    ifindex = Some(i);
                }
                RouteAttribute::Priority(priority) => {
                    metric = Some(priority);
                }
                _ => {}
            }
        }
        // rtnetlink gives None instead of 0.0.0.0 for the default route, but we'll convert to 0 here to make it match the other platforms
        let destination = destination.unwrap_or_else(|| match msg.header.address_family {
            AddressFamily::Inet => Ipv4Addr::UNSPECIFIED.into(),
            AddressFamily::Inet6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => panic!("invalid destination family"),
        });
        Self {
            destination,
            prefix: msg.header.destination_prefix_length,
            source,
            source_prefix: msg.header.source_prefix_length,
            source_hint,
            gateway,
            ifindex,
            table: msg.header.table,
            metric,
        }
    }
}

pub struct NetlinkIfConfiger {}

impl NetlinkIfConfiger {
    pub(crate) fn get_interface_index(name: &str) -> Result<u32, Error> {
        let name = CString::new(name).with_context(|| "failed to convert interface name")?;
        match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => Err(std::io::Error::last_os_error().into()),
            n => Ok(n),
        }
    }

    pub(crate) fn route_to(
        target: IpAddr,
        output_ifindex: Option<u32>,
    ) -> Result<NativeRouteLookup, Error> {
        let mut request = RouteMessage::default();
        request.header.table = RouteHeader::RT_TABLE_UNSPEC;
        request.header.protocol = RouteProtocol::Unspec;
        request.header.scope = RouteScope::Universe;
        request.header.kind = RouteType::Unicast;
        request.header.flags = RouteFlags::LookupTable;
        request.header.source_prefix_length = 0;
        match target {
            IpAddr::V4(target) => {
                request.header.address_family = AddressFamily::Inet;
                request.header.destination_prefix_length = 32;
                request
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet(target)));
            }
            IpAddr::V6(target) => {
                request.header.address_family = AddressFamily::Inet6;
                request.header.destination_prefix_length = 128;
                request
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet6(target)));
            }
        }
        if let Some(output_ifindex) = output_ifindex {
            request.attributes.push(RouteAttribute::Oif(output_ifindex));
        }

        let socket = send_netlink_req(RouteNetlinkMessage::GetRoute(request), NLM_F_REQUEST)?;
        let mut response = Vec::<u8>::new();
        loop {
            if response.is_empty() {
                let (next, _) = socket.recv_from_full()?;
                response = next;
            }
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response)
                .with_context(|| "Failed to deserialize RTM_GETROUTE response")?;
            response = response.split_off(message.buffer_len());

            tracing::debug!(?message, "RTM_GETROUTE response");
            match message.payload {
                NetlinkPayload::Error(error) => {
                    if error.code == NonZero::new(0) {
                        continue;
                    }
                    return Err(error.to_io().into());
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                    let mut selected_ifindex = None;
                    let mut source = None;
                    let mut gateway = None;
                    let mut metric = None;
                    let mut table = (route.header.table != RouteHeader::RT_TABLE_UNSPEC)
                        .then_some(u32::from(route.header.table));
                    for attribute in route.attributes {
                        match attribute {
                            RouteAttribute::Source(address) => {
                                source = source.or_else(|| addr_to_ip(address));
                            }
                            RouteAttribute::PrefSource(address) => {
                                source = addr_to_ip(address);
                            }
                            RouteAttribute::Gateway(address) => {
                                gateway = addr_to_ip(address);
                            }
                            RouteAttribute::Oif(ifindex) => {
                                selected_ifindex = Some(ifindex);
                            }
                            RouteAttribute::Priority(priority) => {
                                metric = Some(priority);
                            }
                            RouteAttribute::Table(table_id) => {
                                table = Some(table_id);
                            }
                            _ => {}
                        }
                    }
                    let output_ifindex = selected_ifindex.ok_or_else(|| {
                        Error::RouteError(Some(format!(
                            "RTM_GETROUTE returned no output interface for {target}"
                        )))
                    })?;
                    return Ok(NativeRouteLookup {
                        output_ifindex,
                        source,
                        gateway,
                        metric,
                        table,
                    });
                }
                NetlinkPayload::Done(_) => {
                    return Err(Error::RouteError(Some(format!(
                        "RTM_GETROUTE returned no route for {target}"
                    ))));
                }
                payload => {
                    return Err(Error::RouteError(Some(format!(
                        "unexpected RTM_GETROUTE response for {target}: {payload:?}"
                    ))));
                }
            }
        }
    }

    fn get_prefix_len(name: &str, ip: Ipv4Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V4(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ip(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(ip)));

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::DelAddress(message),
            true,
        )
    }

    fn get_prefix_len_ipv6(name: &str, ip: Ipv6Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V6(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ipv6(name: &str, ip: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet6;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V6(ip)));

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::DelAddress(message),
            true,
        )
    }

    pub(crate) fn mtu_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        value: libc::c_int,
    ) -> Result<u32, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let dummy_socket = dummy_socket()?;

        let mut ifr: ifreq = build_ifreq(name);

        unsafe {
            ifr.ifr_ifru.ifru_mtu = value;

            // 使用ioctl获取MTU
            if ioctl(dummy_socket.as_raw_fd(), op.try_into().unwrap(), &mut ifr) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu as u32 })
    }

    /// The interface's byte counters (`IFLA_STATS64`) through RTM_GETLINK.
    pub(crate) fn link_counters(ifindex: u32) -> Result<InterfaceCounters, Error> {
        let mut request = LinkMessage::default();
        request.header.index = ifindex;
        let socket = send_netlink_req(RouteNetlinkMessage::GetLink(request), NLM_F_REQUEST)?;
        let mut response = Vec::<u8>::new();
        loop {
            if response.is_empty() {
                let (next, _) = socket.recv_from_full()?;
                response = next;
            }
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response)
                .with_context(|| "Failed to deserialize RTM_GETLINK response")?;
            response = response.split_off(message.buffer_len());
            match message.payload {
                NetlinkPayload::Error(error) => {
                    if error.code == NonZero::new(0) {
                        continue;
                    }
                    return Err(error.to_io().into());
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                    return link
                        .attributes
                        .into_iter()
                        .find_map(|attribute| match attribute {
                            LinkAttribute::Stats64(stats) => Some(InterfaceCounters {
                                tx_bytes: stats.tx_bytes,
                                rx_bytes: stats.rx_bytes,
                            }),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!("RTM_GETLINK for ifindex {ifindex} has no IFLA_STATS64")
                                .into()
                        });
                }
                other => {
                    return Err(
                        anyhow::anyhow!("unexpected RTM_GETLINK response: {other:?}").into()
                    );
                }
            }
        }
    }

    pub(crate) fn mtu(name: &str) -> Result<u32, Error> {
        Self::mtu_op(name, SIOCGIFMTU, 0)
    }

    pub fn list_addresses(name: &str) -> Result<Vec<IpInet>, Error> {
        let mut result = vec![];

        for interface in getifaddrs()
            .with_context(|| "failed to call getifaddrs")?
            .filter(|x| x.interface_name == name)
        {
            let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
                continue;
            };

            use nix::sys::socket::AddressFamily::{Inet, Inet6};

            let (address, netmask) = match (address.family(), netmask.family()) {
                (Some(Inet), Some(Inet)) => (
                    IpAddr::V4(address.as_sockaddr_in().unwrap().ip()),
                    IpAddr::V4(netmask.as_sockaddr_in().unwrap().ip()),
                ),
                (Some(Inet6), Some(Inet6)) => (
                    IpAddr::V6(address.as_sockaddr_in6().unwrap().ip()),
                    IpAddr::V6(netmask.as_sockaddr_in6().unwrap().ip()),
                ),
                (_, _) => continue,
            };

            let prefix = ip_mask_to_prefix(netmask).unwrap();

            result.push(IpInet::new(address, prefix).unwrap());
        }
        Ok(result)
    }

    pub(crate) fn set_flags_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        flags: InterfaceFlags,
    ) -> Result<InterfaceFlags, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let mut req = build_ifreq(name);
        req.ifr_ifru.ifru_flags = flags.bits() as _;

        let socket = dummy_socket()?;

        unsafe {
            if ioctl(socket.as_raw_fd(), op.try_into().unwrap(), &req) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(InterfaceFlags::from_bits_truncate(
                req.ifr_ifru.ifru_flags as _,
            ))
        }
    }

    pub(crate) fn set_flags(name: &str, flags: InterfaceFlags) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCSIFFLAGS, flags)
    }

    pub(crate) fn get_flags(name: &str) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCGIFFLAGS, InterfaceFlags::empty())
    }

    fn list_route_messages(address_family: AddressFamily) -> Result<Vec<RouteMessage>, Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_UNSPEC;
        message.header.protocol = RouteProtocol::Unspec;

        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;

        message.header.address_family = address_family;
        message.header.destination_prefix_length = 0;
        message.header.source_prefix_length = 0;

        let s = send_netlink_req(
            RouteNetlinkMessage::GetRoute(message),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;

        let mut ret_vec = vec![];

        let mut resp = Vec::<u8>::new();
        loop {
            if resp.is_empty() {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }
            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink message")?;
            resp = resp.split_off(ret.buffer_len());

            tracing::debug!("net link response <<< {:?}", ret);

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    tracing::debug!("net link response <<< {:?}", m);
                    ret_vec.push(m);
                }
                NetlinkPayload::Done(_) => {
                    break;
                }
                p => {
                    tracing::error!("Unexpected netlink response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink response").into());
                }
            }
        }

        Ok(ret_vec)
    }

    fn list_routes() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(AddressFamily::Inet)
    }

    pub(crate) fn list_ipv6_route_messages() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(AddressFamily::Inet6)
    }
}

#[async_trait]
impl IfConfiguerTrait for NetlinkIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;
        message.header.address_family = AddressFamily::Inet;
        // metric
        message
            .attributes
            .push(RouteAttribute::Priority(cost.unwrap_or(65535) as u32));
        // output interface
        message
            .attributes
            .push(RouteAttribute::Oif(NetlinkIfConfiger::get_interface_index(
                name,
            )?));
        // source address
        message.header.destination_prefix_length = cidr_prefix;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(address)));

        send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::NewRoute(message), false)
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_routes()?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let other_route: Route = msg.clone().into();
            if other_route.destination == std::net::IpAddr::V4(address)
                && other_route.prefix == cidr_prefix
                && other_route.ifindex == Some(ifidx)
            {
                send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::DelRoute(msg), true)?;
                return Ok(());
            }
        }

        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut message = AddressMessage::default();

        message.header.prefix_len = cidr_prefix;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(address)));

        // for IPv4 the IFA_LOCAL address can be set to the same value as
        // IFA_ADDRESS
        message
            .attributes
            .push(AddressAttribute::Local(std::net::IpAddr::V4(address)));

        // set the IFA_BROADCAST address as well
        if cidr_prefix == 32 {
            message
                .attributes
                .push(AddressAttribute::Broadcast(address));
        } else {
            let ip_addr = u32::from(address);
            let brd = Ipv4Addr::from((0xffff_ffff_u32) >> u32::from(cidr_prefix) | ip_addr);
            message.attributes.push(AddressAttribute::Broadcast(brd));
        };

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::NewAddress(message),
            false,
        )
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        let mut flags = Self::get_flags(name)?;
        flags.set(InterfaceFlags::IFF_UP, up);
        Self::set_flags(name, flags)?;
        Ok(())
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            let prefix_len = Self::get_prefix_len(name, ip.address())?;
            Self::remove_one_ip(name, ip.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.address() {
                    Self::remove_one_ip(name, ipv4, addr.network_length())?;
                }
            }
        }

        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        Self::mtu_op(name, SIOCSIFMTU, mtu as libc::c_int)?;

        Ok(())
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut message = AddressMessage::default();

        message.header.prefix_len = cidr_prefix;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet6;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V6(address)));

        // For IPv6, we don't need IFA_LOCAL or IFA_BROADCAST
        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::NewAddress(message),
            false,
        )
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ipv6) = ip {
            let prefix_len = Self::get_prefix_len_ipv6(name, ipv6.address())?;
            Self::remove_one_ipv6(name, ipv6.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V6(ipv6) = addr.address() {
                    let prefix_len = addr.network_length();
                    Self::remove_one_ipv6(name, ipv6, prefix_len)?;
                }
            }
        }

        Ok(())
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut message = RouteMessage::default();

        message.header.address_family = AddressFamily::Inet6;
        message.header.destination_prefix_length = cidr_prefix;
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;

        message
            .attributes
            .push(RouteAttribute::Priority(cost.unwrap_or(65535) as u32));

        message
            .attributes
            .push(RouteAttribute::Oif(NetlinkIfConfiger::get_interface_index(
                name,
            )?));

        if cidr_prefix != 0 {
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(address)));
        }

        send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::NewRoute(message), false)
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_route_messages(AddressFamily::Inet6)?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let other_route: Route = msg.clone().into();
            if other_route.destination == std::net::IpAddr::V6(address)
                && other_route.prefix == cidr_prefix
                && other_route.ifindex == Some(ifidx)
            {
                send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::DelRoute(msg), true)?;
                return Ok(());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const DUMMY_IFACE_NAME: &str = "dummy";

    /// The ioctl fills `ifr` in place: read through a shared reference, an optimized build takes
    /// the value written before the call and reports 0 (the egress inventory then had no MTU).
    /// Needs no privilege: the loopback interface always exists.
    #[test]
    fn mtu_reads_what_the_kernel_reports() {
        assert_ne!(NetlinkIfConfiger::mtu("lo").unwrap(), 0);
        assert_eq!(
            super::super::interface_mtu("lo"),
            NetlinkIfConfiger::mtu("lo").ok()
        );
    }

    fn run_cmd(cmd: &str) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("failed to execute process");
        assert!(
            output.status.success(),
            "command failed: {cmd}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn run_ip(args: &[&str]) {
        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute ip process");
        assert!(
            output.status.success(),
            "ip command failed: {:?}\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn test_iface_name(tag: &str) -> String {
        format!("et{}{:x}", tag, std::process::id() & 0xffff)
    }

    struct ScopedDummyLink {
        name: String,
    }

    impl ScopedDummyLink {
        fn new(name: &str) -> Self {
            let _ = Command::new("ip").args(["link", "del", name]).output();
            run_ip(&["link", "add", name, "type", "dummy"]);
            run_ip(&["link", "set", name, "up"]);
            Self {
                name: name.to_string(),
            }
        }
    }

    impl Drop for ScopedDummyLink {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", &self.name])
                .output();
        }
    }

    struct PrepareEnv {}
    impl PrepareEnv {
        fn new() -> Self {
            let _ = Command::new("ip")
                .args(["link", "del", DUMMY_IFACE_NAME])
                .output();
            let _ = run_cmd(&format!("ip link add {} type dummy", DUMMY_IFACE_NAME));
            PrepareEnv {}
        }
    }

    impl Drop for PrepareEnv {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", DUMMY_IFACE_NAME])
                .output();
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn addr_test() {
        let _prepare_env = PrepareEnv::new();
        let ifcfg = NetlinkIfConfiger {};
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        ifcfg
            .add_ipv4_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .await
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0].address(),
            IpAddr::V4("10.44.44.4".parse().unwrap())
        );
        assert_eq!(addrs[0].network_length(), 24);

        NetlinkIfConfiger::remove_one_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 0);

        let old_mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_ne!(old_mtu, 0);

        let new_mtu = old_mtu + 1;
        ifcfg.set_mtu(DUMMY_IFACE_NAME, new_mtu).await.unwrap();

        let mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(mtu, new_mtu);

        ifcfg
            .set_link_status(DUMMY_IFACE_NAME, false)
            .await
            .unwrap();
        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn route_test() {
        let _prepare_env = PrepareEnv::new();
        let ret = NetlinkIfConfiger::list_routes().unwrap();

        let ifcfg = NetlinkIfConfiger {};
        println!("{:?}", ret);

        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();

        ifcfg
            .add_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24, None)
            .await
            .unwrap();

        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .map(Route::from)
            .map(|x| x.destination)
            .collect::<Vec<_>>();
        assert!(routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));

        ifcfg
            .remove_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24)
            .await
            .unwrap();
        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .map(Route::from)
            .map(|x| x.destination)
            .collect::<Vec<_>>();
        assert!(!routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_addr_readback_test() {
        let iface = test_iface_name("a");
        let _link = ScopedDummyLink::new(&iface);
        run_ip(&["-6", "addr", "add", "2001:db8:1234::2/64", "dev", &iface]);

        let addrs = NetlinkIfConfiger::list_addresses(&iface).unwrap();
        assert!(addrs.iter().any(|addr| {
            addr.address() == IpAddr::V6("2001:db8:1234::2".parse().unwrap())
                && addr.network_length() == 64
        }));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_route_readback_test() {
        let wan_if = test_iface_name("rw");
        let lan_if = test_iface_name("rl");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _lan = ScopedDummyLink::new(&lan_if);
        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:100:ffff::2/64",
            "dev",
            &wan_if,
        ]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8:100::/56",
            "dev",
            &wan_if,
        ]);
        run_ip(&["-6", "route", "add", "2001:db8:100::/56", "dev", &lan_if]);

        let wan_ifindex = NetlinkIfConfiger::get_interface_index(&wan_if).unwrap();
        let lan_ifindex = NetlinkIfConfiger::get_interface_index(&lan_if).unwrap();
        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();

        assert!(routes.iter().any(|route| {
            route.header.kind == RouteType::Unicast
                && route.header.source_prefix_length == 56
                && route.attributes.iter().any(|attr| {
                    matches!(
                        attr,
                        RouteAttribute::Source(RouteAddress::Inet6(addr))
                            if *addr == "2001:db8:100::".parse::<std::net::Ipv6Addr>().unwrap()
                    )
                })
                && route
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, RouteAttribute::Oif(index) if *index == wan_ifindex))
                && !route
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, RouteAttribute::Destination(_)))
        }));

        assert!(routes.iter().any(|route| {
            route.header.kind == RouteType::Unicast
                && route.header.destination_prefix_length == 56
                && route.attributes.iter().any(|attr| {
                    matches!(
                        attr,
                        RouteAttribute::Destination(RouteAddress::Inet6(addr))
                            if *addr == "2001:db8:100::".parse::<std::net::Ipv6Addr>().unwrap()
                    )
                })
                && route
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, RouteAttribute::Oif(index) if *index == lan_ifindex))
        }));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_route_remove_test() {
        let iface = test_iface_name("rr");
        let _link = ScopedDummyLink::new(&iface);
        let ifcfg = NetlinkIfConfiger {};
        let route_addr = "2001:db8:200::".parse::<std::net::Ipv6Addr>().unwrap();

        ifcfg
            .add_ipv6_route(&iface, route_addr, 56, None)
            .await
            .unwrap();

        let ifindex = NetlinkIfConfiger::get_interface_index(&iface).unwrap();
        let has_route = |routes: &[RouteMessage]| {
            routes.iter().any(|route| {
                route.header.destination_prefix_length == 56
                    && route.attributes.iter().any(|attr| {
                        matches!(
                            attr,
                            RouteAttribute::Destination(RouteAddress::Inet6(addr)) if *addr == route_addr
                        )
                    })
                    && route
                        .attributes
                        .iter()
                        .any(|attr| matches!(attr, RouteAttribute::Oif(index) if *index == ifindex))
            })
        };

        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();
        assert!(has_route(&routes));

        ifcfg
            .remove_ipv6_route(&iface, route_addr, 56)
            .await
            .unwrap();

        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();
        assert!(!has_route(&routes));
    }
}

#[cfg(test)]
mod counter_tests {
    use super::*;

    /// The kernel's own counters of `lo` follow what is sent through it, and
    /// `link_counters` reads them by interface index.
    #[test]
    fn link_counters_follow_loopback_traffic() {
        let lo = NetlinkIfConfiger::get_interface_index("lo").unwrap();
        let before = NetlinkIfConfiger::link_counters(lo).unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = [7u8; 1000];
        for _ in 0..200 {
            sender.send_to(&payload, receiver.local_addr().unwrap()).unwrap();
        }
        let after = NetlinkIfConfiger::link_counters(lo).unwrap();
        // 200 datagrams of at least 1028 bytes each (IPv4 + UDP headers).
        assert!(
            InterfaceCounters::delta(before.tx_bytes, after.tx_bytes) >= 200 * 1028,
            "{before:?} -> {after:?}"
        );
        assert!(InterfaceCounters::delta(before.rx_bytes, after.rx_bytes) >= 200 * 1028);
    }

    /// S-I10, needs root (it makes a dummy interface; the root test run puts
    /// it in a private network namespace). Load that no MP path carries, which
    /// the paths' sent bytes cannot see, fills more than the high-load share of the estimate of the
    /// egress: read from the interface's own counter the estimator enters
    /// its ramp-up decision; fed the paths' sent bytes (none) it does not.
    #[test]
    fn non_mp_load_on_the_nic_makes_the_estimator_ramp_up() {
        use crate::common::egress_quality::autorate::{LinkSqmEstimator, SqmConfig, SqmSample};
        use std::process::Command;

        let name = format!("etc{:x}", std::process::id() & 0xffff);
        let run_ip = |args: &[&str]| {
            let output = Command::new("ip").args(args).output().expect("ip runs");
            assert!(
                output.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let _ = Command::new("ip").args(["link", "del", &name]).output();
        run_ip(&["link", "add", &name, "type", "dummy"]);
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip").args(["link", "del", &self.0]).output();
            }
        }
        let _cleanup = Cleanup(name.clone());
        run_ip(&["addr", "add", "10.99.0.1/24", "dev", &name]);
        run_ip(&["link", "set", &name, "up"]);
        let ifindex = NetlinkIfConfiger::get_interface_index(&name).unwrap();

        let sender = std::net::UdpSocket::bind("10.99.0.1:0").unwrap();
        let target = "10.99.0.2:9";
        let mut from_nic = LinkSqmEstimator::new(SqmConfig::default());
        let mut from_paths = LinkSqmEstimator::new(SqmConfig::default());
        let start = from_nic.estimate().est_bw_bps;
        assert!(start > 0);

        let tick = std::time::Duration::from_millis(200);
        let datagram = [0u8; 1400];
        let mut last = NetlinkIfConfiger::link_counters(ifindex).unwrap();
        for _ in 0..8 {
            // 0.8x the estimate (the high-load test is 0.75x) for one tick, in wire bytes (1400 +
            // 28 header bytes; the kernel counts the 14-byte Ethernet header too).
            let est = from_nic.estimate().est_bw_bps as f64;
            let bytes = est * 0.8 * tick.as_secs_f64() / 8.0;
            let datagrams = (bytes / 1442.0).ceil() as usize;
            let began = std::time::Instant::now();
            for _ in 0..datagrams {
                let _ = sender.send_to(&datagram, target);
            }
            std::thread::sleep(tick.saturating_sub(began.elapsed()));
            let now = NetlinkIfConfiger::link_counters(ifindex).unwrap();
            let sent = InterfaceCounters::delta(last.tx_bytes, now.tx_bytes);
            last = now;
            let achieved = (sent as f64 * 8.0 / began.elapsed().as_secs_f64()) as u64;
            // a steady 20 ms one-way delay: no bufferbloat
            from_nic.update(SqmSample { owd_us: 20_000, achieved_bps: achieved });
            // what the paths report for load none of them carried
            from_paths.update(SqmSample { owd_us: 20_000, achieved_bps: 0 });
        }
        assert!(
            from_nic.estimate().est_bw_bps > start,
            "the estimate follows a loaded NIC upward: {} vs {start}",
            from_nic.estimate().est_bw_bps
        );
        assert!(from_nic.estimate().measured);
        assert_eq!(from_paths.estimate().est_bw_bps, start);
        assert!(!from_paths.estimate().measured);
    }

    #[test]
    fn link_counters_of_a_missing_interface_is_an_error() {
        assert!(NetlinkIfConfiger::link_counters(u32::MAX - 1).is_err());
    }
}
