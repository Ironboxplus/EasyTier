use std::{net::SocketAddr, sync::Arc};

use crate::{
    common::{PeerId, config::is_tunnel_or_loopback_device, global_ctx::ArcGlobalCtx},
    tunnel::common::{BindDev, bind},
};

use super::mp_path::{CarrierKind, UdpMpPathProvider};

/// A deterministic diagnostic path configured on both endpoints.
///
/// Syntax:
/// `mp+udp://<remote-ip>:<port>?peer_id=<id>&bind=<local-ip>:<port>[&egress=<device>]`
///
/// Both endpoints provide mirrored entries. Literal IPs are required so a
/// config refresh cannot silently move a path to a different underlay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManualUdpPathConfig {
    pub(crate) source: String,
    pub(crate) peer_id: PeerId,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) egress_device: Option<String>,
}

impl ManualUdpPathConfig {
    pub(crate) fn parse(source: &str) -> anyhow::Result<Self> {
        let url: url::Url = source
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid manual MP path {source:?}: {error}"))?;
        if url.scheme() != "mp+udp" {
            anyhow::bail!("manual MP path must use mp+udp://, got {source:?}");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("manual MP path is missing remote IP: {source:?}"))?;
        let ip = host.parse::<std::net::IpAddr>().map_err(|_| {
            anyhow::anyhow!("manual MP path requires a literal remote IP: {source:?}")
        })?;
        let port = url
            .port()
            .ok_or_else(|| anyhow::anyhow!("manual MP path is missing remote port: {source:?}"))?;
        if port == 0 {
            anyhow::bail!("manual MP path remote port must not be zero: {source:?}");
        }
        let remote_addr = SocketAddr::new(ip, port);

        let mut peer_id = None;
        let mut bind_addr = None;
        let mut egress_device = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "peer_id" if peer_id.is_none() => {
                    peer_id = Some(value.parse::<PeerId>().map_err(|error| {
                        anyhow::anyhow!("invalid manual MP peer_id {value:?}: {error}")
                    })?);
                }
                "bind" if bind_addr.is_none() => {
                    bind_addr = Some(value.parse::<SocketAddr>().map_err(|error| {
                        anyhow::anyhow!("invalid manual MP bind address {value:?}: {error}")
                    })?);
                }
                "egress" if egress_device.is_none() => {
                    let value = value.trim();
                    if !value.is_empty() {
                        egress_device = Some(value.to_string());
                    }
                }
                "peer_id" | "bind" | "egress" => {
                    anyhow::bail!("duplicate manual MP query parameter {key:?}")
                }
                _ => anyhow::bail!("unknown manual MP query parameter {key:?}"),
            }
        }

        let peer_id = peer_id
            .filter(|peer_id| *peer_id != 0)
            .ok_or_else(|| anyhow::anyhow!("manual MP path requires non-zero peer_id"))?;
        let bind_addr =
            bind_addr.ok_or_else(|| anyhow::anyhow!("manual MP path requires bind=<ip:port>"))?;
        if bind_addr.port() == 0 {
            anyhow::bail!("manual MP bind port must not be zero");
        }
        if bind_addr.is_ipv4() != remote_addr.is_ipv4() {
            anyhow::bail!("manual MP bind and remote addresses must use the same IP family");
        }
        if let Some(device) = egress_device.as_deref() {
            if is_tunnel_or_loopback_device(device) {
                anyhow::bail!(
                    "refusing to use tunnel/loopback interface {device:?} for a manual MP path"
                );
            }
        }

        Ok(Self {
            source: source.to_string(),
            peer_id,
            bind_addr,
            remote_addr,
            egress_device,
        })
    }

    pub(crate) fn is_server(&self, my_peer_id: PeerId) -> bool {
        my_peer_id > self.peer_id
    }

    pub(crate) fn remote_url(&self) -> url::Url {
        crate::tunnel::build_url_from_socket_addr(&self.remote_addr.to_string(), "mpquic")
    }

    pub(crate) fn bind_provider(
        &self,
        global_ctx: &ArcGlobalCtx,
    ) -> anyhow::Result<UdpMpPathProvider> {
        let flags = global_ctx.get_flags();
        let dev = self
            .egress_device
            .clone()
            .map(BindDev::Custom)
            .unwrap_or(BindDev::Disabled);
        let socket = bind::<tokio::net::UdpSocket>()
            .addr(self.bind_addr)
            .dev(dev)
            .net_ns(global_ctx.net_ns.clone())
            .maybe_socket_mark(flags.socket_mark)
            .call()
            .map_err(anyhow::Error::new)?;
        UdpMpPathProvider::new(
            CarrierKind::Manual,
            Arc::new(socket),
            self.remote_addr,
            self.egress_device.clone(),
        )
        .map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_device_bound_manual_udp_path() {
        let parsed = ManualUdpPathConfig::parse(
            "mp+udp://192.0.2.20:41002?peer_id=20&bind=192.0.2.10:41001&egress=Ethernet%202",
        )
        .unwrap();

        assert_eq!(parsed.peer_id, 20);
        assert_eq!(parsed.bind_addr, "192.0.2.10:41001".parse().unwrap());
        assert_eq!(parsed.remote_addr, "192.0.2.20:41002".parse().unwrap());
        assert_eq!(parsed.egress_device.as_deref(), Some("Ethernet 2"));
        assert!(!parsed.is_server(10));
        assert!(parsed.is_server(30));
    }

    #[test]
    fn rejects_ambiguous_or_tunnel_bound_manual_paths() {
        for invalid in [
            "udp://192.0.2.20:41002?peer_id=20&bind=192.0.2.10:41001",
            "mp+udp://example.com:41002?peer_id=20&bind=192.0.2.10:41001",
            "mp+udp://192.0.2.20:41002?peer_id=0&bind=192.0.2.10:41001",
            "mp+udp://192.0.2.20:41002?peer_id=20&bind=192.0.2.10:0",
            "mp+udp://192.0.2.20:41002?peer_id=20&bind=192.0.2.10:41001&egress=tun0",
        ] {
            assert!(ManualUdpPathConfig::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn manual_udp_is_a_real_udp_provider_kind() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let provider = UdpMpPathProvider::new(
            CarrierKind::Manual,
            Arc::new(socket),
            "127.0.0.1:41002".parse().unwrap(),
            None,
        );
        assert!(provider.is_ok());
    }
}
