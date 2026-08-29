//! Conditional forwarding via `systemd-resolved`'s D-Bus API
//! (`org.freedesktop.resolve1`).
//!
//! Constructing [`SystemdResolved`] is itself a verification, not just a
//! presence check: it's not enough that `resolved` is reachable over
//! D-Bus, because `/etc/resolv.conf` might be managed by something else
//! entirely (a plain static file, `resolvconf`, NetworkManager in its own
//! dnsmasq mode, ...) in which case `Link.SetDNS()` calls would succeed on
//! the wire but have no effect on what the host actually resolves through.
//! So `probe()` also checks that `/etc/resolv.conf` is still symlinked
//! into `resolved`'s own runtime directory before returning a backend at
//! all.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use crate::{DnsRoute, DnsRouteConfig};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

#[derive(Debug)]
pub enum Error {
    /// `resolved` isn't usable as a backend right now (wrong
    /// `/etc/resolv.conf`, no ifindex for the given interface, ...) - not
    /// a D-Bus failure, so the caller should try a different backend
    /// rather than treat this as "resolved is broken".
    NotAvailable(String),
    DBus(zbus::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAvailable(msg) => write!(f, "systemd-resolved not usable: {msg}"),
            Error::DBus(e) => write!(f, "systemd-resolved D-Bus call failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Error::DBus(e)
    }
}

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    interface = "org.freedesktop.resolve1.Manager"
)]
trait Resolve1Manager {
    fn get_link(&self, ifindex: i32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    interface = "org.freedesktop.resolve1.Link"
)]
trait Resolve1Link {
    #[zbus(name = "SetDNS")]
    fn set_dns(&self, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    fn set_domains(&self, domains: Vec<(String, bool)>) -> zbus::Result<()>;
}

pub struct SystemdResolved {
    connection: zbus::Connection,
    /// The link `set()` last configured, so `reset()` knows what to undo.
    active_link: Option<i32>,
}

impl SystemdResolved {
    /// Connects to the system bus and verifies `/etc/resolv.conf` still
    /// points at `resolved`'s stub. Fails otherwise - see the module docs.
    pub async fn probe() -> Result<Self, Error> {
        Self::probe_with_resolv_conf(Path::new("/etc/resolv.conf")).await
    }

    async fn probe_with_resolv_conf(resolv_conf: &Path) -> Result<Self, Error> {
        if !resolv_conf_points_at_resolved(resolv_conf) {
            return Err(Error::NotAvailable(format!(
                "{} is not a symlink into systemd-resolved's runtime directory",
                resolv_conf.display()
            )));
        }
        let connection = zbus::Connection::system().await?;
        Ok(Self {
            connection,
            active_link: None,
        })
    }

    async fn link_proxy(&self, ifindex: i32) -> Result<Resolve1LinkProxy<'_>, Error> {
        let manager = Resolve1ManagerProxy::new(&self.connection).await?;
        let path = manager.get_link(ifindex).await?;
        Ok(Resolve1LinkProxy::builder(&self.connection)
            .path(path)?
            .build()
            .await?)
    }
}

#[async_trait::async_trait]
impl DnsRoute for SystemdResolved {
    type Error = Error;

    async fn set(&mut self, interface: &str, config: &DnsRouteConfig) -> Result<(), Error> {
        let idx = ifindex(Path::new("/sys/class/net"), interface)?;
        let link = self.link_proxy(idx).await?;

        let addresses: Vec<(i32, Vec<u8>)> =
            config.servers.iter().map(|ip| encode_addr(*ip)).collect();
        link.set_dns(addresses).await?;

        // Always routing-only (`true`): we never want to also add these
        // domains to the host's default search list, only to route
        // matching queries to `config.servers`.
        let domains: Vec<(String, bool)> = config
            .routing_domains
            .iter()
            .map(|d| (d.clone(), true))
            .collect();
        link.set_domains(domains).await?;

        self.active_link = Some(idx);
        Ok(())
    }

    async fn reset(&mut self) -> Result<(), Error> {
        let Some(idx) = self.active_link.take() else {
            return Ok(());
        };
        let link = match self.link_proxy(idx).await {
            Ok(link) => link,
            Err(Error::DBus(_)) => {
                // Most likely the interface (and its link object) is gone
                // already - nothing left to undo.
                log::debug!("systemd-resolved: link {idx} no longer exists, nothing to reset");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        link.set_dns(Vec::new()).await?;
        link.set_domains(Vec::new()).await?;
        Ok(())
    }
}

fn encode_addr(ip: IpAddr) -> (i32, Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => (AF_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (AF_INET6, v6.octets().to_vec()),
    }
}

fn ifindex(sys_class_net: &Path, interface: &str) -> Result<i32, Error> {
    let path = sys_class_net.join(interface).join("ifindex");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::NotAvailable(format!("reading {}: {e}", path.display())))?;
    raw.trim()
        .parse::<i32>()
        .map_err(|_| Error::NotAvailable(format!("{} does not contain an integer", path.display())))
}

/// Whether `resolv_conf` is a symlink into systemd-resolved's runtime
/// directory (`/run/systemd/resolve/`) - the stub (`stub-resolv.conf`,
/// pointing at 127.0.0.53) or the static variant (`resolv.conf`, used
/// when `DNSStubListener=no`). Either indicates `resolved` is the thing
/// actually in charge of `/etc/resolv.conf`; anything else (a plain file,
/// a symlink elsewhere, no file at all) means `SetDNS()` calls would be
/// accepted over D-Bus but never actually consulted.
fn resolv_conf_points_at_resolved(resolv_conf: &Path) -> bool {
    match std::fs::read_link(resolv_conf) {
        Ok(target) => {
            let target = target.to_string_lossy();
            target.contains("systemd/resolve/") && target.ends_with("resolv.conf")
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn encodes_v4_as_af_inet_with_four_bytes() {
        assert_eq!(
            encode_addr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            (AF_INET, vec![10, 1, 2, 3])
        );
    }

    #[test]
    fn encodes_v6_as_af_inet6_with_sixteen_bytes() {
        let (family, bytes) = encode_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(family, AF_INET6);
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes, Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn resolv_conf_symlink_to_stub_is_recognized() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &link).unwrap();
        assert!(resolv_conf_points_at_resolved(&link));
    }

    #[test]
    fn resolv_conf_symlink_to_static_variant_is_recognized() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink("/run/systemd/resolve/resolv.conf", &link).unwrap();
        assert!(resolv_conf_points_at_resolved(&link));
    }

    #[test]
    fn resolv_conf_pointing_elsewhere_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink("/run/NetworkManager/resolv.conf", &link).unwrap();
        assert!(!resolv_conf_points_at_resolved(&link));
    }

    #[test]
    fn resolv_conf_that_is_a_plain_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("resolv.conf");
        std::fs::write(&plain, "nameserver 1.1.1.1\n").unwrap();
        assert!(!resolv_conf_points_at_resolved(&plain));
    }

    #[test]
    fn resolv_conf_missing_entirely_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!resolv_conf_points_at_resolved(
            &dir.path().join("resolv.conf")
        ));
    }

    #[test]
    fn ifindex_reads_the_sysfs_file() {
        let dir = tempfile::tempdir().unwrap();
        let ifdir = dir.path().join("eth7");
        std::fs::create_dir(&ifdir).unwrap();
        std::fs::write(ifdir.join("ifindex"), "7\n").unwrap();
        assert!(matches!(ifindex(dir.path(), "eth7"), Ok(7)));
    }

    #[test]
    fn ifindex_missing_interface_is_not_available() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            ifindex(dir.path(), "nope"),
            Err(Error::NotAvailable(_))
        ));
    }

    #[test]
    fn ifindex_garbage_content_is_not_available() {
        let dir = tempfile::tempdir().unwrap();
        let ifdir = dir.path().join("eth7");
        std::fs::create_dir(&ifdir).unwrap();
        std::fs::write(ifdir.join("ifindex"), "not a number\n").unwrap();
        assert!(matches!(
            ifindex(dir.path(), "eth7"),
            Err(Error::NotAvailable(_))
        ));
    }
}
