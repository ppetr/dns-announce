//! Auto-detecting Linux backend: tries each candidate in priority order
//! and falls back to a global-only edit if none of the smarter ones are
//! usable. Since that last resort always works,
//! [`LinuxDnsRoute::probe`] never fails to produce *something* - callers
//! never have to know or care which DNS manager, if any, the host is
//! actually running.
//!
//! Priority: `systemd-resolved`, then `resolvconf`, then a direct
//! `/etc/resolv.conf` edit. (NetworkManager is a planned addition - see
//! `docs/design-dns-host-config.md` - not implemented yet.)
//!
//! ## What "bullet-proof" does *not* mean
//!
//! `probe()` always returns a usable backend, but that backend might not
//! be able to honor every [`DnsRouteConfig`]: only `systemd-resolved` can
//! do conditional forwarding (a non-empty `routing_domains`).
//! `resolvconf` and the static-file fallback both refuse such a config
//! outright rather than silently applying it as a global override - see
//! their own module docs. Auto-detection picks a backend based on what's
//! usable on the host, once, at `probe()` time; it does not look ahead at
//! what a later `set()` call will ask for. A caller that needs conditional
//! forwarding specifically should check
//! [`backend_name`](LinuxDnsRoute::backend_name) or simply handle a
//! `set()` error from a backend that can't do it.
//!
//! ## Overriding the choice
//!
//! Set `DNS_HOST_CONFIG_BACKEND` to `systemd-resolved`, `resolvconf`, or
//! `static-resolv-conf` to force one, e.g. for tests. An unusable or
//! unrecognized value is logged and ignored (falls through to
//! auto-detection) rather than rejected, since this is a debugging knob,
//! not part of the public contract.

use std::env;
use std::fmt;

use crate::{DnsRoute, DnsRouteConfig};

use super::{resolvconf, static_resolv_conf, systemd_resolved};
use super::{Resolvconf, StaticResolvConf, SystemdResolved};

const OVERRIDE_ENV_VAR: &str = "DNS_HOST_CONFIG_BACKEND";

enum Backend {
    SystemdResolved(SystemdResolved),
    Resolvconf(Resolvconf),
    StaticResolvConf(StaticResolvConf),
}

impl Backend {
    fn name(&self) -> &'static str {
        match self {
            Backend::SystemdResolved(_) => "systemd-resolved",
            Backend::Resolvconf(_) => "resolvconf",
            Backend::StaticResolvConf(_) => "static-resolv-conf",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    SystemdResolved(systemd_resolved::Error),
    Resolvconf(resolvconf::Error),
    StaticResolvConf(static_resolv_conf::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SystemdResolved(e) => write!(f, "{e}"),
            Error::Resolvconf(e) => write!(f, "{e}"),
            Error::StaticResolvConf(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

pub struct LinuxDnsRoute {
    backend: Backend,
}

impl LinuxDnsRoute {
    /// Never fails: the static-file fallback is always available, so this
    /// always returns something usable, trying each smarter backend in
    /// priority order first. `owner` is only consulted by that fallback
    /// (see [`StaticResolvConf`]) - pick something stable and specific to
    /// your application.
    pub async fn probe(owner: impl Into<String>) -> Self {
        let owner = owner.into();

        if let Ok(name) = env::var(OVERRIDE_ENV_VAR) {
            match Self::probe_named(&name, owner.clone()).await {
                Some(backend) => return Self { backend },
                None => log::warn!(
                    "{OVERRIDE_ENV_VAR}={name:?} is not a usable backend on this host; \
                     falling back to auto-detection"
                ),
            }
        }

        let backend = match SystemdResolved::probe().await {
            Ok(b) => Backend::SystemdResolved(b),
            Err(e) => {
                log::debug!("dns-host-config: systemd-resolved not usable: {e}");
                match Resolvconf::probe() {
                    Ok(b) => Backend::Resolvconf(b),
                    Err(e) => {
                        log::debug!("dns-host-config: resolvconf not usable: {e}");
                        Backend::StaticResolvConf(StaticResolvConf::new(owner))
                    }
                }
            }
        };
        log::info!("dns-host-config: using the {} backend", backend.name());
        Self { backend }
    }

    /// The backend `probe()` actually picked, e.g. for logging or to
    /// decide up front whether conditional forwarding is even possible on
    /// this host - see the module docs.
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    async fn probe_named(name: &str, owner: String) -> Option<Backend> {
        match name {
            "systemd-resolved" => SystemdResolved::probe()
                .await
                .ok()
                .map(Backend::SystemdResolved),
            "resolvconf" => Resolvconf::probe().ok().map(Backend::Resolvconf),
            "static-resolv-conf" => Some(Backend::StaticResolvConf(StaticResolvConf::new(owner))),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl DnsRoute for LinuxDnsRoute {
    type Error = Error;

    async fn set(&mut self, interface: &str, config: &DnsRouteConfig) -> Result<(), Error> {
        match &mut self.backend {
            Backend::SystemdResolved(b) => b
                .set(interface, config)
                .await
                .map_err(Error::SystemdResolved),
            Backend::Resolvconf(b) => b.set(interface, config).await.map_err(Error::Resolvconf),
            Backend::StaticResolvConf(b) => b
                .set(interface, config)
                .await
                .map_err(Error::StaticResolvConf),
        }
    }

    async fn reset(&mut self) -> Result<(), Error> {
        match &mut self.backend {
            Backend::SystemdResolved(b) => b.reset().await.map_err(Error::SystemdResolved),
            Backend::Resolvconf(b) => b.reset().await.map_err(Error::Resolvconf),
            Backend::StaticResolvConf(b) => b.reset().await.map_err(Error::StaticResolvConf),
        }
    }
}
