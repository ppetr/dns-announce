//! Linux backends. Most consumers want [`LinuxDnsRoute`] - it detects
//! which of these is actually usable on the host and picks accordingly.
//! The individual backends are also exported directly for anyone who wants
//! to pick one explicitly rather than auto-detect.
//!
//! NetworkManager is a planned addition to the chain, not implemented yet
//! - see `docs/design-dns-host-config.md`.

pub mod chain;
pub mod resolvconf;
pub mod static_resolv_conf;
pub mod systemd_resolved;

pub use chain::LinuxDnsRoute;
pub use resolvconf::Resolvconf;
pub use static_resolv_conf::StaticResolvConf;
pub use systemd_resolved::SystemdResolved;
