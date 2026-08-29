//! Push a DNS resolver and a routing domain into a host's DNS
//! configuration, and withdraw it again.
//!
//! This crate is the OS-integration half of the story that
//! [`dns-stack`](https://crates.io/crates/dns-stack)'s RA/RDNSS beacon is
//! the other half of - but it has **no dependency on `dns-stack`, or on
//! any other DNS server**. Anyone who runs their own resolver on a VPN,
//! tunnel, or test link and wants a host to actually use it can drive this
//! crate directly.
//!
//! ## What this does and doesn't do
//! - It configures **conditional forwarding by queried name**: an existing
//!   host resolver (e.g. `systemd-resolved`) is told "queries under these
//!   domains go to `servers`; everything else keeps using whatever the host
//!   already had configured." This is often called "split DNS" - not to be
//!   confused with *split-horizon* DNS, which varies answers by the
//!   *source* of a query. There is no source-based logic here or anywhere
//!   in this crate.
//! - It does **not** assign addresses, bring up interfaces, or manage
//!   routes - `interface` is assumed to already exist and `servers` to
//!   already be reachable through it. That is the caller's job, same as it
//!   is for `dns-stack`.
//! - Detecting whether a backend (e.g. systemd-resolved) is usable is
//!   itself a *verification*, not just a presence check: constructing a
//!   backend fails if using it wouldn't actually take effect, rather than
//!   succeeding at a silent no-op. See each backend's module docs for what
//!   it checks.

use std::error::Error;

mod config;
pub use config::{ConfigError, DnsRouteConfig};

#[cfg(target_os = "linux")]
pub mod linux;

/// Pushes `config` into the host's DNS setup for `interface`, and
/// withdraws it again.
///
/// Implementors always rebuild their view of the system from scratch on
/// each `set()` rather than trusting an earlier detection result: what's
/// actually managing DNS on a host can change between calls (a network
/// manager restarts, `systemd-resolved` gets installed, ...), and trusting
/// stale state is itself a source of "silently doesn't work" failures.
#[async_trait::async_trait]
pub trait DnsRoute: Send {
    type Error: Error + Send + Sync + 'static;

    /// Configures `interface` to route `config.routing_domains` (or, if
    /// empty, all queries) to `config.servers`. Calling this again with a
    /// different config replaces the previous one; it does not stack.
    async fn set(&mut self, interface: &str, config: &DnsRouteConfig) -> Result<(), Self::Error>;

    /// Undoes whatever the last `set()` did. A no-op if `set()` was never
    /// called or has already been undone.
    async fn reset(&mut self) -> Result<(), Self::Error>;

    /// Like [`reset`](Self::reset), but called just before `interface` is
    /// destroyed. The default just calls `reset()`; a backend whose state
    /// is scoped to the interface by the OS itself (e.g. systemd-resolved's
    /// per-link config, which disappears with the link) can leave this as
    /// a no-op, but a backend that persists state elsewhere (a file on
    /// disk) needs to actually clean it up here, since there will be no
    /// interface left to key that cleanup off of afterwards.
    async fn reset_before_interface_removal(&mut self) -> Result<(), Self::Error> {
        self.reset().await
    }
}
