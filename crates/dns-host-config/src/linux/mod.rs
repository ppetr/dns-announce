// Copyright 2026 <https://github.com/ppetr/>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
