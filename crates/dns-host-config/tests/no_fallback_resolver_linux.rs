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

//! Verifies `SystemdResolved::set()` refuses a routing-only domain when the
//! host has no other DNS server configured anywhere - see "Known
//! limitation: hosts with no real resolver" in `src/linux/systemd_resolved.rs`.
//! Needs a running `systemd-resolved` with nothing else configuring DNS and
//! a `dummy0` link; run via `docker/systemd_resolved_no_fallback.bats`.
//! Deliberately a separate container from `systemd_resolved_linux.rs`'s -
//! that one's shared container always has a second, default-route link
//! configured (needed by `conditional_forwarding_linux.rs`), which would
//! defeat this scenario.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};

use dns_host_config::linux::systemd_resolved::Error;
use dns_host_config::linux::SystemdResolved;
use dns_host_config::{DnsRoute, DnsRouteConfig};

const IFACE: &str = "dummy0";

#[tokio::test]
#[ignore = "needs a running systemd-resolved with no other DNS configured + dummy0; \
            run via docker/systemd_resolved_no_fallback.bats"]
async fn set_refuses_a_routing_only_domain_with_no_fallback_resolver() {
    let mut backend = SystemdResolved::probe()
        .await
        .expect("systemd-resolved should be usable in this container");

    let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    let config = DnsRouteConfig::new(vec![server], vec!["myvpn.example".into()]).unwrap();

    let err = backend
        .set(IFACE, &config)
        .await
        .expect_err("set() must refuse when the host has no other configured DNS");
    assert!(
        matches!(err, Error::NoFallbackResolver),
        "expected NoFallbackResolver, got {err:?}"
    );
}
