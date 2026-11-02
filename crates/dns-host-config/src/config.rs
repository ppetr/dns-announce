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

use std::fmt;
use std::net::IpAddr;

/// What to push into the host's DNS configuration for one interface.
///
/// `routing_domains` is normalized on construction: lowercased, trailing
/// dot stripped, deduplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRouteConfig {
    pub servers: Vec<IpAddr>,
    pub routing_domains: Vec<String>,
}

/// Why a [`DnsRouteConfig`] was rejected before it ever reached a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NoServers,
    InvalidDomain(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoServers => write!(f, "at least one DNS server is required"),
            ConfigError::InvalidDomain(d) => write!(f, "invalid routing domain: {d:?}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl DnsRouteConfig {
    /// Validates and normalizes `servers`/`routing_domains`.
    ///
    /// `servers` must be non-empty. Each domain must be a non-empty ASCII
    /// string of labels separated by `.`, using only letters, digits, `-`
    /// and `.` — the same restriction `resolvectl`/systemd-resolved apply
    /// to a routing domain.
    pub fn new(servers: Vec<IpAddr>, routing_domains: Vec<String>) -> Result<Self, ConfigError> {
        if servers.is_empty() {
            return Err(ConfigError::NoServers);
        }
        for domain in &routing_domains {
            if !is_valid_domain(domain) {
                return Err(ConfigError::InvalidDomain(domain.clone()));
            }
        }
        Ok(Self {
            servers,
            routing_domains: normalize_domains(routing_domains),
        })
    }
}

fn is_valid_domain(domain: &str) -> bool {
    let trimmed = domain.trim_end_matches('.');
    !trimmed.is_empty()
        && trimmed.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn normalize_domains(domains: Vec<String>) -> Vec<String> {
    let mut cleaned: Vec<String> = domains
        .into_iter()
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    cleaned.sort_unstable();
    cleaned.dedup();
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    fn addr() -> IpAddr {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }

    #[test]
    fn rejects_empty_servers() {
        assert_eq!(
            DnsRouteConfig::new(vec![], vec!["myvpn.example".into()]),
            Err(ConfigError::NoServers)
        );
    }

    #[test]
    fn rejects_invalid_domain() {
        assert_eq!(
            DnsRouteConfig::new(vec![addr()], vec!["my vpn".into()]),
            Err(ConfigError::InvalidDomain("my vpn".into()))
        );
        assert_eq!(
            DnsRouteConfig::new(vec![addr()], vec!["".into()]),
            Err(ConfigError::InvalidDomain("".into()))
        );
    }

    #[test]
    fn lowercases_and_strips_trailing_dot() {
        let cfg = DnsRouteConfig::new(vec![addr()], vec!["MyVPN.Example.".into()]).unwrap();
        assert_eq!(cfg.routing_domains, vec!["myvpn.example"]);
    }

    #[test]
    fn sorts_and_dedups_domains() {
        let cfg = DnsRouteConfig::new(
            vec![addr()],
            vec!["b.example".into(), "a.example".into(), "b.example".into()],
        )
        .unwrap();
        assert_eq!(cfg.routing_domains, vec!["a.example", "b.example"]);
    }
}
