//! Exercises the real `SystemdResolved` backend against `systemd-resolved`
//! running in a container (see docker/systemd_resolved.bats), which also creates the
//! `dummy0` interface this test targets. `#[ignore]` because it needs a
//! real system bus with `resolved` on it and a `dummy0` link to exist.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use dns_host_config::linux::SystemdResolved;
use dns_host_config::{DnsRoute, DnsRouteConfig};

const IFACE: &str = "dummy0";

fn resolvectl(args: &[&str]) -> String {
    let out = Command::new("resolvectl")
        .args(args)
        .output()
        .expect("running resolvectl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test]
#[ignore = "needs a running systemd-resolved + dummy0 interface; run via docker/systemd_resolved.bats"]
async fn set_pushes_dns_and_routing_domain_then_reset_clears_them() {
    let mut backend = SystemdResolved::probe()
        .await
        .expect("systemd-resolved should be usable in this container");

    let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    let config = DnsRouteConfig::new(vec![server], vec!["myvpn.example".into()]).unwrap();

    backend
        .set(IFACE, &config)
        .await
        .expect("set() against a real systemd-resolved should succeed");

    let dns = resolvectl(&["dns", IFACE]);
    assert!(dns.contains("10.9.9.9"), "resolvectl dns {IFACE}: {dns:?}");

    let domains = resolvectl(&["domain", IFACE]);
    assert!(
        domains.contains("myvpn.example"),
        "resolvectl domain {IFACE}: {domains:?}"
    );

    backend
        .reset()
        .await
        .expect("reset() against a real systemd-resolved should succeed");

    let dns_after = resolvectl(&["dns", IFACE]);
    assert!(
        !dns_after.contains("10.9.9.9"),
        "resolvectl dns {IFACE} after reset should be empty: {dns_after:?}"
    );

    let domains_after = resolvectl(&["domain", IFACE]);
    assert!(
        !domains_after.contains("myvpn.example"),
        "resolvectl domain {IFACE} after reset should be empty: {domains_after:?}"
    );
}

#[tokio::test]
#[ignore = "needs a running systemd-resolved + dummy0 interface; run via docker/systemd_resolved.bats"]
async fn reset_without_a_prior_set_is_a_harmless_no_op() {
    let mut backend = SystemdResolved::probe()
        .await
        .expect("probe should succeed");
    backend
        .reset()
        .await
        .expect("reset with nothing active is a no-op");
}
