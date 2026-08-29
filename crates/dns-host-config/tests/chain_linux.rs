//! Exercises `LinuxDnsRoute::probe()` against the same container as
//! `tests/systemd_resolved_linux.rs` (see docker/run.sh): with a real
//! systemd-resolved and no resolvconf/NetworkManager competing for
//! attention, it should auto-detect the systemd-resolved backend and its
//! set()/reset() should work exactly like driving `SystemdResolved`
//! directly.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use dns_host_config::linux::LinuxDnsRoute;
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
#[ignore = "needs a running systemd-resolved + dummy0 interface; run via docker/run.sh"]
async fn auto_detection_picks_systemd_resolved_in_this_container() {
    let route = LinuxDnsRoute::probe("dns-host-config-test").await;
    assert_eq!(route.backend_name(), "systemd-resolved");
}

#[tokio::test]
#[ignore = "needs a running systemd-resolved + dummy0 interface; run via docker/run.sh"]
async fn set_and_reset_work_through_the_auto_detected_backend() {
    let mut route = LinuxDnsRoute::probe("dns-host-config-test").await;

    let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 8));
    let config = DnsRouteConfig::new(vec![server], vec!["chain.example".into()]).unwrap();

    route
        .set(IFACE, &config)
        .await
        .expect("set() through the auto-detected backend should succeed");

    let dns = resolvectl(&["dns", IFACE]);
    assert!(dns.contains("10.9.9.8"), "resolvectl dns {IFACE}: {dns:?}");
    let domains = resolvectl(&["domain", IFACE]);
    assert!(
        domains.contains("chain.example"),
        "resolvectl domain {IFACE}: {domains:?}"
    );

    route.reset().await.expect("reset() should succeed");

    let dns_after = resolvectl(&["dns", IFACE]);
    assert!(
        !dns_after.contains("10.9.9.8"),
        "resolvectl dns {IFACE} after reset: {dns_after:?}"
    );
}
