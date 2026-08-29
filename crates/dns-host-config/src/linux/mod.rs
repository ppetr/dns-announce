//! Linux backends, tried in priority order by whatever ends up assembling
//! them into the public entry point (not yet present - one backend at a
//! time, see `docs/design-dns-host-config.md` for the planned chain:
//! systemd-resolved, NetworkManager, resolvconf, static `/etc/resolv.conf`).
