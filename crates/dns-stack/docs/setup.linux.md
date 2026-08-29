# Linux setup

`dns-stack` puts a resolver address and a search domain onto a link via
RA/RDNSS (RFC 8106). Whether a Linux host on that link *acts* on it is entirely
up to that host's own network stack -- this crate only puts the bytes on the
wire. This document covers what the receiving Linux host needs, the non-obvious
ways it fails, the more direct alternative, and the containerised tests that
exercise all of it.

## Two ways to get split-DNS onto a Linux host

### A. RA/RDNSS auto-discovery (what this crate does)

The beacon advertises the resolver; a userspace RA consumer on the host
(`systemd-networkd`, NetworkManager, `rdnssd`, `dhcpcd`) picks it up and
configures the system resolver. Zero per-host DNS configuration -- *if* the host
already runs such a consumer on the relevant interface.

Best when you announce to **many / heterogeneous clients** on a shared link and
cannot touch each one: you are effectively a router for that link.

### B. Configure `systemd-resolved` directly

If you control the host and it runs `systemd-resolved`, skip RA entirely and set
the link's DNS yourself:

```sh
resolvectl dns    <link> <resolver-addr>
resolvectl domain <link> ~myvpn.example     # leading ~ = routing-only (split DNS)
```

or the D-Bus API `org.freedesktop.resolve1` (`SetLinkDNS`, `SetLinkDomains`,
`SetLinkDefaultRoute`). For hosts without `systemd-resolved`: `resolvconf` /
`openresolv`, otherwise `/etc/resolv.conf`.

Best when **you own the host** (a VPN client configuring its own tunnel). It is
deterministic, immediate, scoped without any client-side opt-in, and
`systemd-resolved` drops the configuration automatically when the link goes
away. `dns-stack` targets (A); (B) is noted here because it is frequently the
better fit, and the same `Resolver` implementation can sit behind it.

## Path A: making RA/RDNSS work

### Kernel prerequisites (non-networkd consumers)

* `net.ipv6.conf.<link>.accept_ra` must be non-zero. Default `1`, but flips to
  `0` when `net.ipv6.conf.all.forwarding=1`; then set `accept_ra=2` on the
  tunnel interface.
* `net.ipv6.conf.<link>.disable_ipv6=0` (and `all.disable_ipv6=0`).
* **The kernel never parses RDNSS/DNSSL.** Even with `accept_ra` on, the options
  are dropped unless a userspace consumer is running.

> When `systemd-networkd` runs its own RA client (`IPv6AcceptRA=yes`) it sets the
> kernel's `accept_ra=0` for that link and does everything in userspace. The
> `sysctl` above then does **not** apply -- the `.network` setting does. Do not
> debug one while expecting the other.

### The RA must not look self-originated

`RaConfig::link_local_src` is the RA's IPv6 source address. **It must not be an
address assigned to the receiving interface.** A host silently discards an RA
whose source is one of its own addresses (it looks looped back). If your tunnel
bring-up puts `fe80::1` on the client end, do not also use `fe80::1` as
`link_local_src`.

### The receiving interface needs a link-local

`systemd-networkd`'s RA client only runs on a link that already has an `fe80::`
address. A `tun` device has no MAC and the kernel will not autogenerate one, so
the bring-up must add one -- `ip -6 addr add fe80::<x>/64 dev <link>`, or
`LinkLocalAddressing=ipv6` in the `.network` file.

### systemd-networkd + systemd-resolved

`/etc/systemd/network/50-myvpn.network`:

```ini
[Match]
Name=myvpn0

[Network]
# If networkd manages this link it takes authoritative control of the link's
# global IPv6 addresses (see gotcha below), so hand it the address.
Address=fd00:aaaa::2/64
LinkLocalAddressing=ipv6
IPv6AcceptRA=yes

[IPv6AcceptRA]
UseDNS=yes
UseDomains=route      # "route" = split DNS; the default "no" makes the resolver global
```

`systemctl restart systemd-networkd`, then check `resolvectl status myvpn0` --
you want a `DNS Servers:` line and `DNS Domain: ~myvpn.example`.

For `getaddrinfo` (not just `resolvectl query`) to use it, `nss-resolve` must be
wired: `hosts: files resolve [!UNAVAIL=return] dns` in `/etc/nsswitch.conf`
(install `libnss-resolve`), or point `/etc/resolv.conf` at the stub
`127.0.0.53`.

#### Gotcha: networkd flushes "foreign" addresses

On a link `systemd-networkd` manages with `IPv6AcceptRA=`, it removes global
IPv6 addresses it did not configure itself -- including one your VPN client
assigned out of band. The resolver address then has no on-link route, so RDNSS
discovery *appears* to succeed (`resolved` learns the server) but every query to
it fails. Fix, pick one:

* put the interface address in `[Address]=` so networkd owns it (above); or
* keep networkd off that interface's addressing entirely and use Path B.

`KeepConfiguration=` does **not** help here -- it only applies across networkd
restarts, not to third-party addresses during normal operation.

#### Gotcha: DNSSL domain needs at least two labels

`systemd-resolved` will not accept a single bare label (`myvpn`) as a routing
domain from an RA: `resolvectl domain` stays empty and split DNS never engages.
Advertise a dotted domain:

```rust
search_domains: vec!["myvpn.example".into()],   // not "myvpn"
```

#### Gotcha: RDNSS carries no route

RFC 8106 advertises a resolver *address*, not a route to it, and this crate
sends no Prefix Information option. Nothing makes the resolver on-link by
itself -- the transport (your VPN's addressing and routes) must make
`server_addr` reachable from the client.

### NetworkManager

NM consumes RDNSS automatically on a managed connection and feeds
`systemd-resolved` when present (otherwise writes `resolv.conf`). For scoped
split DNS add a routing search domain:
`nmcli connection modify <con> +ipv6.dns-search '~myvpn.example'`. Harder to
drive headless / in a container than networkd.

### rdnssd / dhcpcd

Legacy standalone consumers for hosts without `systemd-networkd`. `rdnssd`
writes `/etc/resolv.conf` (global resolver, no split DNS). `dhcpcd` has RDNSS
support and run hooks.

### Firewall / reverse-path

IPv6 has no `rp_filter` sysctl, but an nftables `fib` / `rpfilter` rule or a
strict ruleset can drop the crate's injected DNS replies arriving on the tunnel
interface. Allow inbound UDP/53 from `server_addr` on that interface.

## Verifying: the test containers

Two Docker setups under `docker/` exercise the real path. Both need
`--cap-add=NET_ADMIN` (the discovery one uses `--privileged`) and
`/dev/net/tun`; the scripts wire that up. The test binaries are compiled on the
host and bind-mounted in -- the images carry no toolchain.

### `docker/run.sh` -- the DNS server path

Minimal `debian:stable-slim`. Runs `tests/loopback_linux.rs`: a dedicated `tun`
is a private point-to-point link, a real `std::net::UdpSocket` sends a query
straight to `[server]:53`, the crate answers, the kernel delivers the reply.
Proves the IPv6/UDP framing and checksums the crate emits are accepted by a real
OS stack. No systemd.

### `docker/run-discovery.sh` -- the RA/RDNSS discovery path

`docker/Dockerfile.discovery`: `debian:stable` with `systemd` as PID 1,
`systemd-networkd`, `systemd-resolved`, `libnss-resolve`, and
`docker/discovery.network` matching the test interface. Runs
`tests/discovery_linux.rs`, four layered checks so a failure points at the layer
that broke:

| test | proves |
|------|--------|
| `ra_is_well_formed_on_the_wire_per_rdisc6` | a standalone RFC 8106 parser (`rdisc6`) accepts the RA -- RDNSS server and DNSSL domain present |
| `resolved_picks_up_rdnss_from_the_beacon` | networkd hands `systemd-resolved` the resolver **and** the `~myvpn.example` routing domain |
| `getaddrinfo_resolves_in_suffix_name_via_rdnss` | the whole chain: `getaddrinfo("foo.myvpn.example")` -> `nss-resolve` -> `resolved` -> split DNS -> the crate -> the expected address |
| `resolved_does_not_route_foreign_names_to_us` | the routing domain is *scoped* -- non-suffix lookups never reach the crate's resolver |

All four are `#[ignore]`d in a normal `cargo test`; the scripts pass
`--ignored`. Shared harness (TUN device wired to a running `DnsStack`) is
`tests/common/mod.rs`.

## Troubleshooting checklist

| Symptom | Check | Likely fix |
|---------|-------|------------|
| `resolvectl status <link>` shows no DNS server | `journalctl -u systemd-networkd`; is `networkctl status <link>` `Network File:` set? | `.network` `[Match]` not matching; or `udev` not installed, so networkd waits for the link to be "initialized" |
| link matched, still no DNS server | is `link_local_src` also an address on the link? does the link have any `fe80::`? | make `link_local_src` distinct from the interface's addresses; add a link-local to the interface |
| DNS server present, `resolvectl domain <link>` empty | is the DNSSL domain a single bare label? | advertise a dotted domain (`myvpn.example`) |
| server + domain present, `getaddrinfo` still fails | `ip -6 route` -- is there a route to `server_addr`? | networkd flushed the address -- put it in `[Address]=`; or the transport must provide the route |
| `resolvectl query` works, `getaddrinfo` does not | `/etc/nsswitch.conf` `hosts:` line | add `resolve` (install `libnss-resolve`), or point `/etc/resolv.conf` at `127.0.0.53` |
| nothing at all, non-networkd host | `sysctl net.ipv6.conf.<link>.accept_ra` | `accept_ra=2` if forwarding is on; ensure a userspace RDNSS consumer is running |
