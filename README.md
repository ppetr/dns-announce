# dns-announce

Announce a DNS resolver to link-local IPv6 clients over a point-to-point or
shared link, so a stock OS IPv6 stack **auto-discovers it with zero client-side
configuration**, and answer the queries that come back with a tiny in-process
DNS server whose policy you supply.

The classic use case is **split-horizon DNS for a VPN-style link**: clients keep
using their normal resolver for everything, but names under one suffix
(`*.myvpn`) get answered by you.

```text
          ┌─────────────────────── your process ───────────────────────┐
          │                                                            │
 link  ──►│  inbound packets ─► dns-announce ─► Resolver (your code)    │
(tun,     │   (mpsc<Vec<u8>>)        │            answer / NXDOMAIN /   │
 io_uring,│                         ▼            "not mine"            │
 socket,  │  outbound packets ◄─ RA beacon + RS replies + DNS replies  │
 test)  ◄─│   (mpsc<Vec<u8>>)                                          │
          │                                                            │
          └────────────────────────────────────────────────────────────┘
```

## How it works

* **RA/RDNSS beacon.** Periodically emits unsolicited ICMPv6 Router
  Advertisements to `ff02::1` carrying the RDNSS (RFC 8106) and DNSSL options —
  i.e. "use this DNS server" and "append this search domain". Also answers
  Router Solicitations with a unicast RA. Hop-limit / source-address rules from
  RFC 4861 are enforced so off-link spoofed solicitations are ignored.
* **In-process DNS server.** Every query addressed to the advertised resolver
  address on UDP/53 is parsed and handed to your `Resolver`. It returns one of
  three verdicts:

  | `Reply`            | Wire result | Effect on the client |
  |--------------------|-------------|----------------------|
  | `Answer(Addrs(…))` | `NOERROR`   | Uses the addresses. An empty list is a clean NOERROR/no-data. |
  | `NxDomain`         | `NXDOMAIN`  | Name does not exist; client caches the negative and does **not** ask another resolver. |
  | `NotMine`          | `REFUSED`   | Client falls back to its other configured resolvers. This is what keeps unrelated lookups working. |

  Only `A` / `AAAA` are synthesized, and only in the family the client asked
  for. Message parsing/serialization is delegated to
  [`simple-dns`](https://crates.io/crates/simple-dns); its types are kept out of
  the public API so it can be swapped later without a breaking change.

## Design: transport-agnostic

The crate **never touches a network device, socket, or OS API.** It consumes
inbound IP packets from a `tokio::sync::mpsc::Receiver<In>` and produces
outbound IP packets on a `tokio::sync::mpsc::Sender<Vec<u8>>`.

`In` is any `Deref<Target = [u8]> + Send + 'static` — `Vec<u8>`,
`bytes::Bytes`, `Box<[u8]>`, an io_uring buffer wrapper, whatever your transport
hands you. Only the bytes are ever read. Replies are small and synthesized from
scratch, so they are always freshly allocated `Vec<u8>`.

Consequences:

* Bridging the channels to a real packet source is **your job** (see
  [`examples/basic.rs`](examples/basic.rs) for a `tun-rs` bridge).
* Assigning `link_local_src` and `server_addr` as real addresses on the
  interface is also your job — this crate does no interface configuration.
* Unit testing is trivial: push byte buffers in, pop byte buffers out. See
  [`tests/stack.rs`](tests/stack.rs), which drives the whole stack with the
  tokio clock paused and no sockets at all.

## Quick start

```toml
[dependencies]
dns-announce = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync"] }
async-trait = "0.1"
```

```rust
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dns_announce::dns::{matches_suffix, Answer, DnsConfig, Query, Reply, Resolver};
use dns_announce::ra::RaConfig;
use dns_announce::DnsAnnounce;
use tokio::sync::mpsc;

struct MyResolver;

#[async_trait]
impl Resolver for MyResolver {
    async fn resolve(&self, query: &Query) -> Reply {
        // Only names under "myvpn" are ours; everything else is REFUSED
        // so the OS asks its real resolver.
        if !matches_suffix(&query.name, "myvpn") {
            return Reply::NotMine;
        }
        match query.name.as_str() {
            "foo.myvpn" => {
                let addr: IpAddr = "fd00:aaaa::2".parse().unwrap();
                Reply::Answer(Answer::Addrs(vec![addr]))
            }
            _ => Reply::NxDomain,
        }
    }
}

# async fn run() {
// These must actually be assigned to your interface at the OS level.
let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
let server_addr: Ipv6Addr = "fd00:aaaa::1".parse().unwrap();

let ra_cfg = RaConfig {
    link_local_src: link_local,
    dns_servers: vec![server_addr],
    search_domains: vec!["myvpn".to_string()],
    lifetime_secs: 1800,
    router_lifetime_secs: 0, // do NOT become the default IPv6 route
    resend_interval: Duration::from_secs(600),
};
let dns_cfg = DnsConfig { server_addr };

let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Vec<u8>>(256);

// Spawns the beacon + dispatcher tasks. Must be called from within a
// tokio runtime.
DnsAnnounce::new(ra_cfg, dns_cfg).spawn(incoming_rx, outgoing_tx, Arc::new(MyResolver));

// Now bridge `incoming_tx` / `outgoing_rx` to your packet source.
# let _ = &mut outgoing_rx;
# let _ = incoming_tx;
# }
```

`Query` gives you `name` (the queried name, trailing dot stripped, ASCII
lowercased) and `kind` (`RecordKind::A` / `Aaaa` / `Other`). `matches_suffix` is
the ready-made label-boundary, case-insensitive suffix check for the "one
suffix" gate.

Both spawned tasks stop cleanly once `outgoing` has no live receivers or
`incoming` closes.

## Configuration reference

### `RaConfig`

| Field                  | Meaning |
|------------------------|---------|
| `link_local_src`       | Link-local source address of your interface (`fe80::/10`). RAs are sent from here. |
| `dns_servers`          | Resolver address(es) to advertise via RDNSS — usually just your own address on this link. |
| `search_domains`       | Search domain(s) to advertise via DNSSL, e.g. `"myvpn.example"`. Empty ⇒ no DNSSL option. Use **≥ 2 labels**: `systemd-resolved` drops a single bare label as a routing domain ([Linux setup](docs/setup.linux.md)). |
| `lifetime_secs`        | How long resolvers should trust the RDNSS/DNSSL entries. RFC 8106 recommends ≥ 2× the resend interval. |
| `router_lifetime_secs` | Router Lifetime in the RA header. Keep `0` unless you actually want to become the default IPv6 route. |
| `resend_interval`      | How often to re-send unsolicited RAs to `ff02::1`. |

### `DnsConfig`

| Field         | Meaning |
|---------------|---------|
| `server_addr` | IPv6 address this DNS server answers on. Queries to any other address are ignored (fall through). |

## Non-goals / current limitations

* No interface / address / route configuration — you assign the addresses.
* No transport — you bridge the channels to real packet I/O.
* Inbound parsing assumes a plain IPv6 header with **no extension headers**;
  such packets are ignored.
* Only the **first question** of a query is considered.
* Only `A` / `AAAA` answers. No `CNAME` / `TXT` / `SRV` / `PTR`, no EDNS(0), no
  TCP fallback / truncation.
* Answer TTL is a fixed 60 s.
* **RDNSS is best-effort.** Platform support varies a lot; macOS and iOS do not
  implement RFC 8106 at all as of this writing. For production, pair this with a
  platform-specific resolver-configuration fallback (see below).

## Client-side setup

> **Linux:** [`docs/setup.linux.md`](docs/setup.linux.md) is the full guide —
> `systemd-networkd`/`-resolved` configuration, the direct `resolvectl`
> alternative, the non-obvious failure modes (RA source vs. interface address,
> networkd flushing "foreign" addresses, single-label DNSSL domains), and the
> containerised integration tests.

This crate emits raw packets through your transport, so **the sending host needs
no sysctl changes** — it bypasses the kernel's RA machinery entirely (no
`net.ipv6.conf.*.forwarding` required for the announcement itself).

The **receiving** host is where it matters, and that is a client-side concern
(in Linux) this crate does not control:

* **`net.ipv6.conf.<iface>.accept_ra`** must be non-zero. Default is `1`, but if
  that host has `net.ipv6.conf.all.forwarding=1` the default flips to `0` and
  RAs are ignored — then you need `accept_ra=2` on the relevant (usually tunnel)
  interface.
* **`net.ipv6.conf.<iface>.disable_ipv6=0`** (and `all.disable_ipv6=0`).
* **The kernel does not parse RDNSS/DNSSL itself** — a userspace consumer must be
  running or the options are silently dropped even with `accept_ra` on:
  `systemd-networkd` (`IPv6AcceptRA=yes`, `UseDNS=yes`, and `UseDomains=route`
  for *scoped* split DNS — the default `no` gives you the resolver globally)
  feeding `systemd-resolved`, or NetworkManager, or `dhcpcd`, or the legacy
  `rdnssd`. On a link networkd manages this way it also takes over the link's
  global addresses — see [`docs/setup.linux.md`](docs/setup.linux.md).
* `router_lifetime_secs: 0` (the default here) is fine — DNS consumers still
  parse RDNSS; it only means no default route is installed.
* IPv6 has no `rp_filter` sysctl, but an nftables `fib` / `rpfilter` rule or a
  strict firewall can drop the injected DNS replies on the tunnel interface —
  make sure that interface's traffic is allowed.

## Possible future improvements

### Reaching platforms that ignore RA/RDNSS

RFC 8106 is the cleanest mechanism where it works, but several stacks never
consume it. A companion, opt-in `platform` module (feature-gated, privileged,
inherently OS-specific — kept out of the transport-agnostic core) could push the
same `dns_servers` / `search_domains` through the native channel instead:

* **macOS / iOS** — no RDNSS support at all. Options:
  * write a resolver file at `/etc/resolver/<suffix>` (file-based split DNS;
    `man 5 resolver`), or
  * set `SupplementalMatchDomains` + `ServerAddresses` in the
    SystemConfiguration dynamic store
    (`State:/Network/Service/<id>/DNS`, via `scutil` / the
    `SystemConfiguration` framework). iOS realistically needs a
    `NEDNSSettingsManager` / Network Extension profile.
* **Windows** — RDNSS is only honored by recent builds. Use the **Name
  Resolution Policy Table**: `Add-DnsClientNrptRule -Namespace ".myvpn"
  -NameServers …`, or per-interface DNS via
  `netsh interface ipv6 add dnsserver` / `Set-DnsClientServerAddress`.
* **Linux with `systemd-resolved`** — works via RDNSS on a managed link, but an
  explicit path is more reliable for split DNS:
  `resolvectl dns <link> <addr>` + `resolvectl domain <link> ~myvpn` (the `~`
  makes it routing-only), or the D-Bus `SetLinkDNS` / `SetLinkDomains` API.
* **Linux without `systemd-resolved`** — `resolvconf` / `openresolv`, or
  managing `/etc/resolv.conf` directly.
* **Android** — only reachable from inside the app's own `VpnService`:
  `VpnService.Builder::addDnsServer` / `addSearchDomain`.

### Alternative announcement channels

* **Stateless DHCPv6 DNS options (RFC 3646).** Set the RA `O` flag and answer
  `Information-Request` with `OPTION_DNS_SERVERS` / `OPTION_DOMAIN_LIST`. Reaches
  clients that do DHCPv6 but ignore RDNSS.
* **IPv4 support.** DHCPv4 option 6 (DNS) / option 119 (domain search) for
  dual-stack links — an entirely separate mechanism.
* **mDNS / DNS-SD responder** for `.local` discovery on the link.

### DNS server features

* Multiple questions per query.
* More record types: `CNAME`, `TXT`, `SRV`, and `PTR` for reverse lookups.
* EDNS(0), response truncation + TCP fallback.
* Per-answer / resolver-controlled TTL instead of the fixed 60 s.
* Optional query-logging / metrics hooks and `tracing` spans (currently `log`).

### RA / packet handling

* Parse IPv6 extension headers on inbound packets instead of dropping them.
* MTU option; Prefix Information option if the crate ever grows addressing.
* Rate-limit solicited RAs (RFC 4861 `MIN_DELAY_BETWEEN_RAS`) and send a small
  burst on solicitation.
* Config validation: `link_local_src` really in `fe80::/10`, `dns_servers`
  non-empty, `lifetime_secs` ≥ 2× `resend_interval`.

### Lifecycle

* Return a shutdown handle (`JoinHandle` / `CancellationToken`) rather than
  relying on channel closure.
* On shutdown, emit a final RA with RDNSS lifetime `0` to withdraw the resolver
  promptly instead of letting clients time it out.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
