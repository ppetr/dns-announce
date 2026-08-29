# dns-announce workspace

A Cargo workspace for split-horizon-free, "give this VPN link its own DNS"
tooling. It's split into small, independently useful crates rather than one
monolith, so each piece can be depended on (or replaced) on its own.

## Crates

* [`dns-stack`](crates/dns-stack/) — a transport-agnostic DNS server and
  IPv6 Router Advertisement / RDNSS (RFC 8106) beacon. You supply a
  `Resolver`; it answers queries and, optionally, announces itself via RA.
  Never touches a socket or OS API directly — packets in, packets out, over
  plain channels.

More crates are planned alongside it — see
[`docs/design-dns-host-config.md`](docs/design-dns-host-config.md) for the
next one, which pushes a resolver + routing domain directly into a host's
DNS configuration (systemd-resolved, NetworkManager, macOS, Windows) as an
alternative or complement to RA/RDNSS discovery.

Each crate has its own README, license (all Apache-2.0), and version; there
is no dependency between them, so you can use `dns-stack` with your own host
integration, or a future host-integration crate with your own DNS server.
