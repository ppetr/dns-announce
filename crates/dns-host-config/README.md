# dns-host-config

Push a DNS resolver and a routing domain into a host's DNS configuration —
`systemd-resolved` today, more backends planned — and withdraw it again.

```text
your DNS server (any implementation) ──┐
                                        ├─► DnsRouteConfig { servers, routing_domains }
your VPN/tunnel's interface name ──────┘
                                              │
                                              ▼
                                    dns-host-config::DnsRoute
                                              │
                                              ▼
                          whatever the host actually runs
                    (systemd-resolved today; NetworkManager,
                     resolvconf, macOS, Windows planned)
```

This is the OS-integration half of the story
[`dns-stack`](../dns-stack/)'s RA/RDNSS beacon is the other half of — but
**there is no dependency between the two crates**. Anyone running their own
DNS server on a VPN, tunnel, or test link and wanting a host to actually use
it can drive this crate directly; `dns-stack` doesn't know this crate
exists, and vice versa.

## What this is (and isn't)

This configures **conditional forwarding by queried name**: an existing
host resolver is told "queries under these domains go to `servers`;
everything else keeps using whatever the host already had." This is often
called "split DNS" — not to be confused with *split-horizon* DNS, which
varies answers by the *source* of a query. There's no source-based logic
here, and none is needed: whoever is asking is always the local host.

This crate does **not** assign addresses, bring up interfaces, or manage
routes. `interface` is assumed to already exist and `servers` to already be
reachable through it — that remains the caller's job.

## Status

Linux only, `systemd-resolved` backend in progress. See
[`../../docs/design-dns-host-config.md`](../../docs/design-dns-host-config.md)
for the full planned backend chain (NetworkManager, resolvconf, static
`/etc/resolv.conf` on Linux; `/etc/resolver/<suffix>` on macOS; NRPT on
Windows) and the architecture notes it's based on.

## License

Apache-2.0, same as `dns-stack`.
