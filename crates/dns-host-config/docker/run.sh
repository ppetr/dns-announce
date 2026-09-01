#!/bin/sh
# Boot a container running systemd + systemd-resolved (nothing else touches
# DNS in it), create a dummy interface for resolved to know about, then run
# every "*_linux" integration test in tests/ against it: they drive the
# real org.freedesktop.resolve1 D-Bus API (directly, or via
# LinuxDnsRoute's auto-detection) and check the result with `resolvectl`,
# plus tests/conditional_forwarding_linux.rs - the same unified test
# docker/run-resolvconf.sh, docker/run-resolvconf-truncating.sh, and
# docker/run-static.sh also run, so conditional forwarding is verified to
# behave identically no matter which backend ends up in charge.
#
# Extra args are forwarded to each test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run.sh needs jq to locate the compiled test binaries" >&2
  exit 1
}

tests="systemd_resolved_linux chain_linux conditional_forwarding_linux"

mount_args=""
for t in $tests; do
  cargo test --no-run --test "$t"
  bin=$(cargo test --no-run --message-format=json-render-diagnostics --test "$t" \
        | jq -r --arg t "$t" 'select(.executable != null and .target.name == $t) | .executable')
  [ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary for $t not found" >&2; exit 1; }
  mount_args="$mount_args -v ${bin}:/${t}:ro"
done

docker build -t dns-host-config-systemd-resolved docker/

# shellcheck disable=SC2086 # $mount_args is a deliberately unquoted list of -v flags
cid=$(docker run -d --rm --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /tmp \
        $mount_args \
        dns-host-config-systemd-resolved)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

# Wait for systemd to finish booting.
state=""
i=0
while [ "$i" -lt 30 ]; do
  state=$(docker exec "$cid" systemctl is-system-running 2>/dev/null || true)
  case "$state" in running | degraded) break ;; esac
  i=$((i + 1))
  sleep 1
done
echo "container system state: ${state:-unknown}"

# The tests target a fixed interface name; the harness creates it since
# the test binaries themselves have no CAP_NET_ADMIN-using code of their
# own. An address is required, not just link-up: systemd-resolved doesn't
# create a DNS scope for an address-less link (its per-link DNS/domain
# config is accepted over D-Bus but never actually used for a query until
# then), and conditional_forwarding_linux does real UDP resolution
# through it via getent, unlike the other two tests here which only
# inspect resolved's D-Bus state.
docker exec "$cid" ip link add dummy0 type dummy
docker exec "$cid" ip link set dummy0 up
docker exec "$cid" ip addr add 192.168.50.1/24 dev dummy0

# conditional_forwarding_linux's fake "pre-existing resolver" (see that
# test's module docs, ORIGINAL_SERVER_ADDR). systemd-resolved routes each
# query by domain rather than merging a flat nameserver list, so
# "already configured" here can't mean a registered record the way it
# does for the resolvconf/static backends - it means a *second* link,
# marked as the default-route target, carrying its own DNS server. Any
# query whose name doesn't match dummy0's routing-only domain (set by
# the test's own set() call) falls through to whichever link is marked
# default-route, exactly mirroring what a real second network interface
# with its own DHCP-provided DNS would do. Harmless to the other two
# tests in this loop - they never touch this interface.
docker exec "$cid" ip link add original0 type dummy
docker exec "$cid" ip link set original0 up
docker exec "$cid" ip addr add 192.168.51.1/24 dev original0
docker exec "$cid" resolvectl dns original0 127.7.7.7
docker exec "$cid" resolvectl default-route original0 yes

status=0
for t in $tests; do
  echo "=== $t ==="
  docker exec "$cid" "/$t" --ignored --nocapture --test-threads=1 "$@" || status=$?
done
exit "$status"
