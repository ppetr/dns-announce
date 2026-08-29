#!/bin/sh
# Boot a container running systemd + systemd-resolved (nothing else touches
# DNS in it), create a dummy interface for resolved to know about, then run
# every "*_linux" integration test in tests/ against it: they drive the
# real org.freedesktop.resolve1 D-Bus API (directly, or via
# LinuxDnsRoute's auto-detection) and check the result with `resolvectl`.
#
# Extra args are forwarded to each test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run.sh needs jq to locate the compiled test binaries" >&2
  exit 1
}

tests="systemd_resolved_linux chain_linux"

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
# own.
docker exec "$cid" ip link add dummy0 type dummy
docker exec "$cid" ip link set dummy0 up

status=0
for t in $tests; do
  echo "=== $t ==="
  docker exec "$cid" "/$t" --ignored --nocapture --test-threads=1 "$@" || status=$?
done
exit "$status"
