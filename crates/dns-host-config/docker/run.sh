#!/bin/sh
# Boot a container running systemd + systemd-resolved (nothing else touches
# DNS in it), create a dummy interface for resolved to know about, then run
# tests/systemd_resolved_linux.rs against it: the test drives the real
# org.freedesktop.resolve1 D-Bus API and checks the result with
# `resolvectl`.
#
# Extra args are forwarded to the test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

cargo test --no-run --test systemd_resolved_linux
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test systemd_resolved_linux \
      | jq -r 'select(.executable != null and .target.name == "systemd_resolved_linux") | .executable')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary not found" >&2; exit 1; }

docker build -t dns-host-config-systemd-resolved docker/

cid=$(docker run -d --rm --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /tmp \
        -v "$bin":/systemd_resolved_linux:ro \
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

# The test targets a fixed interface name; the harness creates it since the
# test binary itself has no CAP_NET_ADMIN-using code of its own.
docker exec "$cid" ip link add dummy0 type dummy
docker exec "$cid" ip link set dummy0 up

exec docker exec "$cid" /systemd_resolved_linux --ignored --nocapture --test-threads=1 "$@"
