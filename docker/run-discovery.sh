#!/bin/sh
# Boot a container running systemd-networkd + systemd-resolved, then run the
# RA/RDNSS discovery tests (tests/discovery_linux.rs) against it: the test
# creates the TUN and runs the beacon, networkd hands the advertised resolver
# to resolved, and getaddrinfo("foo.myvpn") resolves end to end.
#
# Extra args are forwarded to the test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run-discovery.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

cargo test --no-run --test discovery_linux
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test discovery_linux \
      | jq -r 'select(.executable != null and .target.name == "discovery_linux") | .executable')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary not found" >&2; exit 1; }

docker build -f docker/Dockerfile.discovery -t dns-announce-discovery docker/

cid=$(docker run -d --rm --privileged --cgroupns=host --device=/dev/net/tun \
        --tmpfs /run --tmpfs /tmp \
        -v "$bin":/discovery_linux:ro \
        dns-announce-discovery)
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

# Layered discovery tests, sequential (they touch global resolver state).
exec docker exec "$cid" /discovery_linux --ignored --nocapture --test-threads=1 "$@"
