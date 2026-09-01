#!/bin/sh
# Boot a minimal container with no DNS manager at all - no
# systemd-resolved, no resolvconf, no NetworkManager - so
# LinuxDnsRoute::probe() must fall through every smarter backend and land
# on StaticResolvConf, then run tests/conditional_forwarding_linux.rs
# against it directly. The same unified test docker/run.sh
# (systemd-resolved), docker/run-resolvconf.sh, and
# docker/run-resolvconf-truncating.sh also run, so conditional forwarding
# is verified to behave identically no matter which backend ends up in
# charge.
#
# Extra args are forwarded to the test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run-static.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

cargo test --no-run --test conditional_forwarding_linux
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test conditional_forwarding_linux \
      | jq -r 'select(.executable != null and .target.name == "conditional_forwarding_linux") | .executable')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary not found" >&2; exit 1; }

docker build -f docker/Dockerfile.static -t dns-host-config-static docker/

cid=$(docker run -d --rm --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /tmp \
        -v "$bin":/conditional_forwarding_linux:ro \
        dns-host-config-static)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

# The test's fake "pre-existing resolver" (see
# tests/conditional_forwarding_linux.rs, ORIGINAL_SERVER_ADDR) - with no
# DNS manager in the picture, "register an existing nameserver" just
# means it's the one line already sitting in /etc/resolv.conf for
# StaticResolvConf to find, back up, and preserve.
docker exec "$cid" sh -c 'umount /etc/resolv.conf 2>/dev/null; echo "nameserver 127.7.7.7" > /etc/resolv.conf'

docker exec "$cid" ip link add dummy0 type dummy
docker exec "$cid" ip link set dummy0 up

# Not `exec`: that would replace this shell process instead of letting it
# exit normally, and the EXIT trap above (which removes $cid) only fires
# on a normal exit - `exec`'d here, the container would leak on every run
# regardless of --rm.
docker exec "$cid" /conditional_forwarding_linux --ignored --nocapture --test-threads=1 "$@"
