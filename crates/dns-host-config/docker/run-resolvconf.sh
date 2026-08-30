#!/bin/sh
# Boot a minimal container with resolvconf(8) and nothing else touching
# DNS, register a fake "pre-existing resolver" with it, create the dummy0
# interface, then run tests/conditional_forwarding_linux.rs against it -
# the same test docker/run.sh (systemd-resolved) also runs, so conditional
# forwarding is verified to behave identically regardless of which backend
# LinuxDnsRoute::probe() actually picks. A static-resolv-conf variant of
# this script is a planned addition, not built yet.
#
# KNOWN FAILING right now: the second assertion (a name outside our suffix
# falls through to the pre-registered resolver below) fails - see
# src/linux/resolvconf.rs, "Known issue: the merge doesn't happen when
# driven from this code (unresolved)". The first assertion (our suffix
# resolves through us) passes.
#
# Extra args are forwarded to the test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run-resolvconf.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

cargo test --no-run --test conditional_forwarding_linux
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test conditional_forwarding_linux \
      | jq -r 'select(.executable != null and .target.name == "conditional_forwarding_linux") | .executable')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary not found" >&2; exit 1; }

docker build -f docker/Dockerfile.resolvconf -t dns-host-config-resolvconf docker/

cid=$(docker run -d --rm --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /tmp \
        -v "$bin":/conditional_forwarding_linux:ro \
        dns-host-config-resolvconf)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

# resolvconf(8) gets installed here, not baked into the image - see
# Dockerfile.resolvconf for why. Point resolv.conf at a real resolver
# first (Docker's own bind-mounted one is usually already fine, but
# --privileged lets us also just replace it outright) so `apt-get
# update` itself can resolve deb.debian.org.
docker exec "$cid" sh -c 'umount /etc/resolv.conf 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf'
docker exec "$cid" apt-get update -qq
docker exec "$cid" apt-get install -y -qq --no-install-recommends resolvconf iproute2

# Register the test's fake "pre-existing resolver" (see
# tests/conditional_forwarding_linux.rs, ORIGINAL_SERVER_ADDR) under a
# name resolvconf's default interface-order treats as low-priority
# (falls into the catch-all "*" bucket), so it plays the same role real
# original resolvers do relative to our own tun*-prefixed registration.
docker exec "$cid" sh -c 'echo "nameserver 127.7.7.7" | resolvconf -a original0'

docker exec "$cid" ip link add dummy0 type dummy
docker exec "$cid" ip link set dummy0 up

exec docker exec "$cid" /conditional_forwarding_linux --ignored --nocapture --test-threads=1 "$@"
