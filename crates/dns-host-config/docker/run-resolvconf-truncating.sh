#!/bin/sh
# Counterpart to docker/run-resolvconf.sh: the same minimal
# resolvconf(8) container, but left at Debian resolvconf's default
# TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS=y - the configuration
# most real hosts actually have. Under that default, resolvconf drops
# every nameserver after our loopback-addressed, tun*-priority entry from
# the merged /etc/resolv.conf, so LinuxDnsRoute::probe() must refuse the
# resolvconf backend and fall through to static-resolv-conf instead - see
# src/linux/resolvconf.rs, "Loopback truncation".
#
# This script exists to verify that fall-through end to end: it runs the
# same tests/conditional_forwarding_linux.rs unified test as
# docker/run-resolvconf.sh, docker/run-static.sh, and docker/run.sh, and
# expects it to pass via static-resolv-conf even though resolvconf(8) is
# installed and would otherwise have been preferred.
#
# Extra args are forwarded to the test binary (e.g. a test-name filter).
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run-resolvconf-truncating.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

cargo test --no-run --test conditional_forwarding_linux
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test conditional_forwarding_linux \
      | jq -r 'select(.executable != null and .target.name == "conditional_forwarding_linux") | .executable')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "test binary not found" >&2; exit 1; }

# shellcheck source=docker/resolvconf-container-common.sh
. docker/resolvconf-container-common.sh
start_resolvconf_container

# Not `exec` - see the same comment in run-resolvconf.sh: it would skip
# the EXIT trap that removes $cid and leak the container on every run.
# shellcheck disable=SC2154 # $cid is set by start_resolvconf_container() in the sourced file
docker exec "$cid" /conditional_forwarding_linux --ignored --nocapture --test-threads=1 "$@"
