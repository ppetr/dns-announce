#!/bin/sh
# Boot a minimal container with resolvconf(8), with
# TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS explicitly turned off,
# register a fake "pre-existing resolver" with it, create the dummy0
# interface, then run tests/conditional_forwarding_linux.rs against it -
# the same unified test docker/run.sh (systemd-resolved) and
# docker/run-static.sh (no DNS manager at all) also run, so conditional
# forwarding is verified to behave identically regardless of which backend
# LinuxDnsRoute::probe() actually picks.
#
# The knob has to be off for this script to test what its name promises:
# Debian resolvconf's default (on) truncates the merged nameserver list
# right after our loopback-addressed entry, which makes probe() refuse
# this backend and fall through to static-resolv-conf instead - see
# src/linux/resolvconf.rs, "Loopback truncation". That fall-through case,
# with the knob left at its default, is covered separately by
# docker/run-resolvconf-truncating.sh.
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

# shellcheck source=docker/resolvconf-container-common.sh
. docker/resolvconf-container-common.sh
TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS=no
export TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS
start_resolvconf_container

# Not `exec`: that would replace this shell process instead of letting it
# exit normally, and the EXIT trap that removes $cid (set inside
# start_resolvconf_container) only fires on a normal exit - `exec`'d here,
# the container would leak on every run regardless of --rm.
# shellcheck disable=SC2154 # $cid is set by start_resolvconf_container() in the sourced file
docker exec "$cid" /conditional_forwarding_linux --ignored --nocapture --test-threads=1 "$@"
