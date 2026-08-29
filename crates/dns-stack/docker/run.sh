#!/bin/sh
# Compile the loopback integration test on the host, then run it inside a
# minimal debian-slim container with the test binary bind-mounted in (nothing
# is copied into the image or the repo). Any arguments are forwarded to the
# test binary, e.g. a test-name filter.
#
# The container only runs the binary, so the host's glibc must be <= the
# container's (debian:stable-slim) - true for any reasonably current distro.
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
  echo "docker/run.sh needs jq to locate the compiled test binary" >&2
  exit 1
}

# Compile the test (compile errors surface here, with normal formatting).
cargo test --no-run --test loopback_linux

# Ask cargo exactly which file that produced - robust against stale hashes in
# target/debug/deps and against the artifact filename scheme changing.
bin=$(cargo test --no-run --message-format=json-render-diagnostics --test loopback_linux \
      | jq -r 'select(.executable != null and .target.name == "loopback_linux") | .executable')

[ -n "$bin" ] && [ -x "$bin" ] || {
  echo "could not locate the loopback_linux test binary" >&2
  exit 1
}

docker build -t dns-stack-loopback docker/
exec docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun \
  -v "$bin":/loopback_linux:ro \
  dns-stack-loopback "$@"
