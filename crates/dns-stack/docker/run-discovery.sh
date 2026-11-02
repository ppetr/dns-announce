#!/bin/sh
# Copyright 2026 <https://github.com/ppetr/>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

docker build -f docker/Dockerfile.discovery -t dns-stack-discovery docker/

cid=$(docker run -d --rm --privileged --cgroupns=host --device=/dev/net/tun \
        --tmpfs /run --tmpfs /tmp \
        -v "$bin":/discovery_linux:ro \
        dns-stack-discovery)
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
