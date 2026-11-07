#!/usr/bin/env bats
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

#
# The systemd-resolved backend on a host with no other DNS configured
# anywhere - relying entirely on resolved's FallbackDNS=. Verifies
# SystemdResolved::set() refuses a routing-only domain in this case rather
# than silently taking resolved's FallbackDNS= offline for everything else -
# see "Known limitation: hosts with no real resolver" in
# src/linux/systemd_resolved.rs and docs/design-dns-host-config.md.
#
# Deliberately a separate container from systemd_resolved.bats: that one
# always configures original0 as a default-route link (needed by the tests
# sharing it), which would defeat this scenario.

bats_require_minimum_version 1.5.0

load helpers

setup_file() {
  cd "$BATS_TEST_DIRNAME/.." || return 1
  require_tools cargo jq docker

  local bin
  bin=$(compile_test_binary no_fallback_resolver_linux) || return 1
  build_image dns-host-config-systemd-resolved || return 1
  DHC_CID=$(boot_container dns-host-config-systemd-resolved \
    -v "$bin:/no_fallback_resolver_linux:ro") || return 1
  export DHC_CID

  echo "# container system state: $(wait_for_systemd "$DHC_CID")"

  # dummy0 only - an address (resolved needs one to open a DNS scope), no
  # default-route link, no global DNS=, so Manager.DNS stays empty until
  # the test's own set() call tries to change that.
  add_dummy_iface "$DHC_CID" dummy0 192.168.50.1/24
}

teardown_file() {
  remove_container "${DHC_CID:-}"
}

@test "set() refuses a routing-only domain when relying solely on FallbackDNS" {
  run run_rust_test "$DHC_CID" no_fallback_resolver_linux
  [ "$status" -eq 0 ]
}
