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
# The static-/etc/resolv.conf backend: a container with no DNS manager at
# all (no systemd-resolved, no resolvconf, no NetworkManager), so
# LinuxDnsRoute::probe() falls through every smarter backend and lands on
# StaticResolvConf. With nothing managing resolv.conf, "the host's
# pre-existing resolver" is just the one line already in the file for
# StaticResolvConf to back up and preserve.

bats_require_minimum_version 1.5.0

load helpers

setup_file() {
  cd "$BATS_TEST_DIRNAME/.." || return 1
  require_tools cargo jq docker

  local bin
  bin=$(compile_test_binary conditional_forwarding_linux) || return 1
  build_image dns-host-config-static -f "$BATS_TEST_DIRNAME/Dockerfile.static" || return 1
  DHC_CID=$(boot_container dns-host-config-static \
    -v "$bin:/conditional_forwarding_linux:ro") || return 1
  export DHC_CID

  docker exec "$DHC_CID" sh -c \
    'umount /etc/resolv.conf 2>/dev/null; printf "nameserver 127.7.7.7\n" > /etc/resolv.conf'
  add_dummy_iface "$DHC_CID" dummy0
}

teardown_file() {
  remove_container "${DHC_CID:-}"
}

@test "conditional forwarding resolves through the static-resolv-conf backend" {
  run run_rust_test "$DHC_CID" conditional_forwarding_linux
  [ "$status" -eq 0 ]
  [[ "$output" == *"auto-detected backend: static-resolv-conf"* ]]
}
