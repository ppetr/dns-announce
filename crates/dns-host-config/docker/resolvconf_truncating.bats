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
# resolvconf(8) left at Debian's default
# TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS=y - the configuration
# most real hosts with resolvconf installed actually have. Under it,
# resolvconf drops every nameserver after our loopback-addressed,
# tun*-priority entry from the merged /etc/resolv.conf, so
# Resolvconf::probe() must refuse the backend and LinuxDnsRoute must fall
# through to static-resolv-conf. This suite verifies that fall-through
# end to end. See src/linux/resolvconf.rs, "Loopback truncation".

bats_require_minimum_version 1.5.0

load helpers

setup_file() {
  cd "$BATS_TEST_DIRNAME/.." || return 1
  require_tools cargo jq docker

  local bin
  bin=$(compile_test_binary conditional_forwarding_linux) || return 1
  build_image dns-host-config-resolvconf \
    -f "$BATS_TEST_DIRNAME/Dockerfile.resolvconf" || return 1
  DHC_CID=$(boot_container dns-host-config-resolvconf \
    -v "$bin:/conditional_forwarding_linux:ro") || return 1
  export DHC_CID

  setup_resolvconf_container "$DHC_CID"
}

teardown_file() {
  remove_container "${DHC_CID:-}"
}

@test "conditional forwarding falls through to static-resolv-conf when resolvconf truncates" {
  run run_rust_test "$DHC_CID" conditional_forwarding_linux
  [ "$status" -eq 0 ]
  [[ "$output" == *"auto-detected backend: static-resolv-conf"* ]]
}
