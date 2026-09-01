#!/usr/bin/env bats
#
# The resolvconf(8) backend, with
# TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS turned off so
# Resolvconf::probe() actually accepts it. Debian resolvconf's default
# (on) truncates the merged nameserver list right after our
# loopback-addressed, first-sorted entry, which makes probe() refuse the
# backend and fall through to static-resolv-conf - that case is covered
# by resolvconf_truncating.bats. See src/linux/resolvconf.rs, "Loopback
# truncation".

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

  setup_resolvconf_container "$DHC_CID" --truncate-off
}

teardown_file() {
  remove_container "${DHC_CID:-}"
}

@test "conditional forwarding resolves through the resolvconf backend" {
  run run_rust_test "$DHC_CID" conditional_forwarding_linux
  [ "$status" -eq 0 ]
  [[ "$output" == *"auto-detected backend: resolvconf"* ]]
}
