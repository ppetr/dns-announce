#!/usr/bin/env bats
#
# The systemd-resolved backend: a container running systemd +
# systemd-resolved and nothing else touching DNS. Three compiled Rust
# integration tests run against it, sharing one container:
#
#   systemd_resolved_linux       - SetDNS/SetDomains + reset, checked
#                                  directly against a real resolved
#   chain_linux                  - auto-detection picks systemd-resolved,
#                                  set/reset work through the chain
#   conditional_forwarding_linux - the unified split-DNS test
#
# They set()/reset() the same dummy0 link in turn, so this file opts out
# of within-file parallelization (setup_file below).
#
# systemd-resolved routes each query by domain rather than merging a flat
# nameserver list, so the unified test's "pre-existing resolver" is a
# second link (original0) marked as the default-route target with its own
# DNS server, not a registered record - any name not matching dummy0's
# routing-only domain falls through to it. The other two tests never
# touch original0.

bats_require_minimum_version 1.5.0

load helpers

setup_file() {
  cd "$BATS_TEST_DIRNAME/.." || return 1
  require_tools cargo jq docker
  export BATS_NO_PARALLELIZE_WITHIN_FILE=true

  local t bin mounts=()
  for t in systemd_resolved_linux chain_linux conditional_forwarding_linux; do
    bin=$(compile_test_binary "$t") || return 1
    mounts+=(-v "$bin:/$t:ro")
  done

  build_image dns-host-config-systemd-resolved || return 1
  DHC_CID=$(boot_container dns-host-config-systemd-resolved "${mounts[@]}") || return 1
  export DHC_CID

  echo "# container system state: $(wait_for_systemd "$DHC_CID")"

  # dummy0: the interface every suite targets. An address is required,
  # not just link-up - systemd-resolved won't open a DNS scope on an
  # address-less link, and conditional_forwarding_linux does real UDP
  # resolution through it.
  add_dummy_iface "$DHC_CID" dummy0 192.168.50.1/24

  # original0: the unified test's pre-existing resolver, as a
  # default-route link (see the file header).
  add_dummy_iface "$DHC_CID" original0 192.168.51.1/24
  docker exec "$DHC_CID" resolvectl dns original0 127.7.7.7
  docker exec "$DHC_CID" resolvectl default-route original0 yes
}

teardown_file() {
  remove_container "${DHC_CID:-}"
}

@test "systemd_resolved_linux: SetDNS/SetDomains and reset against a real resolved" {
  run run_rust_test "$DHC_CID" systemd_resolved_linux
  [ "$status" -eq 0 ]
}

@test "chain_linux: auto-detection picks systemd-resolved and set/reset work" {
  run run_rust_test "$DHC_CID" chain_linux
  [ "$status" -eq 0 ]
}

@test "conditional forwarding resolves through the systemd-resolved backend" {
  run run_rust_test "$DHC_CID" conditional_forwarding_linux
  [ "$status" -eq 0 ]
  [[ "$output" == *"auto-detected backend: systemd-resolved"* ]]
}
