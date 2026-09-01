# shellcheck shell=bash
#
# Shared helpers for the bats suites in this directory (static.bats,
# resolvconf.bats, resolvconf_truncating.bats, systemd_resolved.bats).
# Each suite boots one Docker container in setup_file, runs one or more
# compiled Rust integration-test binaries inside it, and tears the
# container down in teardown_file. Load with `load helpers`.

# Fail the current bats context (setup_file / a test) with a message.
dhc_fail() {
  printf 'helpers.bash: %s\n' "$*" >&2
  return 1
}

# require_tools jq docker ... - abort unless every named tool is on PATH.
require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || dhc_fail "required tool not found: $tool"
  done
}

# compile_test_binary <cargo-test-name> - build the named `tests/*.rs`
# integration test and echo the path to its compiled binary. Must run
# with the crate (or workspace) as the working directory.
compile_test_binary() {
  local name=$1 bin
  cargo test --no-run --test "$name" >&2 || dhc_fail "cargo test --no-run --test $name failed"
  bin=$(
    cargo test --no-run --message-format=json-render-diagnostics --test "$name" |
      jq -r --arg t "$name" 'select(.executable != null and .target.name == $t) | .executable'
  )
  [[ -n $bin && -x $bin ]] || dhc_fail "compiled binary for $name not found"
  printf '%s\n' "$bin"
}

# build_image <tag> [docker-build-args...] - build an image from a
# Dockerfile in this directory, which is also the build context. Pass the
# Dockerfile with `-f "$BATS_TEST_DIRNAME/Dockerfile.<name>"`; the default
# `Dockerfile` needs no `-f`.
build_image() {
  local tag=$1
  shift
  docker build "$@" -t "$tag" "$BATS_TEST_DIRNAME" >&2 ||
    dhc_fail "docker build -t $tag failed"
}

# boot_container <image> [docker-run-args...] - start a detached,
# self-removing, privileged container and echo its id. Extra args (e.g.
# `-v src:dst:ro`) go before the image.
boot_container() {
  local image=$1
  shift
  docker run -d --rm --privileged --cgroupns=host --tmpfs /run --tmpfs /tmp \
    "$@" "$image" || dhc_fail "docker run $image failed"
}

# remove_container <cid> - best-effort teardown; never fails.
remove_container() {
  docker rm -f "$1" >/dev/null 2>&1 || true
}

# add_dummy_iface <cid> <name> [cidr] - create an up dummy interface,
# optionally with an address (systemd-resolved needs one before it will
# open a DNS scope on the link).
add_dummy_iface() {
  local cid=$1 name=$2 cidr=${3:-}
  docker exec "$cid" ip link add "$name" type dummy
  docker exec "$cid" ip link set "$name" up
  [[ -z $cidr ]] || docker exec "$cid" ip addr add "$cidr" dev "$name"
}

# run_rust_test <cid> <cargo-test-name> [extra-args...] - run a compiled
# integration-test binary mounted at /<name> inside the container, with
# the flags every one of these suites needs.
run_rust_test() {
  local cid=$1 name=$2
  shift 2
  docker exec "$cid" "/$name" --ignored --nocapture --test-threads=1 "$@"
}
