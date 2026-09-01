#!/bin/sh
# Shared setup for the two resolvconf-backend Docker harnesses
# (run-resolvconf.sh and run-resolvconf-truncating.sh): both boot the same
# minimal container, install resolvconf(8) at runtime, and register the
# test's fake "pre-existing resolver" the same way - they differ only in
# whether TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS ends up off or
# left at its default. See src/linux/resolvconf.rs, "Loopback truncation",
# for what that knob does and why it matters here.
#
# Sourced, not executed - the caller must already have `set -eu` in
# effect, `cd`'d to the crate root, and `bin` pointing at the compiled
# conditional_forwarding_linux test binary. Defines
# start_resolvconf_container(), which builds the image, boots the
# container into $cid (installing the EXIT cleanup trap), and leaves it
# ready for the caller to just run the test binary against.

start_resolvconf_container() {
  docker build -f docker/Dockerfile.resolvconf -t dns-host-config-resolvconf docker/

  # shellcheck disable=SC2154 # $bin is set by the sourcing script before calling this function
  cid=$(docker run -d --rm --privileged --cgroupns=host \
          --tmpfs /run --tmpfs /tmp \
          -v "$bin":/conditional_forwarding_linux:ro \
          dns-host-config-resolvconf)
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

  # resolvconf(8) gets installed here, not baked into the image - see
  # Dockerfile.resolvconf for why. Point resolv.conf at a real resolver
  # first (Docker's own bind-mounted one is usually already fine, but
  # --privileged lets us also just replace it outright) so `apt-get
  # update` itself can resolve deb.debian.org.
  docker exec "$cid" sh -c 'umount /etc/resolv.conf 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf'
  docker exec "$cid" apt-get update -qq
  docker exec "$cid" apt-get install -y -qq --no-install-recommends resolvconf iproute2

  # resolvconf's postinst captures whatever /etc/resolv.conf held at
  # install time (the bootstrap 8.8.8.8 line above) as a permanent record
  # named "original.resolvconf". Left in place, it would shadow the
  # test's own pre-registered resolver (127.7.7.7, registered as
  # "original0" below) on NXDOMAIN - it was only ever there to let apt
  # resolve deb.debian.org, so drop it now that installation is done.
  docker exec "$cid" resolvconf -d original.resolvconf -f

  if [ "${TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS:-}" = "no" ]; then
    docker exec "$cid" sh -c \
      'echo "TRUNCATE_NAMESERVER_LIST_AFTER_LOOPBACK_ADDRESS=no" > /etc/default/resolvconf'
  fi

  # Register the test's fake "pre-existing resolver" (see
  # tests/conditional_forwarding_linux.rs, ORIGINAL_SERVER_ADDR) under a
  # name resolvconf's default interface-order treats as low-priority
  # (falls into the catch-all "*" bucket), so it plays the same role real
  # original resolvers do relative to our own tun*-prefixed registration.
  docker exec "$cid" sh -c 'echo "nameserver 127.7.7.7" | resolvconf -a original0'

  docker exec "$cid" ip link add dummy0 type dummy
  docker exec "$cid" ip link set dummy0 up
}
