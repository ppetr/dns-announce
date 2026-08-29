# systemd-in-a-container with systemd-resolved and nothing else driving DNS,
# so the SystemdResolved backend's D-Bus calls can be exercised against a
# real resolved instance without touching the host's own configuration.
#
# No networkd, no libnss-resolve: docker/run.sh drives resolved directly
# over D-Bus and checks the result with `resolvectl`, it never resolves a
# name through nsswitch.
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv systemd-resolved dbus iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN systemctl enable systemd-resolved

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/lib/systemd/systemd"]
