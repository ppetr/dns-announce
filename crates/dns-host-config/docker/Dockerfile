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

# See docker-resolv-conf-fixup.service: Docker's own /etc/resolv.conf bind
# mount blocks the postinst above from replacing it with resolved's
# symlink, so a unit undoes that at every boot instead - idempotent and a
# no-op outside Docker, so nothing downstream (this image or a real host)
# needs to special-case which one it's running in.
COPY docker-resolv-conf-fixup.service /etc/systemd/system/docker-resolv-conf-fixup.service
RUN systemctl enable systemd-resolved docker-resolv-conf-fixup.service

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/lib/systemd/systemd"]
