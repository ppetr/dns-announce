# Minimal image whose only job is to RUN the loopback integration test with the
# capabilities it needs (CAP_NET_ADMIN, /dev/net/tun). It carries no toolchain,
# no packages, and not even the test binary - docker/run.sh compiles the test on
# the host and bind-mounts it in at /loopback_linux at run time.
#
# Use docker/run.sh; a bare `docker run` of this image without that mount has
# nothing to execute.
FROM debian:stable-slim
ENTRYPOINT ["/loopback_linux", "--ignored", "--nocapture"]
