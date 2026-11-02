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

# systemd-in-a-container with systemd-resolved and nothing else driving DNS,
# so the SystemdResolved backend's D-Bus calls can be exercised against a
# real resolved instance without touching the host's own configuration.
#
# No networkd, no libnss-resolve: docker/systemd_resolved.bats drives resolved directly
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
