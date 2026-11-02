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

# Minimal image whose only job is to RUN the loopback integration test with the
# capabilities it needs (CAP_NET_ADMIN, /dev/net/tun). It carries no toolchain,
# no packages, and not even the test binary - docker/run.sh compiles the test on
# the host and bind-mounts it in at /loopback_linux at run time.
#
# Use docker/run.sh; a bare `docker run` of this image without that mount has
# nothing to execute.
FROM debian:stable-slim
ENTRYPOINT ["/loopback_linux", "--ignored", "--nocapture"]
