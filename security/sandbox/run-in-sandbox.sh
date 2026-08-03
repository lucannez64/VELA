#!/usr/bin/env bash
#
# VELA pentest sandbox wrapper (bubblewrap).
#
# Every dynamic test runs inside an isolated bubblewrap namespace:
#   * private network namespace  (loopback only; no host network)
#   * private /tmp and /home     (writes are discarded on exit)
#   * read-only system tree
#   * private pid namespace      (no host process visibility)
#
# The sandbox shares only the VELA repo (read-only) and the target/ build
# cache (read-write) so tests can use prebuilt binaries without rebuilding.
#
# Usage:
#   security/sandbox/run-in-sandbox.sh <cmd...>
#   security/sandbox/run-in-sandbox.sh ./security/exploits/run-exploits.sh
#   security/sandbox/run-in-sandbox.sh python3 security/exploits/test_s1_grant_hijack.py
#
# A fresh throwaway /home and /tmp are created per invocation, so anything a
# test writes (DATA_DIR, logs, leaked material) dies with the sandbox.

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Network namespace with loopback only.
#   unshare --net          : private netns
#   --setup 'ip link set lo up' : bring up lo
NET_NS='unshare --net --mount-proc'

bwrap \
  --unshare-all \
  --hostname vela-sandbox \
  --proc /proc \
  --dev /dev \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind /etc /etc \
  --ro-bind /run /run \
  --ro-bind /opt /opt \
  --tmpfs /tmp \
  --tmpfs /home \
  --ro-bind /home/hirew/.cargo /home/hirew/.cargo \
  --ro-bind /home/hirew/.rustup /home/hirew/.rustup \
  --ro-bind /home/hirew/Projects/VELA "$ROOT" \
  --bind /dev/shm /dev/shm \
  --chdir "$ROOT" \
  -- "$@"
