#!/bin/sh
# VELA server container entrypoint.
#
# The image runs as root only long enough to make sure DATA_DIR is writable by
# the unprivileged `vela` user, then drops privileges via gosu. This keeps the
# runtime non-root while automatically fixing ownership on volumes that were
# created by older root-run images — no operator action, no data loss.
set -e

DATA_DIR="${DATA_DIR:-/var/lib/vela}"

# Only chown the top level; the server creates its files inside. Recursive
# chown on a large volume would delay every restart; new files are created by
# the vela user anyway. If the volume already contains root-owned files from an
# old image, fix them once (bounded by volume size, done only when needed).
if [ -d "$DATA_DIR" ]; then
    if [ "$(stat -c '%u' "$DATA_DIR" 2>/dev/null || echo 0)" != "10001" ]; then
        chown -R 10001:10001 "$DATA_DIR" 2>/dev/null || \
            echo "warning: could not chown $DATA_DIR; continuing anyway" >&2
    fi
else
    mkdir -p "$DATA_DIR" 2>/dev/null || true
    chown 10001:10001 "$DATA_DIR" 2>/dev/null || true
fi

exec gosu vela /usr/local/bin/vela-server "$@"
