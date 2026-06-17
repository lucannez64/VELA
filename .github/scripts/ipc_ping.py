#!/usr/bin/env python3
"""CI smoke check for the extension<->desktop bridge.

Drives the *real* native-messaging host (passed as argv[1]) with a framed
`{"action":"ping"}` and asserts it reaches the running VELA desktop app and
gets a pong back. Exercises the same code path the browser extension uses:
host -> reads ipc_auth.json -> connects to the desktop IPC socket -> ping/pong.
"""
import json
import struct
import subprocess
import sys


def frame(obj):
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def main():
    if len(sys.argv) < 2:
        print("usage: ipc_ping.py <path-to-native-messaging-host.py>")
        return 2

    host = sys.argv[1]
    proc = subprocess.Popen(
        [sys.executable, host],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = proc.communicate(input=frame({"action": "ping"}), timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        print("native-messaging host timed out")
        return 1

    if err:
        sys.stderr.write(err.decode("utf-8", "replace"))

    if len(out) < 4:
        print(f"no framed response from host; raw={out!r}")
        return 1

    length = struct.unpack("<I", out[:4])[0]
    resp = json.loads(out[4:4 + length].decode("utf-8"))
    print("host ping response:", resp)

    if resp.get("success") and resp.get("connected"):
        print("IPC bridge OK (extension host <-> desktop ping/pong)")
        return 0
    print("IPC bridge FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
