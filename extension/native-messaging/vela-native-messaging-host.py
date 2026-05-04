#!/usr/bin/env python3
"""
VELA Native Messaging Host.

The browser extension talks to this process over the browser native messaging
stdio protocol. This host then relays requests to VELA Desktop over an
OS-local pipe/socket using a per-session capability written by the desktop app.
"""

import json
import os
import platform
import socket
import struct
import sys
from pathlib import Path

MAX_MESSAGE_BYTES = 1024 * 1024


def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    if len(raw_length) != 4:
        return None

    length = struct.unpack("<I", raw_length)[0]
    if length == 0 or length > MAX_MESSAGE_BYTES:
        return None

    payload = sys.stdin.buffer.read(length)
    if len(payload) != length:
        return None

    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as error:
        print(f"Invalid native message JSON: {error}", file=sys.stderr)
        return None


def write_message(message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def candidate_auth_paths():
    system = platform.system().lower()
    home = Path.home()

    if system == "windows":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            yield Path(appdata) / "vela" / "VELA" / "data" / "vela" / "ipc_auth.json"
            yield Path(appdata) / "com" / "vela" / "VELA" / "data" / "vela" / "ipc_auth.json"
        if localappdata:
            yield Path(localappdata) / "vela" / "VELA" / "data" / "vela" / "ipc_auth.json"
            yield Path(localappdata) / "com" / "vela" / "VELA" / "data" / "vela" / "ipc_auth.json"
    elif system == "darwin":
        yield home / "Library" / "Application Support" / "com.vela.VELA" / "vela" / "ipc_auth.json"
    else:
        xdg_data_home = os.environ.get("XDG_DATA_HOME")
        if xdg_data_home:
            yield Path(xdg_data_home) / "com.vela.VELA" / "vela" / "ipc_auth.json"
        yield home / ".local" / "share" / "com.vela.VELA" / "vela" / "ipc_auth.json"
        yield home / ".local" / "share" / "vela" / "vela" / "ipc_auth.json"


def load_ipc_auth():
    for path in candidate_auth_paths():
        try:
            with path.open("r", encoding="utf-8") as handle:
                auth = json.load(handle)
            if auth.get("capability") and auth.get("endpoint") and auth.get("protocol"):
                return auth
        except FileNotFoundError:
            continue
        except Exception as error:
            print(f"Failed to read IPC auth file {path}: {error}", file=sys.stderr)
    return None


def framed_exchange(stream, message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(payload)))
    stream.write(payload)
    stream.flush()

    raw_length = stream.read(4)
    if len(raw_length) != 4:
        return None
    length = struct.unpack("<I", raw_length)[0]
    if length == 0 or length > MAX_MESSAGE_BYTES:
        return None
    response = stream.read(length)
    if len(response) != length:
        return None
    return json.loads(response.decode("utf-8"))


def send_to_desktop(message):
    auth = load_ipc_auth()
    if not auth:
        return {"success": False, "error": "VELA Desktop IPC is not available"}

    message = dict(message)
    message["capability"] = auth["capability"]

    protocol = auth["protocol"]
    endpoint = auth["endpoint"]

    try:
        if protocol == "windows_named_pipe":
            with open(endpoint, "r+b", buffering=0) as pipe:
                return framed_exchange(pipe, message)

        if protocol == "unix_socket":
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(endpoint)
                with sock.makefile("rwb", buffering=0) as stream:
                    return framed_exchange(stream, message)

        return {"success": False, "error": "Unsupported VELA Desktop IPC protocol"}
    except Exception as error:
        print(f"Desktop IPC error: {error}", file=sys.stderr)
        return {"success": False, "error": "Could not reach VELA Desktop"}


def handle_message(message):
    action = message.get("action", "")

    handlers = {
        "ping": handle_ping,
        "openVault": handle_open_vault,
        "openSettings": handle_open_vault,
        "getLogins": handle_get_logins,
        "getAvailableLogins": handle_get_logins,
        "saveCredentials": handle_save_credentials,
        "getMasterKey": handle_not_implemented,
        "unlockVault": handle_not_implemented,
        "lockVault": handle_not_implemented,
        "getStatus": handle_not_implemented,
    }

    handler = handlers.get(action)
    if not handler:
        return {"success": False, "error": f"Unknown action: {action}"}
    return handler(message)


def handle_ping(_message):
    response = send_to_desktop({"msg_type": "ping", "payload": {}})
    if response and response.get("msg_type") in ("pong", "Pong"):
        return {"success": True, "connected": True}
    return {"success": False, "connected": False}


def handle_open_vault(_message):
    response = send_to_desktop({"msg_type": "open_vault", "payload": {}})
    if response and response.get("msg_type") in ("pong", "Pong"):
        return {"success": True}
    return {"success": False, "error": "Could not open VELA Desktop"}


def handle_get_logins(message):
    url = message.get("url", "")
    user_initiated = bool(
        message.get("userInitiated")
        or message.get("user_initiated")
        or message.get("action") == "getLogins"
    )
    response = send_to_desktop(
        {
            "msg_type": "autofill_request",
            "payload": {"domain": url, "user_initiated": user_initiated},
        }
    )

    if not response or response.get("msg_type") not in ("AutofillResponse", "autofill_response"):
        return {"success": False, "logins": []}

    payload = response.get("payload", {})
    if payload.get("requires_biometric"):
        return {"success": False, "requires_biometric": True, "logins": []}

    logins = []
    for item in payload.get("items", []):
        if item.get("item_type") == "login":
            login = {
                "id": item.get("id"),
                "name": item.get("name"),
                "username": item.get("username"),
                "url": item.get("url"),
            }
            if user_initiated:
                login["password"] = item.get("password")
                login["totp"] = item.get("totp")
            logins.append(login)
    return {"success": True, "logins": logins}


def handle_save_credentials(_message):
    return {"success": False, "error": "Not implemented"}


def handle_not_implemented(_message):
    return {"success": False, "error": "Not implemented"}


def main():
    while True:
        message = read_message()
        if message is None:
            break
        write_message(handle_message(message))


if __name__ == "__main__":
    main()
