#!/usr/bin/env python3
"""
VELA Native Messaging Host

Bridge between VELA browser extension and desktop app via TCP socket.
Desktop app listens on localhost:14597.
"""

import json
import sys
import socket

HOST = "localhost"
PORT = 14597
BUFFER_SIZE = 65536


def read_message():
    """Read a message from stdin (Chrome/Firefox native messaging protocol)."""
    try:
        content_length_line = sys.stdin.readline()
        if not content_length_line:
            return None

        content_length = int(content_length_line.strip())
        if content_length <= 0:
            return None

        message_json = sys.stdin.read(content_length)
        if message_json:
            return json.loads(message_json)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"Error reading message: {e}", file=sys.stderr)
        return None

    return None


def write_message(message):
    """Write a message to stdout (Chrome/Firefox native messaging protocol)."""
    try:
        message_json = json.dumps(message)
        response = f"Content-Length: {len(message_json)}\n\n{message_json}"
        sys.stdout.write(response)
        sys.stdout.flush()
        return True
    except Exception as e:
        print(f"Error writing message: {e}", file=sys.stderr)
        return False


def send_to_socket(message):
    """Send message to desktop app via TCP and get response."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))

        message_json = json.dumps(message) + "\n"
        sock.sendall(message_json.encode("utf-8"))

        response = b""
        while True:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            response += chunk
            if b"\n" in response:
                break

        if response:
            return json.loads(response.decode("utf-8").strip())
        return None
    except socket.timeout:
        return None
    except Exception as e:
        print(f"Socket error: {e}", file=sys.stderr)
        return None
    finally:
        if sock:
            sock.close()


def handle_message(message):
    """Route incoming messages to appropriate handlers."""
    action = message.get("action", "")

    handlers = {
        "ping": handle_ping,
        "getLogins": handle_get_logins,
        "getAvailableLogins": handle_get_available_logins,
        "saveCredentials": handle_save_credentials,
        "getMasterKey": handle_get_master_key,
        "unlockVault": handle_unlock_vault,
        "lockVault": handle_lock_vault,
        "getStatus": handle_get_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(message)

    return {"success": False, "error": f"Unknown action: {action}"}


def handle_ping(message):
    """Handle ping requests."""
    response = send_to_socket({"msg_type": "Ping", "payload": {}})

    if response and response.get("msg_type") == "Pong":
        return {"success": True, "connected": True}
    return {"success": False, "error": "No response from desktop"}


def handle_get_logins(message):
    """Get logins for a specific URL."""
    url = message.get("url", "")
    response = send_to_socket(
        {"msg_type": "AutofillRequest", "payload": {"domain": url}}
    )

    if response and response.get("msg_type") == "AutofillResponse":
        items = response.get("payload", {}).get("items", [])
        logins = []
        for item in items:
            if item.get("item_type") == "login":
                logins.append(
                    {
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "username": item.get("username"),
                        "password": item.get("password"),
                        "url": item.get("url"),
                    }
                )
        return {"success": True, "logins": logins}
    return {"success": False, "logins": []}


def handle_get_available_logins(message):
    """Get all available logins for the current page domain."""
    return handle_get_logins(message)


def handle_save_credentials(message):
    """Save new credentials."""
    return {"success": False, "error": "Not implemented"}


def handle_get_master_key(message):
    """Request master key for authentication."""
    return {"success": False, "error": "Not implemented"}


def handle_unlock_vault(message):
    """Unlock the vault with biometric or PIN."""
    return {"success": False, "error": "Not implemented"}


def handle_lock_vault(message):
    """Lock the vault."""
    return {"success": False, "error": "Not implemented"}


def handle_get_status(message):
    """Get the current status of the desktop app."""
    return {"success": False, "error": "Not implemented"}


def main():
    """Main entry point for the native messaging host."""
    while True:
        message = read_message()
        if message is None:
            break

        response = handle_message(message)
        write_message(response)


if __name__ == "__main__":
    main()
