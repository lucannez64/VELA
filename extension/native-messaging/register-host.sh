#!/bin/bash
# VELA Native Messaging Host Registration Script
# Registers for all Chromium-based browsers on Linux/macOS: Chrome, Edge, Brave, Thorium, Helium, etc.
#
# Registers the compiled Rust host (vela-nm-host). Since issue #149 option B
# there is no capability file and no Python dependency: the browser spawns
# this one self-contained binary over stdio.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST_NAME="com.vela.desktop"

find_host_binary() {
	# Explicit override wins, then the usual install locations, then a local
	# build from the desktop workspace.
	if [ -n "${VELA_NM_HOST_PATH:-}" ]; then
		echo "$VELA_NM_HOST_PATH"
		return 0
	fi
	local candidate
	for candidate in \
		"/usr/bin/vela-native-messaging-host" \
		"/usr/local/bin/vela-native-messaging-host" \
		"$HOME/.local/bin/vela-native-messaging-host" \
		"$SCRIPT_DIR/../../target/release/vela-native-messaging-host" \
		"$SCRIPT_DIR/../../target/debug/vela-native-messaging-host" \
		"$SCRIPT_DIR/../../desktopVELA/target/release/vela-native-messaging-host" \
		"$SCRIPT_DIR/../../desktopVELA/target/debug/vela-native-messaging-host"; do
		if [ -x "$candidate" ]; then
			echo "$candidate"
			return 0
		fi
	done
	return 1
}

HOST_BIN="$(find_host_binary)" || {
	echo "ERROR: vela-native-messaging-host not found."
	echo ""
	echo "Build it first:"
	echo "  cd desktopVELA && cargo build --release -p vela-nm-host"
	echo ""
	echo "Or point VELA_NM_HOST_PATH at an existing binary."
	exit 1
}

if [ -z "${VELA_CHROME_EXTENSION_ID:-}" ]; then
	echo "ERROR: set VELA_CHROME_EXTENSION_ID to the audited Chromium extension ID before registration"
	exit 1
fi

# A Chromium extension ID is exactly 32 characters from a-p — it is a base16
# encoding of a hash digit-shifted into that alphabet, so nothing else is even
# representable. Checking it here costs one line and saves a bad afternoon:
# without it, a Firefox add-on UUID pasted in by mistake is written to every
# Chromium browser's manifest, and the only symptom is the browser saying
# "Access to the specified native messaging host is forbidden" at runtime, in a
# place that gives no hint the registration is what's wrong. That happened on a
# real machine — four browsers registered with a UUID that can never match.
if ! printf '%s' "$VELA_CHROME_EXTENSION_ID" | grep -Eq '^[a-p]{32}$'; then
	echo "ERROR: '$VELA_CHROME_EXTENSION_ID' is not a Chromium extension ID."
	echo ""
	echo "  A Chromium extension ID is 32 characters, a-p only, e.g."
	echo "    jphblihlihkilmjccigaikljencgofkl"
	echo "  Find it at chrome://extensions (or brave://extensions) with"
	echo "  Developer mode turned on."
	echo ""
	case "$VELA_CHROME_EXTENSION_ID" in
	*-*-*-*-*)
		echo "  That looks like a Firefox add-on UUID. Firefox does not use this"
		echo "  script — run ./register-firefox-host.sh instead, which registers"
		echo "  the add-on by its gecko id (vela@vela.app) and needs no UUID."
		;;
	esac
	exit 1
fi

echo "VELA Native Messaging Host Registration for Chromium Browsers"
echo "=============================================================="
echo "Host binary: $HOST_BIN"
echo ""

detect_nm_dir() {
	local browser=$1
	local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"

	case "$browser" in
	chrome)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
		else
			echo "$config_home/google-chrome/NativeMessagingHosts"
		fi
		;;
	chromium)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
		else
			echo "$config_home/chromium/NativeMessagingHosts"
		fi
		;;
	edge)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
		else
			echo "$config_home/microsoft-edge/NativeMessagingHosts"
		fi
		;;
	brave)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
		else
			echo "$config_home/BraveSoftware/Brave-Browser/NativeMessagingHosts"
		fi
		;;
	thorium)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Thorium/NativeMessagingHosts"
		else
			echo "$config_home/thorium/NativeMessagingHosts"
		fi
		;;
	helium)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Helium/NativeMessagingHosts"
		else
			echo "$config_home/helium/NativeMessagingHosts"
		fi
		;;
	vivaldi)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts"
		else
			echo "$config_home/vivaldi/NativeMessagingHosts"
		fi
		;;
	opera)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts"
		else
			echo "$config_home/opera/NativeMessagingHosts"
		fi
		;;
	arc)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Arc/NativeMessagingHosts"
		else
			echo "$config_home/Arc/NativeMessagingHosts"
		fi
		;;
	ungoogled-chromium)
		echo "$config_home/ungoogled-chromium/NativeMessagingHosts"
		;;
	*)
		echo "$config_home/$browser/NativeMessagingHosts"
		;;
	esac
}

register_browser() {
	local browser=$1
	local nm_dir
	nm_dir=$(detect_nm_dir "$browser")

	mkdir -p "$nm_dir"

	rm -f "$nm_dir/vela-desktop.json"

	cat >"$nm_dir/$HOST_NAME.json" <<EOF
{
  "name": "$HOST_NAME",
  "description": "VELA Desktop Password Manager Native Messaging Host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$VELA_CHROME_EXTENSION_ID/"]
}
EOF

	echo "  OK   $browser -> $nm_dir"
}

BROWSERS=(chrome chromium edge brave thorium helium vivaldi opera arc ungoogled-chromium)

for browser in "${BROWSERS[@]}"; do
	register_browser "$browser"
done

echo ""
echo "Done. Restart your browser(s) and reload the VELA extension."
