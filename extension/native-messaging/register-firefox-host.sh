#!/bin/bash
# VELA Native Messaging Host Registration Script
# Registers for Firefox and all Gecko-based forks: Zen Browser, Waterfox, Floorp, Librewolf, etc.
#
# Registers the compiled Rust host (vela-nm-host). Since issue #149 option B
# there is no capability file and no Python dependency: the browser spawns
# this one self-contained binary over stdio.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST_NAME="com.vela.desktop"

find_host_binary() {
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

echo "VELA Native Messaging Host Registration for Gecko Browsers"
echo "============================================================"
echo "Host binary: $HOST_BIN"
echo ""

detect_nm_dir() {
	local browser=$1
	local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"

	case "$browser" in
	firefox)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
		else
			echo "$HOME/.mozilla/native-messaging-hosts"
		fi
		;;
	zen)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/zen/NativeMessagingHosts"
		else
			echo "$HOME/.zen/native-messaging-hosts"
		fi
		;;
	waterfox)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Waterfox/NativeMessagingHosts"
		else
			echo "$HOME/.waterfox/native-messaging-hosts"
		fi
		;;
	floorp)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Floorp/NativeMessagingHosts"
		else
			echo "$HOME/.floorp/native-messaging-hosts"
		fi
		;;
	librewolf)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/librewolf/NativeMessagingHosts"
		else
			echo "$HOME/.librewolf/native-messaging-hosts"
		fi
		;;
	thunderbird)
		if [ "$(uname)" = "Darwin" ]; then
			echo "$HOME/Library/Application Support/Thunderbird/NativeMessagingHosts"
		else
			echo "$HOME/.thunderbird/native-messaging-hosts"
		fi
		;;
	*)
		echo "$config_home/$browser/native-messaging-hosts"
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
  "allowed_extensions": ["vela@vela.app"]
}
EOF

	echo "  OK   $browser -> $nm_dir"
}

BROWSERS=(firefox zen waterfox floorp librewolf thunderbird)

for browser in "${BROWSERS[@]}"; do
	register_browser "$browser"
done

echo ""
echo "Done. Restart your browser(s) and reload the VELA extension."
