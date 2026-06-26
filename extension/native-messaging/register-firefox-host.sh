#!/bin/bash
# VELA Native Messaging Host Registration Script
# Registers for Firefox and all Gecko-based forks: Zen Browser, Waterfox, Floorp, Librewolf, etc.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST_SCRIPT="$SCRIPT_DIR/vela-native-messaging-host.py"
HOST_WRAPPER="$SCRIPT_DIR/vela-native-messaging-host"
HOST_NAME="com.vela.desktop"

if [ ! -f "$HOST_SCRIPT" ]; then
	echo "ERROR: $HOST_SCRIPT not found"
	exit 1
fi

chmod +x "$HOST_SCRIPT"

echo "VELA Native Messaging Host Registration for Gecko Browsers"
echo "============================================================"
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

	local python_path
	python_path=$(which python3 2>/dev/null || which python 2>/dev/null || echo "")

	if [ -z "$python_path" ]; then
		echo "  SKIP $browser (python not found)"
		return
	fi

	cat >"$HOST_WRAPPER" <<EOF
#!/bin/sh
exec "$python_path" "$HOST_SCRIPT"
EOF
	chmod +x "$HOST_WRAPPER"

	rm -f "$nm_dir/vela-desktop.json"

	cat >"$nm_dir/$HOST_NAME.json" <<EOF
{
  "name": "$HOST_NAME",
  "description": "VELA Desktop Password Manager Native Messaging Host",
  "path": "$HOST_WRAPPER",
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
