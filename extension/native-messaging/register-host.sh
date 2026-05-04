#!/bin/bash
# VELA Native Messaging Host Registration Script
# Registers for all Chromium-based browsers on Linux/macOS: Chrome, Edge, Brave, Thorium, Helium, etc.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST_SCRIPT="$SCRIPT_DIR/vela-native-messaging-host.py"
HOST_WRAPPER="$SCRIPT_DIR/vela-native-messaging-host"
HOST_NAME="com.vela.desktop"

if [ ! -f "$HOST_SCRIPT" ]; then
	echo "ERROR: $HOST_SCRIPT not found"
	exit 1
fi

if [ -z "${VELA_CHROME_EXTENSION_ID:-}" ]; then
	echo "ERROR: set VELA_CHROME_EXTENSION_ID to the audited Chromium extension ID before registration"
	exit 1
fi

chmod +x "$HOST_SCRIPT"

echo "VELA Native Messaging Host Registration for Chromium Browsers"
echo "=============================================================="
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
