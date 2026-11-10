#!/usr/bin/env bash
# Installs Flashlight (mobile app tracking debugger) so mitmweb / mitmdump load it automatically.
set -euo pipefail

# GitHub repository (used when the script is run via curl | bash).
# Always downloads the latest published release, never unreleased work.
REPO="michalnovacek96/flashlight"
RAW_URL="https://github.com/$REPO/releases/latest/download/app_tracking_debugger.py"

DIR="$HOME/.mitmproxy"
DEST="$DIR/addons/app_tracking_debugger.py"
CONFIG="$DIR/config.yaml"

mkdir -p "$DIR/addons"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/app_tracking_debugger.py"
if [ -f "$SRC" ]; then
  cp "$SRC" "$DEST"
  echo "Copied addon to $DEST"
else
  curl -fsSL "$RAW_URL" -o "$DEST"
  echo "Downloaded addon to $DEST"
fi

if [ -f "$CONFIG" ] && grep -q "app_tracking_debugger.py" "$CONFIG"; then
  echo "Already registered in $CONFIG"
elif [ -f "$CONFIG" ] && grep -qx "scripts:[[:space:]]*" "$CONFIG"; then
  # existing block list -> add our script as its first item
  awk -v dest="$DEST" '{ print } /^scripts:[[:space:]]*$/ { print "  - " dest }' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
  echo "Registered in $CONFIG"
elif [ -f "$CONFIG" ] && grep -q "^scripts:" "$CONFIG"; then
  echo
  echo "Your $CONFIG already has a 'scripts:' entry. Add this script to it manually:"
  echo "  $DEST"
else
  printf '\nscripts:\n  - %s\n' "$DEST" >> "$CONFIG"
  echo "Registered in $CONFIG"
fi

# open only the tracking hits UI on start, not mitmweb's own page
if ! grep -q "^web_open_browser:" "$CONFIG"; then
  printf 'web_open_browser: false\n' >> "$CONFIG"
fi

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$DEST")
echo
echo "Done. Installed Flashlight ${VERSION:-unknown}."
echo "Start mitmweb - Flashlight opens at http://127.0.0.1:8082"
