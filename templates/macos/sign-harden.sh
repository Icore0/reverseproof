#!/usr/bin/env bash
# usage: sign-harden.sh path/to/App.app "Developer ID Application: Name (TEAMID)"
set -euo pipefail
APP="${1:?path to .app}"; IDENTITY="${2:?signing identity}"
HERE="$(cd "$(dirname "$0")" && pwd)"
for exe in "$APP"/Contents/MacOS/*; do strip -x "$exe" 2>/dev/null || true; done   # drop local symbols
codesign --force --deep --options runtime --timestamp \
  --entitlements "$HERE/entitlements.plist" --sign "$IDENTITY" "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"
codesign -dvv "$APP" 2>&1 | grep -E 'flags=.*runtime' && echo "hardened runtime: ON"
echo "Next: notarize (xcrun notarytool submit ... --wait; xcrun stapler staple \"$APP\")"
echo "In-process anti-attach: see examples/toy/toy.c (-DDENY_ATTACH). It is bypassable; see docs/VERDICT.md."
