#!/usr/bin/env bash
# Run ON THE VPS after copying a new APK there. Publishes it as the version every phone will be
# offered on its next update check (api/mobile/v1/version/ + api/mobile/v1/download/).
#
# Usage: publish_release.sh <path-to-apk> <version-code> <version-name> ["release notes"]
# Example: publish_release.sh /home/deploy/LEA-ankety-2.27-release.apk 36 2.27 "Автообновление"
set -euo pipefail

APK_PATH="${1:?usage: publish_release.sh <apk> <version-code> <version-name> [notes]}"
VERSION_CODE="${2:?usage: publish_release.sh <apk> <version-code> <version-name> [notes]}"
VERSION_NAME="${3:?usage: publish_release.sh <apk> <version-code> <version-name> [notes]}"
NOTES="${4:-}"

RELEASES_DIR="${LEA_MOBILE_RELEASES_DIR:-/opt/lea-mobile/releases}"
mkdir -p "$RELEASES_DIR"

if [ ! -f "$APK_PATH" ]; then
  echo "APK not found: $APK_PATH" >&2
  exit 1
fi

cp "$APK_PATH" "$RELEASES_DIR/latest.apk"
python3 - "$RELEASES_DIR/version.json" "$VERSION_CODE" "$VERSION_NAME" "$NOTES" <<'PYEOF'
import json, sys
path, code, name, notes = sys.argv[1:5]
with open(path, "w", encoding="utf-8") as f:
    json.dump({"version_code": int(code), "version_name": name, "notes": notes}, f, ensure_ascii=False)
PYEOF

echo "Published version $VERSION_NAME (code $VERSION_CODE) — phones will see it on their next check."
