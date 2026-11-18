#!/bin/bash
# protect-folder uninstaller.
#
#   sudo ./uninstall.sh [--restore-all] [--purge] [--dry-run]
#
# Refuses while any directory is still protected: removing the tooling while directories stay locked
# root:root 0700 would strand them. With --restore-all it first runs `protect-folder remove --yes` for every
# registered directory (original owner/mode/ACL restored only after an identity check); if ANY removal fails
# it stops and removes nothing else. --purge also deletes the root-only state (snapshots) and logs.
set -euo pipefail

RESTORE=0; PURGE=0; DRY=0
for a in "$@"; do
  case "$a" in
    --restore-all) RESTORE=1 ;;
    --purge) PURGE=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
[ "$DRY" -eq 1 ] || [ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: must run as root (sudo ./uninstall.sh)" >&2; exit 3; }

BIN=/usr/local/bin/protect-folder; LIB=/usr/local/lib/protect-folder
ETC=/etc/protect-folder; STATE=/var/lib/protect-folder; LOG=/var/log/protect-folder
run() { if [ "$DRY" -eq 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }

targets=""
if [ -x "$BIN" ]; then
  targets="$("$BIN" list --json 2>/dev/null | /usr/bin/python3 -I -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for t in (d.get("data") or {}).get("targets", []):
    print(t.get("canonical_path") or t.get("path"))' || true)"
elif [ -d "$ETC" ] && [ -s "$ETC/targets.json" ]; then
  echo "uninstall.sh: $BIN is missing but a registry exists; reinstall first so directories can be restored." >&2
  exit 1
fi

if [ -n "$targets" ]; then
  if [ "$RESTORE" -eq 0 ]; then
    echo "uninstall.sh: these directories are still protected (root-locked):" >&2
    echo "$targets" | sed 's/^/  /' >&2
    echo "Restore them first (sudo protect-folder remove PATH) or re-run with --restore-all." >&2
    exit 4
  fi
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    echo "restoring: $t"
    run "$BIN" remove --yes -- "$t" || { echo "uninstall.sh: restoring $t failed; nothing else was removed" >&2; exit 5; }
  done <<< "$targets"
fi

run rm -f "$BIN"
run rm -rf "$LIB" "$ETC"
if [ "$PURGE" -eq 1 ]; then run rm -rf "$STATE" "$LOG"; else echo "kept $STATE and $LOG (use --purge to delete)"; fi
echo "uninstalled."
