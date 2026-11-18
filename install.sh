#!/bin/bash
# protect-folder installer. Auditable, idempotent, offline: it downloads NOTHING.
#
#   sudo ./install.sh [--dry-run] [--no-vendor] [--node PATH] [--srt-package DIR]
#
# What it does (nothing else):
#   1. refuses to run unless you are root (it never invokes sudo itself) and Python >= 3.10 exists;
#   2. checks the system tools SRT/ACL handling needs (bubblewrap, socat, ripgrep, getfacl/setfacl);
#   3. copies the Python sources into a ROOT-OWNED staging directory and runs the installer FROM THERE, so a
#      user-writable checkout can never change what root executes mid-install (the staged tree hash is printed);
#   4. the installer then creates /etc/protect-folder (0755), /var/lib/protect-folder (0700),
#      /var/log/protect-folder (0755), copies the code to /usr/local/lib/protect-folder, writes the
#      /usr/local/bin/protect-folder launcher, and vendors a root-owned copy of node + @anthropic-ai/sandbox-runtime
#      (found on this machine, version-checked, hashed) into /usr/local/lib/protect-folder/runtime.
set -euo pipefail

DRY=0; VENDOR=1; NODE_ARG=(); SRT_ARG=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --no-vendor) VENDOR=0 ;;
    --node) [ "$#" -ge 2 ] || { echo "--node needs a path" >&2; exit 2; }; NODE_ARG=(--node "$2"); shift ;;
    --srt-package) [ "$#" -ge 2 ] || { echo "--srt-package needs a directory" >&2; exit 2; }; SRT_ARG=(--srt-package "$2"); shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/src/protect_folder"
[ -d "$SRC" ] || { echo "install.sh: $SRC not found; run it from the project directory" >&2; exit 1; }

if [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "install.sh: must run as root, e.g.:  sudo ./install.sh   (try --dry-run first)" >&2
  exit 3
fi

PY=/usr/bin/python3
[ -x "$PY" ] || { echo "install.sh: $PY missing (apt install python3)" >&2; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
  || { echo "install.sh: Python >= 3.10 required" >&2; exit 1; }

missing=()
for t in bwrap socat rg getfacl setfacl; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "install.sh: missing: ${missing[*]}" >&2
  echo "  apt install bubblewrap socat ripgrep acl      # system tools" >&2
  echo "  npm install -g @anthropic-ai/sandbox-runtime@0.0.83   # node + srt are vendored from here (as your user)" >&2
  [ "$DRY" -eq 1 ] || exit 1
fi

STAGE="$(mktemp -d /tmp/protect-folder-stage.XXXXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
chmod 0700 "$STAGE"
mkdir "$STAGE/src"
cp -r "$SRC" "$STAGE/src/protect_folder"
find "$STAGE" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} + 2>/dev/null || true
if [ "$(id -u)" -eq 0 ]; then chown -R root:root "$STAGE"; fi
chmod -R go-w "$STAGE"
echo "install.sh: staged source tree sha256: $(cd "$STAGE/src" && find protect_folder -type f | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"

ARGS=(install)
[ "$DRY" -eq 1 ] && ARGS+=(--dry-run)
[ "$VENDOR" -eq 0 ] && ARGS+=(--no-vendor)
ARGS+=("${NODE_ARG[@]}" "${SRT_ARG[@]}")
# -I: no PYTHON* env / user site; sys.path is set explicitly to the staged, root-owned tree.
"$PY" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from protect_folder.cli import main; sys.exit(main(sys.argv[2:]))' \
  "$STAGE/src" "${ARGS[@]}"

if [ "$DRY" -eq 0 ]; then
  cat <<'MSG'

Installed. Next:
  protect-folder doctor
  sudo protect-folder add --dry-run /path/to/protect     # then without --dry-run
  protect-folder verify
  protect-folder run -- claude          # or opencode / codex
Run 'sudo -K' after administrative commands. protect-folder is NOT a defence against root/sudo by your own account.
MSG
fi
