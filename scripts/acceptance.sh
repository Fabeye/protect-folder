#!/bin/bash
# protect-folder end-to-end acceptance on YOUR disks. Disk-agnostic: pass any directories, each on whatever
# filesystem/mount you want exercised (internal SSD, external HDD, a second partition, ...).
#
#   sudo ./scripts/acceptance.sh [--agents] PATH1 [PATH2 ...]
#
# It NEVER protects PATH itself and never touches existing files: for each PATH it creates a fresh synthetic
# directory  PATH/pf-acceptance-XXXXXX  holding a random marker, exercises protect/verify/run/restore on THAT, and
# removes it at the end. The unprivileged steps run as $SUDO_USER (the real user), the privileged ones as root.
# Needs: protect-folder installed (sudo ./install.sh). Exit 0 only if every step PASSED; SKIPPED steps are listed.
# Writes ./acceptance-report-<timestamp>.txt. --agents additionally runs live agent checks (uses model quota).
set -uo pipefail

PF="${PF_BIN:-/usr/local/bin/protect-folder}"
AGENTS=0; PATHS=()
for a in "$@"; do
  case "$a" in
    --agents) AGENTS=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) PATHS+=("$a") ;;
  esac
done
[ "${#PATHS[@]}" -ge 1 ] || { echo "usage: sudo $0 [--agents] PATH1 [PATH2 ...]" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "acceptance.sh: run it with sudo (administrative steps need root; the agent-facing steps drop to \$SUDO_USER)" >&2; exit 3; }
USER_NAME="${SUDO_USER:-}"
{ [ -n "$USER_NAME" ] && [ "$USER_NAME" != root ]; } || { echo "acceptance.sh: run it via sudo from your normal account (SUDO_USER is not set)" >&2; exit 3; }
[ -x "$PF" ] || { echo "acceptance.sh: $PF not found; run 'sudo ./install.sh' first" >&2; exit 1; }

REPORT="$PWD/acceptance-report-$(date +%Y%m%d-%H%M%S).txt"
PASS=0; FAIL=0; SKIP=0
say() { echo "$*" | tee -a "$REPORT"; }
# If interrupted (Ctrl-C, kill, a failing step), never leave a fixture root-locked and registered.
CURRENT_T=""
cleanup() {
  if [ -n "$CURRENT_T" ] && [ -d "$CURRENT_T" ]; then
    "$PF" remove --yes -- "$CURRENT_T" >/dev/null 2>&1 || "$PF" remove --forget --yes -- "$CURRENT_T" >/dev/null 2>&1 || true
    asuser rm -rf "$CURRENT_T" 2>/dev/null || rm -rf "$CURRENT_T" 2>/dev/null || true
    echo "acceptance: interrupted; removed fixture $CURRENT_T" >&2
  fi
}
trap 'cleanup; exit 130' INT TERM
trap 'cleanup' EXIT
ok()   { PASS=$((PASS+1)); say "PASS    $1"; }
bad()  { FAIL=$((FAIL+1)); say "FAIL    $1  -- $2"; }
skip() { SKIP=$((SKIP+1)); say "SKIPPED $1  -- $2"; }
# The operator's own PATH (sudo resets it to root's secure_path, which does not contain ~/.local/bin or nvm).
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
USER_PATH="$(sudo -u "$USER_NAME" -H bash -lc 'echo $PATH' 2>/dev/null)"
[ -n "$USER_PATH" ] || USER_PATH=/usr/local/bin:/usr/bin:/bin
# A login shell does not run ~/.bashrc, where nvm adds its bin; add the usual per-user install locations
# (newest nvm node first) so agents installed with npm/nvm are found like they are in the operator's terminal.
for d in "$USER_HOME/.local/bin" $(ls -d "$USER_HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -rV) "$USER_HOME/.opencode/bin"; do
  [ -d "$d" ] && case ":$USER_PATH:" in *":$d:"*) ;; *) USER_PATH="$USER_PATH:$d" ;; esac
done
asuser() { sudo -u "$USER_NAME" -H env -i HOME="$USER_HOME" PATH="$USER_PATH" TERM="${TERM:-dumb}" "$@"; }
user_has() { asuser sh -c 'command -v "$1" >/dev/null 2>&1' _ "$1"; }
pf_user() { asuser "$PF" "$@"; }
# expect NAME CONDITION-DESCRIPTION -- command...   (command's exit status 0 => PASS)
expect() { local name="$1"; shift; if out="$("$@" 2>&1)"; then ok "$name"; else bad "$name" "$(echo "$out" | tail -2 | tr '\n' ' ')"; fi; }

say "protect-folder acceptance  $(date -Is)  user=$USER_NAME  version=$($PF version 2>&1 | head -1)"
say "paths: ${PATHS[*]}"
say

# ---- global ---------------------------------------------------------------------------------------------
expect "doctor runs"                  pf_user doctor
expect "adapters lists claude/opencode/codex" bash -c "$(printf '%q ' sudo -u "$USER_NAME" "$PF" adapters) | grep -q codex"
expect "version"                      pf_user version
expect "verify --admin (root-only state)" "$PF" verify --admin
expect "list --json is valid JSON"    bash -c "$(printf '%q ' sudo -u "$USER_NAME" "$PF" list --json) | /usr/bin/python3 -c 'import json,sys; json.load(sys.stdin)'"

# ---- per disk -----------------------------------------------------------------------------------------------
n=0
for base in "${PATHS[@]}"; do
  n=$((n+1)); tag="[disk$n:$base]"
  if [ ! -d "$base" ]; then bad "$tag exists" "not a directory"; continue; fi
  fs="$(findmnt -no FSTYPE -T "$base" 2>/dev/null || echo ?)"
  T="$(asuser mktemp -d "$base/pf-acceptance-XXXXXX" 2>/dev/null)" || { bad "$tag create fixture" "cannot create a directory under $base as $USER_NAME"; continue; }
  MARK="PF-ACCEPT-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  asuser bash -c "printf '%s' '$MARK' > '$T/marker.txt'; mkdir -p '$T/sub'; printf '%s' '$MARK' > '$T/sub/deep.txt'"
  CURRENT_T="$T"
  say "-- $tag filesystem=$fs fixture=$T"
  before="$(stat -c '%u:%g:%a' "$T"; getfacl -p "$T" 2>/dev/null | md5sum)"

  expect "$tag marker readable before protection" asuser cat "$T/marker.txt"
  expect "$tag add --dry-run changes nothing" bash -c "'$PF' add --dry-run --yes -- '$T' >/dev/null && [ \"\$(stat -c '%u:%g:%a' '$T')\" = \"$(stat -c '%u:%g:%a' "$T")\" ]"

  case "$fs" in
    vfat|exfat|ntfs|ntfs3|fuseblk|fuse*|nfs*|cifs|smb*)
      if "$PF" add --yes -- "$T" >/dev/null 2>&1; then bad "$tag unsupported filesystem ($fs) refused" "add succeeded on a filesystem without POSIX permissions"; "$PF" remove --yes -- "$T" >/dev/null 2>&1
      else ok "$tag unsupported filesystem ($fs) refused with a clear error"; fi
      asuser rm -rf "$T"; continue ;;
  esac

  if ! "$PF" add --yes -- "$T" >>"$REPORT" 2>&1; then bad "$tag add --yes" "see report"; asuser rm -rf "$T"; continue; fi
  ok "$tag add --yes"
  expect "$tag add is idempotent (ALREADY_PROTECTED, no snapshot overwrite)" bash -c "out=\$('$PF' add --yes --json -- '$T' 2>&1); echo \"\$out\" | grep -q ALREADY_PROTECTED"
  expect "$tag L4: owner root:root mode 700" bash -c "[ \"\$(stat -c '%u:%g:%a' '$T')\" = '0:0:700' ]"
  expect "$tag L4: unprivileged read is denied outside SRT" bash -c "! sudo -u '$USER_NAME' cat '$T/marker.txt' >/dev/null 2>&1"
  expect "$tag L4: unprivileged listing is denied outside SRT" bash -c "! sudo -u '$USER_NAME' ls '$T' >/dev/null 2>&1"
  expect "$tag list shows the directory" bash -c "sudo -u '$USER_NAME' '$PF' list --no-color | grep -qF -- '$(basename "$T")'"
  expect "$tag status" pf_user status "$T"
  expect "$tag verify (per-layer, independent tests)" pf_user verify "$T"

  # L3: inside SRT the directory is masked, an ordinary project directory still works
  out="$(asuser "$PF" run --quiet -- cat "$T/marker.txt" 2>&1)"; case "$out" in *"$MARK"*) bad "$tag SRT: marker NOT returned inside run" "marker leaked";; *) ok "$tag SRT: marker not returned inside run";; esac
  out="$(asuser "$PF" run --quiet -- python3 -c "import sys; print(open('$T/sub/deep.txt').read())" 2>&1)"; case "$out" in *"$MARK"*) bad "$tag SRT: python open() blocked" "marker leaked";; *) ok "$tag SRT: python open() of a nested file blocked";; esac
  expect "$tag run preserves arguments/exit status" bash -c "sudo -u '$USER_NAME' '$PF' run --quiet -- sh -c 'exit 7'; [ \$? -eq 7 ]"
  expect "$tag run refuses to launch as root" bash -c "! '$PF' run --quiet -- true >/dev/null 2>&1"

  # per-directory layers: SRT-only (Linux permissions off) must still mask inside run, and be restorable
  expect "$tag set-layers --no-linux restores original permissions" bash -c "'$PF' set-layers --no-linux --yes -- '$T' >/dev/null && [ \"\$(stat -c '%u:%g:%a' '$T')\" != '0:0:700' ]"
  out="$(asuser "$PF" run --quiet -- cat "$T/marker.txt" 2>&1)"; case "$out" in *"$MARK"*) bad "$tag layers: SRT alone still masks" "leaked";; *) ok "$tag layers: SRT alone still masks";; esac
  expect "$tag set-layers --all re-applies the lock" bash -c "'$PF' set-layers --all --yes -- '$T' >/dev/null && [ \"\$(stat -c '%u:%g:%a' '$T')\" = '0:0:700' ]"

  if [ "$AGENTS" -eq 1 ]; then
    for ag in claude opencode codex; do user_has "$ag" || { skip "$tag agent:$ag" "not on $USER_NAME's PATH"; continue; }
      say "...     $tag verify --agent $ag --live (real model calls; can take several minutes, 15 min limit)"
      expect "$tag verify --agent $ag --live" timeout 900 sudo -u "$USER_NAME" -H env -i HOME="$USER_HOME" PATH="$USER_PATH" \
             TERM="${TERM:-dumb}" "$PF" verify --agent "$ag" --live "$T"
    done
  else
    skip "$tag live agent checks" "not requested (--agents)"
  fi

  # restore: byte-for-byte the same owner/mode/ACL as before
  expect "$tag remove --yes" "$PF" remove --yes -- "$T"
  after="$(stat -c '%u:%g:%a' "$T"; getfacl -p "$T" 2>/dev/null | md5sum)"
  [ "$before" = "$after" ] && ok "$tag original owner/mode/ACL restored exactly" || bad "$tag original owner/mode/ACL restored exactly" "before=[$before] after=[$after]"
  expect "$tag marker readable again after restore" asuser cat "$T/marker.txt"
  asuser rm -rf "$T"
  CURRENT_T=""
done

say
say "RESULT: $PASS passed, $FAIL failed, $SKIP skipped   (report: $REPORT)"
say "This proves the tested paths and mechanisms on these disks only; it is not a defence against root/sudo by your own account."
[ "$FAIL" -eq 0 ]
