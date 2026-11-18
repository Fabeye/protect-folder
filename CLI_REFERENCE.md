# CLI reference

Administrator commands need `sudo`: `install`, `add`, `set-layers`, `remove`, `recover`. Everything else runs as
your ordinary user. `run` never uses sudo and refuses to run as root. Put `--` before a path that starts with `-`.
Every command accepts `--json` (stable envelope below).

| Command | Purpose |
|---|---|
| `install [--dry-run] [--no-vendor] [--node PATH] [--srt-package DIR]` | create the root-owned layout, default policy, vendored runtime (see `install.sh`) |
| `doctor` | dependencies, versions, trust of installed files, pending recovery, sudo cache, privileged groups/sockets, agents running outside the launcher |
| `add PATH [--dry-run] [--yes] [--follow-symlinks] [--no-agent-permissions] [--no-hook] [--no-srt] [--no-linux] [--accept-no-fs-enforcement]` | protect a directory. Idempotent: a second `add` gives `ALREADY_PROTECTED` and keeps the original snapshot |
| `set-layers PATH [--no-X] [--agent-permissions] [--hook] [--srt] [--linux] [--all] [--dry-run] [--yes] [--accept-no-fs-enforcement]` | change only the named layers. PATH may be the path, the spelling used at add time, or a unique id prefix (6+ hex) |
| `remove PATH [--dry-run] [--yes] [--forget]` | restore owner/mode/ACL **after** an identity check; `--forget` drops a stale registration without touching the filesystem |
| `recover [--dry-run] [--yes]` | roll back an interrupted operation |
| `list [--no-color] [--json]` | table: ID, Directory, Agent, Hook, SRT, Linux, Status |
| `status [PATH] [--json]` | identity, per-layer state, timestamps, restart-pending |
| `verify [PATH] [--agent NAME] [--profile P] [--live]` | per-layer executable tests; `--live` drives real agent sessions |
| `verify --admin` | root-only checks of snapshots, restore safety and installed code; never launches an agent |
| `run [--profile NAME] [--require-layers N] [-q] [--json] -- CMD [ARGS...]` | launch inside the sandbox; argv is passed through unchanged (no shell) |
| `logs [--since 2h] [--agent NAME]` | admin log (root-managed) and hook log (best-effort) |
| `adapters` | declared capabilities per agent (not verification results) |
| `version` | version |

`--require-layers`: by default every **enabled** enforcement layer (SRT, Linux permissions) must pass; an explicit
`N` additionally demands `N` verified layers, capped at the number enabled.

## JSON envelope

```json
{"schema": "protect-folder/1", "command": "add", "ok": true, "reason_code": "OK",
 "message": "...", "data": {}, "warnings": [], "hint": "optional"}
```

## Reason codes and exit codes

`OK 0`, `ERROR 1`, `USAGE 2`, `NOT_ROOT 3`, `IS_ROOT 4`, `ALREADY_PROTECTED 10`, `NOT_PROTECTED 11`,
`PATH_NOT_FOUND 12`, `NOT_A_DIRECTORY 13`, `FORBIDDEN_PATH 14`, `OVERLAPS_TRUSTED 15`, `NESTED_TARGET 16`,
`SYMLINK_TARGET 17`, `UNSUPPORTED_FILESYSTEM 18`, `UNEXPECTED_ACL 19`, `IDENTITY_MISMATCH 20`, `MOUNT_MISSING 21`,
`STALE 22`, `LOCKED 23`, `RECOVERY_REQUIRED 24`, `TAMPERED 25`, `SCHEMA_UNSUPPORTED 26`, `APPLY_FAILED 27`,
`CONFIRMATION_REQUIRED 28`, `NOT_INSTALLED 29`, `PREFLIGHT_FAILED 30`, `SRT_UNAVAILABLE 31`,
`LAYERS_INSUFFICIENT 32`, `NOT_IMPLEMENTED 33`, `VERIFY_FAILED 34`, `ADAPTER_INVALID 35`, `NO_LAYERS_ENABLED 36`.
When `run` launches an agent, its own exit status is returned (`128+N` for a signal).

## Filesystems

Supported: ext2/3/4, xfs, btrfs and other POSIX-permission filesystems. Refused with `UNSUPPORTED_FILESYSTEM`:
vfat, exfat, ntfs/ntfs3, fuse*, nfs, cifs and unknown types (root ownership and mode cannot be enforced there).

## policy.json (root-owned, `/etc/protect-folder/policy.json`)

`inspection_mode` (`balanced`|`strict`), `default_profile`, `profiles` (`allowedDomains`, optional fixed `relays`),
`inspection` (`max_source_bytes`, `max_seconds`), `env_drop`/`env_keep`, `extra_write_paths`. See
`examples/policy.json`. Allow-all entries (`*`) are refused.

<!-- BEGIN GENERATED OPTIONS (scripts/gen_cli_reference.py) -->

## Complete option listing (generated from the parser)

Every command also accepts `-h/--help`. `--json` prints the envelope described above instead of text.

### `protect-folder install`  (needs sudo)

Install/verify the root-owned layout (sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `--dry-run` | show the plan, change nothing | off |
| `--no-vendor` | skip vendoring node + sandbox-runtime (the launcher will then refuse to run) | off |
| `--node PATH` | node executable to vendor (default: next to the srt package) |  |
| `--srt-package DIR` | directory of the @anthropic-ai/sandbox-runtime package to vendor (default: searched in the invoking user's nvm/npm prefixes; a bare 'srt' on PATH is never trusted) |  |
| `--json` | machine-readable output | off |

### `protect-folder doctor`

Check dependencies, versions, integrity.

| Argument / option | Meaning | Default |
|---|---|---|
| `--json` | machine-readable output | off |

### `protect-folder add`  (needs sudo)

Protect a directory (sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `path` | directory to protect (any absolute or relative path; spaces and Unicode are fine) |  |
| `--dry-run` | show the plan, change nothing | off |
| `--yes`, `-y` | do not prompt for confirmation | off |
| `--follow-symlinks` | allow the path to resolve through a symlink (protects the destination) | off |
| `--no-agent-permissions` | disable layer 1: native agent permission rules | off |
| `--no-hook` | disable layer 2: pre-execution command/script inspection | off |
| `--no-srt` | disable layer 3: SRT sandbox masking of this directory | off |
| `--no-linux` | disable layer 4: root:root 0700 (ownership, mode and ACL stay/return as they were) | off |
| `--accept-no-fs-enforcement` | explicitly accept a configuration where BOTH SRT and Linux permissions are off | off |
| `--json` | machine-readable output | off |

### `protect-folder set-layers`  (needs sudo)

Change which protection layers are enabled for a directory (sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `path` | path, spelling used at add time, or target id (prefix) |  |
| `--no-agent-permissions` | disable layer 1: native agent permission rules | off |
| `--no-hook` | disable layer 2: pre-execution command/script inspection | off |
| `--no-srt` | disable layer 3: SRT sandbox masking of this directory | off |
| `--no-linux` | disable layer 4: root:root 0700 (ownership, mode and ACL stay/return as they were) | off |
| `--agent-permissions` | enable layer 1 | off |
| `--hook` | enable layer 2 | off |
| `--srt` | enable layer 3 | off |
| `--linux` | enable layer 4 | off |
| `--accept-no-fs-enforcement` | explicitly accept a configuration where BOTH SRT and Linux permissions are off | off |
| `--all` | enable all four layers | off |
| `--dry-run` | show the plan, change nothing | off |
| `--yes`, `-y` | do not prompt | off |
| `--json` | machine-readable output | off |

### `protect-folder remove`  (needs sudo)

Unprotect a directory and restore its original permissions (sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `path` | path, spelling used at add time, or target id |  |
| `--dry-run` | show the plan, change nothing | off |
| `--yes`, `-y` | do not prompt for confirmation | off |
| `--forget` | drop a stale registration WITHOUT touching the filesystem | off |
| `--json` | machine-readable output | off |

### `protect-folder recover`  (needs sudo)

Roll back an interrupted add/remove (sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `--dry-run` | show the plan, change nothing | off |
| `--yes`, `-y` | do not prompt for confirmation | off |
| `--json` | machine-readable output | off |

### `protect-folder list`

List protected directories with the state of every layer.

| Argument / option | Meaning | Default |
|---|---|---|
| `--no-color` | plain output (also honoured: NO_COLOR, non-tty) | off |
| `--json` | machine-readable output | off |

### `protect-folder status`

Show identity and per-layer state of protected directories.

| Argument / option | Meaning | Default |
|---|---|---|
| `path` (optional) | limit to one directory (path, spelling used at add time, or id prefix) |  |
| `--no-color` | plain output (also honoured: NO_COLOR, non-tty) | off |
| `--json` | machine-readable output | off |

### `protect-folder verify`

Run per-layer enforcement tests.

| Argument / option | Meaning | Default |
|---|---|---|
| `path` (optional) | limit to one protected directory (default: all) |  |
| `--agent AGENT` | also verify this agent's layers: claude, opencode or codex |  |
| `--profile PROFILE` | network profile to test with |  |
| `--live` | also run real agent sessions (consumes model calls) to verify L1/L2 | off |
| `--admin` | root-only checks of root-owned state (snapshots, restore safety, installed code); run as 'sudo protect-folder verify --admin'; never launches an agent | off |
| `--no-color` | plain output | off |
| `--json` | machine-readable output | off |

### `protect-folder logs`

Show administrative and hook logs.

| Argument / option | Meaning | Default |
|---|---|---|
| `--since SINCE` | e.g. 30m, 2h, 7d or an ISO timestamp |  |
| `--agent AGENT` | only hook-log records of this agent |  |
| `--json` | machine-readable output | off |

### `protect-folder run`

Run a command inside the protection sandbox (never uses sudo).

| Argument / option | Meaning | Default |
|---|---|---|
| `--profile PROFILE` | network profile (see 'protect-folder help profiles'; default: the agent's own profile) |  |
| `--require-layers N` | also require N verified layers (default: every enabled enforcement layer must pass) |  |
| `--json` | print the capability report as JSON on stderr | off |
| `--quiet`, `-q` | suppress the capability banner | off |
| `COMMAND` (optional) | after '--': the command and its arguments, passed through verbatim (no shell), e.g. -- claude   or   -- python3 script.py 'a b' |  |

### `protect-folder adapters`

Show agent adapter capabilities.

| Argument / option | Meaning | Default |
|---|---|---|
| `--json` | machine-readable output | off |

### `protect-folder version`

Print version.

| Argument / option | Meaning | Default |
|---|---|---|
| `--json` | machine-readable output | off |

### `protect-folder help`

Complete built-in documentation (topics, commands, 'all').

| Argument / option | Meaning | Default |
|---|---|---|
| `topic` (optional) | a command name, a topic name, or 'all' |  |

## Built-in network profiles (`run --profile`, `verify --profile`)

| Name | Allowed hosts | Notes |
|---|---|---|
| `offline` | none | no network at all |
| `claude` | `api.anthropic.com` | Claude Code API only |
| `opencode-cloud` | `opencode.ai` | OpenCode hosted (opencode/*) models only; other providers need a custom profile |
| `codex` | `chatgpt.com` | Codex with ChatGPT login only; API-key use (api.openai.com) needs a custom profile |
| `opencode-local-ollama` | `127.0.0.1:11434` | OpenCode with the host's Ollama on 127.0.0.1:11434 and nothing else; fixed in-sandbox relay |

Custom profiles go in `/etc/protect-folder/policy.json` (see `examples/policy.json`).

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `NO_COLOR` | any command with a table/report | disable colour (same as --no-color) |
| `PF_OPENCODE_MODEL` | `verify --agent opencode --live` | force the model used for the live OpenCode checks, e.g. `opencode/big-pickle`; default: the local Ollama model if present, else a free hosted one |
| `PF_PRIVILEGED_TESTS=1` | test suite | allow `-m privileged` tests (real chown/chmod/ACL; run under sudo) |
| `PF_LIVE_AGENT_TESTS=1` | test suite | allow `-m live_agent` tests (real agent sessions; consume quota) |
| `PF_BIN` | `scripts/acceptance.sh` | path of the protect-folder executable to test (default `/usr/local/bin/protect-folder`) |
| `SUDO_USER / SUDO_UID` | set by sudo | identify the operator for audit records and for finding node/srt in `install`; never trusted for authorisation (euid 0 is) |

protect-folder itself reads no other environment variables for configuration: locations are fixed, and the launcher removes `LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS` and similar from the agent's environment (see `policy.json` `env_drop`/`env_keep`).

<!-- END GENERATED OPTIONS -->
