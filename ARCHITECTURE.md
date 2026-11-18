# Architecture

```
            sudo (administrative)                         ordinary user
 ┌──────────────────────────────────────┐     ┌────────────────────────────────────────────┐
 │ add / set-layers / remove / recover  │     │ run / list / status / verify / logs / ...  │
 │  admin.py  → transactions.py (flock, │     │  preflight.py → launcher.py → SRT → agent  │
 │  undo journal, RECOVERY_REQUIRED)    │     └────────────────────────────────────────────┘
 └───────────────┬──────────────────────┘                 │ reads (verifies ownership every time)
                 ▼                                         ▼
   /etc/protect-folder/{targets.json, srt-targets.json, policy.json}   (root-owned registry + policy)
   /var/lib/protect-folder/{snapshots.json, transactions/, lock}       (root-only, 0700)
   /usr/local/lib/protect-folder/{protect_folder/, runtime/{node, srt/, MANIFEST sha256}}
   /usr/local/bin/protect-folder                                       (shim: python3 -I -S, root lib path)
```

## Modules (`src/protect_folder/`)

| Module | Responsibility |
|---|---|
| `paths.py`, `mounts.py` | canonicalisation, no-follow open, forbidden/overlapping paths, `/proc/self/mountinfo`, identity (dev/ino/mount/uuid) |
| `registry.py` | schema v2 `Target` (+ per-directory `layers`), migration v1→v2, deterministic serialisation, `policy_revision` |
| `layers.py` | the four layers, effective (inherited) layers for nested targets, display states |
| `snapshots.py`, `hostops.py` | original uid/gid/mode/ACL; chown/chmod via an `O_PATH` fd; `FakeHostOps` for tests |
| `transactions.py`, `admin.py` | exclusive lock, intent journal, compensation, `RECOVERY_REQUIRED`; `add`/`set-layers`/`remove`/`recover` |
| `policy/srt.py` | compile registry → SRT settings, then independently validate the result |
| `policy/profiles.py`, `sandbox_relay.py` | network profiles; the fixed in-sandbox relay |
| `preflight.py` | every fail-closed check before launch; per-layer status (DISABLED/UNVERIFIED/PASS) |
| `launcher.py`, `sessions.py` | argv-only spawn, signals/exit status/TTY preserved; restart-pending tracking |
| `inspect/` | shell lexer, Python AST folding, JS/Ruby/Perl literal folding, ALLOW/DENY/INCOMPLETE engine |
| `hooks/claude_pretooluse.py` | the L2 entry point shared by Claude Code and the OpenCode plugin (fails closed) |
| `adapters/` | `claude`, `opencode` (+ `opencode_plugin/`), `codex`, `generic`; each with `verify` |
| `verify/` | L3/L4/L1/L2 executable tests, per-directory evidence cache, `verify --admin` |
| `status.py`, `render.py`, `cli.py` | views, table rendering (width/Unicode aware), argparse CLI + JSON envelope |
| `install.py`, `runtime.py` | vendoring node + srt (hashes), trust checks |

## Launch path (`protect-folder run -- CMD`)

1. Refuse if root, uninstalled, tampered, pending recovery, runtime hash mismatch, target missing/replaced, or
   L4 not effective on a directory that enables it.
2. The adapter prepares per-launch policy for only the directories that enable each layer (settings file /
   `OPENCODE_CONFIG_CONTENT`), forces agent-specific safety flags, and refuses server/daemon attach modes.
3. The SRT settings are compiled and validated; an empirical probe confirms every protected path is masked in the
   *effective* sandbox; the adapter's `sandbox_check` proves enabled agent layers initialised (OpenCode plugin
   handshake).
4. The agent starts under SRT (wrapped in the relay when the network profile has one). Exit status, signals and
   the TTY pass through unchanged.

## Registry schema v2 (excerpt)

```json
{"schema_version": 2, "revision": 7, "policy_revision": "<sha256>",
 "targets": [{"id": "...", "canonical_path": "...", "st_dev": 2049, "st_ino": 123, "mount_point": "...",
              "filesystem_type": "ext4", "layers": {"agent_permissions": true, "pre_execution_hook": true,
              "sandbox_runtime": true, "linux_permissions": false}, "created_at": "..."}]}
```

`policy_revision` hashes the targets **including layer flags**, so evidence for one configuration never counts for
another. A malformed `layers` object in a v2 file is `TAMPERED`.

## Transactions

`add`/`set-layers`/`remove` are multi-step and not atomic across permissions and several files. Each takes the
lock, writes an intent journal (fsynced), applies steps, and on failure compensates in reverse, restoring metadata
only if the object identity is unchanged. If rollback cannot be proven, `RECOVERY_REQUIRED` is set; `run`, `verify`
and the hook refuse until `sudo protect-folder recover`.
