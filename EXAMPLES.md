# protect-folder: examples of everything

Copy-paste recipes for every command and the situations you will actually meet. Paths are illustrations: use your
own. A line starting with `sudo` needs administrator rights; everything else runs as your normal user. Every
`protect-folder ...` line in this file is parsed against the real command-line parser by the test suite, so no
example uses a flag that does not exist. (That checks the syntax, not the effect.)

Complete option tables: `protect-folder help all`, `CLI_REFERENCE.md`. Concepts: `README.md`, `SECURITY.md`.

Contents: 1 Setup · 2 Protect a directory · 3 Choose layers · 4 Look · 5 Verify · 6 Run agents · 7 Network ·
8 Remove / recover · 9 Scripting · 10 Many disks · 11 Day to day · 12 Messages and what to do · 13 Install, uninstall, tests

---

## 1. Setup

```bash
sudo ./install.sh --dry-run          # show the plan, change nothing
sudo ./install.sh                    # install (idempotent: safe to repeat, also to deploy a newer version)
sudo ./install.sh --no-vendor        # layout only, skip node + sandbox-runtime (run will then refuse)
sudo ./install.sh --node /path/to/node --srt-package /path/to/node_modules/@anthropic-ai/sandbox-runtime
sudo protect-folder install --dry-run   # what install.sh runs underneath (from an already installed copy: repair/re-vendor)
protect-folder doctor                # dependencies, trust of installed files, sudo cache, risky groups, agents
protect-folder version
protect-folder adapters              # which layers each agent supports (declared, not verified)
```

`install.sh` finds node and the sandbox-runtime package in **your** nvm/npm folders (root's `PATH` is not trusted).
`doctor` prints `[PASS]`, `[WARN]`, `[INFO]`, `[FAIL]` lines. A `[WARN] group:lxd` means that account can bypass
the root-owned lock outside the sandbox. After any `sudo`, run `sudo -K`.

## 2. Protect a directory

```bash
sudo protect-folder add --dry-run '/mnt/ssd2/clients/Acme credentials'   # always look first
sudo protect-folder add '/mnt/ssd2/clients/Acme credentials'             # asks to confirm
sudo protect-folder add --yes '/mnt/ssd2/clients/Acme credentials'       # no prompt (scripts)
sudo protect-folder add '/media/me/HDD1/Архив/секреты'                   # spaces and Unicode are fine
sudo protect-folder add -- '-weird-name'                                 # '--' for a name starting with '-'
sudo protect-folder add --follow-symlinks ~/shortcut-to-secrets          # protect the symlink's DESTINATION
sudo -K
```

What `add` does: snapshots the directory's owner, mode and ACL, makes **only that directory** `root:root 0700`
(not its contents), registers it and writes the sandbox policy. It refuses `/`, system folders, your home folder,
mount points, symlinks (unless `--follow-symlinks`), non-POSIX filesystems (vfat, exfat, ntfs, nfs, fuse...), and
directories nested inside or around another protected one. Adding the same directory twice answers
`ALREADY_PROTECTED` and keeps the original snapshot.

**Expect this:** while L4 is on, your own editor, file manager and programs lose access to that directory too. Use
`set-layers DIR --no-linux` (below) if you need it readable by your user.

Restart any agent you already had running; old sessions keep their old sandbox and are not covered.

## 3. Choose layers per directory

Layers: **1** agent permissions (`--no-agent-permissions`), **2** pre-execution hook (`--no-hook`), **3** sandbox
(`--no-srt`), **4** Linux permissions (`--no-linux`). All four are on by default.

```bash
# at add time
sudo protect-folder add /data/notes --no-linux              # keep owner/mode; L1-L3 on (e.g. a shared folder)
sudo protect-folder add /data/notes --no-hook --no-agent-permissions   # enforcement layers only
sudo protect-folder add /data/notes --no-srt --no-linux --accept-no-fs-enforcement   # advisory layers only (weak)

# later, on an already protected directory: only the layers you name change
sudo protect-folder set-layers /data/notes --dry-run --no-hook
sudo protect-folder set-layers /data/notes --no-hook        # turn layer 2 off
sudo protect-folder set-layers /data/notes --hook           # and back on
sudo protect-folder set-layers /data/notes --no-linux --srt # several at once
sudo protect-folder set-layers /data/notes --all            # everything on
sudo protect-folder set-layers e55edd53 --no-linux          # by id prefix from 'list'
```

Turning L4 off restores the original owner/mode/ACL (after checking it is the same directory); turning it on
re-applies the lock. At least one layer must stay on (`NO_LAYERS_ENABLED`; use `remove` to stop protecting).
Turning off both SRT and Linux permissions needs `--accept-no-fs-enforcement` (or typed confirmation), because
what remains cannot enforce anything alone. A directory inside a protected parent cannot switch off a layer the
parent enforces (shown with `*` in `list`).

## 4. Look at what is protected

```bash
protect-folder list                 # table: ID, Directory, Agent, Hook, SRT, Linux, Status
protect-folder list --no-color      # plain (also automatic when piped or NO_COLOR is set)
protect-folder status               # overall state + every directory
protect-folder status /data/notes   # one directory: identity, mount, per-layer state, restart-pending
protect-folder status e55edd53      # by id prefix
protect-folder logs                 # admin actions (root-written) and hook decisions (best-effort)
protect-folder logs --since 2h
protect-folder logs --since 2026-11-18T10:00:00 --agent claude
```

Cell meanings: `✓` verified · `?` enabled but **not verified yet** (never counted as a pass) · `✗` verification
failed · `—` disabled · `*` inherited from a protected parent. `Status` is verified layers out of 4.
`status` shows `STALE`/`MOUNT_MISSING` when a protected disk is absent or the directory was replaced.

## 5. Verify (prove it works)

```bash
protect-folder verify                          # L3 + L4 tests against synthetic fixtures; nothing real is read
protect-folder verify /data/notes              # only this directory's checks
protect-folder verify --agent claude           # + L1/L2 offline checks for Claude Code
protect-folder verify --agent opencode --live  # + real agent sessions (uses model calls)
protect-folder verify --agent codex --live
protect-folder verify --agent opencode --live --profile opencode-cloud
PF_OPENCODE_MODEL=opencode/big-pickle protect-folder verify --agent opencode --live   # choose the live model
sudo protect-folder verify --admin             # root-only: snapshots, restore safety, installed code; no agent launched
protect-folder verify --json | jq '.ok'
```

Results per layer: `PASS`, `FAIL` (a leak or broken control: **fix before relying on it**), `UNVERIFIED` (e.g. the model
never attempted the tool call; not a pass), `UNSUPPORTED` (Codex L1/L2), `STALE` (agent updated since the last
pass), `DISABLED`. A live check can need a second try, and a slow or CPU-bound local model makes it much slower:
check `ollama ps` (the model should be fully on the GPU).

## 6. Run agents (the only supported way)

Always start agents through the wrapper. Everything after `--` is the command, passed unchanged (no shell).

```bash
cd ~/code/my-project
protect-folder run -- claude
protect-folder run -- claude -p "summarise this repo"
protect-folder run -- opencode
protect-folder run -- opencode run "list the TODOs"
protect-folder run -- codex
protect-folder run -- codex exec "explain main.py"
protect-folder run -- python3 build.py 'argument with spaces'      # any program: L3 + L4 only
protect-folder run --profile offline -- python3 analyse.py         # no network at all
protect-folder run --profile claude -- claude
protect-folder run --profile opencode-local-ollama -- opencode     # host Ollama only
protect-folder run --profile opencode-cloud -- opencode run -m opencode/big-pickle "hello"
protect-folder run --quiet -- ./tool                               # no capability banner
protect-folder run --json -- claude -p hi                          # banner as JSON on stderr
protect-folder run --require-layers 3 -- claude                    # refuse unless 3 layers verified
protect-folder run -- sh -c 'exit 7'; echo $?                      # prints 7: the agent's own exit status
```

`run` refuses to start (fail closed, agent not launched) if you are root, a protected directory is missing,
replaced or not root-locked, the runtime was tampered with, recovery is pending, or the agent's enabled layers
cannot be established. It never uses sudo and drops dangerous environment variables (`LD_PRELOAD`, `PYTHONPATH`,
`NODE_OPTIONS`, ...). By default every **enabled** enforcement layer must pass; `--require-layers N` adds a stricter
minimum.

What the wrapper refuses on purpose: `opencode --server ...`, `opencode service|attach|serve|web`, an OpenCode that
is not v2.x, `codex --remote`, `codex app-server|remote-control|exec-server|agents`. Reason: those run under some
other server's configuration, outside the sandbox policy.

## 7. Network profiles and policy

```bash
protect-folder help profiles                  # built-in profiles and their hosts
sudo cp examples/policy.json /etc/protect-folder/policy.json   # start from the example, then edit as root
sudoedit /etc/protect-folder/policy.json
protect-folder run --profile claude-with-oauth-refresh -- claude    # a custom profile from policy.json
```

`/etc/protect-folder/policy.json` (root-owned; see `examples/policy.json`):

```json
{
  "schema_version": 1,
  "inspection_mode": "strict",
  "default_profile": null,
  "profiles": { "my-api": { "allowedDomains": ["api.example.com"] } },
  "inspection": { "max_source_bytes": 1048576, "max_seconds": 2.0 },
  "extra_write_paths": ["/home/me/.cache/shared-models"]
}
```

`inspection_mode`: `balanced` (default) lets commands whose targets cannot be resolved statically through to the
sandbox and root lock; `strict` blocks them. `allowedDomains` takes hostnames or `IP:port` literals; `*` is refused.
A hosted agent may need more hosts than the built-in profile (token refresh, API-key login): make a custom profile.

## 8. Stop protecting, recover, forget

```bash
sudo protect-folder remove --dry-run /data/notes     # plan only
sudo protect-folder remove /data/notes               # restores the original owner/mode/ACL after an identity check
sudo protect-folder remove --yes e55edd53            # by id prefix, no prompt
sudo protect-folder remove --forget '/media/me/HDD1/Архив/секреты'   # disk gone for good: drop the entry, touch nothing
sudo protect-folder recover --dry-run                # an add/remove was interrupted (crash, power loss)
sudo protect-folder recover --yes
```

`remove` refuses (`IDENTITY_MISMATCH`) if the directory at that path is no longer the one you protected, and
`MOUNT_MISSING` if its disk is not mounted; it never guesses. While a recovery is pending, `run`, `verify` and the
hook refuse (`RECOVERY_REQUIRED`).

## 9. Scripting with --json

Every command takes `--json` and prints `{schema, command, ok, reason_code, message, data, warnings[, hint]}`.
Exit codes are stable (`protect-folder help exit-codes`).

```bash
protect-folder list --json | jq -r '.data.targets[] | "\(.verified_count)/4  \(.canonical_path)"'
protect-folder list --json | jq -r '.data.targets[] | select(.restart_pending) | .canonical_path'
protect-folder list --json | jq -r '.data.targets[] | select(.layer_details.sandbox_runtime.state != "VERIFIED") | .id'
protect-folder status /data/notes --json | jq '.data'
protect-folder verify --json | jq -e '.ok'            # exit status 0 only if everything passed
sudo protect-folder add --yes --json /data/notes | jq -r '.reason_code'    # OK or ALREADY_PROTECTED ...
```

In shell scripts check the exit status, not the text. `ALREADY_PROTECTED` makes `add` idempotent for automation.

## 10. Many directories on many disks

See `examples/three-volumes.md` for a full walk-through. In short:

```bash
for d in '/home/me/private/notes' '/mnt/fast ssd/clients/Acme credentials' '/media/me/HDD1/Архив/секреты'; do
  sudo protect-folder add --yes "$d"
done
protect-folder list
protect-folder verify
```

Targets are independent absolute paths, identified by device + inode + mount (not by name), on any disk with POSIX
permissions. An unplugged disk makes `run` refuse until it is back (or you `remove --forget` it).

## 11. Day to day

```bash
protect-folder list                                   # morning check: anything ✗ or 'restart pending'?
protect-folder run -- claude                          # work
protect-folder doctor                                 # after upgrades: also shows agents running OUTSIDE the wrapper
protect-folder verify --agent claude --live           # after an agent update (its cached pass becomes STALE)
sudo -K                                               # after every sudo
protect-folder help                                   # built-in documentation
protect-folder help set-layers
protect-folder help layers
protect-folder help all | less
```

## 12. Messages and what to do

| You see | Meaning | Do |
|---|---|---|
| `NOT_ROOT` | an administrator command ran without sudo | repeat with `sudo` |
| `IS_ROOT` | `run` refuses to start as root | run as your normal user |
| `ALREADY_PROTECTED` | already registered; nothing changed | nothing |
| `NOT_PROTECTED` | path/id is not registered | check `protect-folder list` |
| `FORBIDDEN_PATH` / `OVERLAPS_TRUSTED` | too broad or inside protect-folder's own folders | pick a specific directory |
| `NESTED_TARGET` | inside or around an already protected directory | protect the outer one or `remove` first |
| `SYMLINK_TARGET` | the path goes through a symlink | add the real path, or `--follow-symlinks` |
| `UNSUPPORTED_FILESYSTEM` | vfat/exfat/ntfs/nfs/fuse: ownership cannot be enforced | use an ext4/xfs/btrfs location |
| `UNEXPECTED_ACL` | extended ACLs and `setfacl` unavailable | `apt install acl` |
| `IDENTITY_MISMATCH` | the directory at the path was replaced | investigate; `remove --forget` only if you are sure |
| `MOUNT_MISSING` / `STALE` | the disk is not mounted | mount it, or `remove --forget` |
| `RECOVERY_REQUIRED` | an operation was interrupted | `sudo protect-folder recover` |
| `TAMPERED` | a root-owned file was changed | do not run agents; reinstall: `sudo ./install.sh` |
| `PREFLIGHT_FAILED` | `run` refused (message says why) | read the message and `hint`; agent was not started |
| `NO_LAYERS_ENABLED` | you tried to turn every layer off | use `remove` instead |
| `L2 ... UNVERIFIED` | the model never attempted the tool | run the live verify again; not a leak |
| `command not found: help` | the installed copy is older than the docs | `sudo ./install.sh` |

## 13. Install, uninstall, tests

```bash
sudo ./uninstall.sh --restore-all       # restores every protected directory first, then removes the installation
python3 -m pytest -m "not privileged and not live_agent"                              # default suite, temp fixtures
sudo env PF_PRIVILEGED_TESTS=1 python3 -m pytest -m privileged tests/integration      # real chown/chmod/ACL
PF_LIVE_AGENT_TESTS=1 python3 -m pytest -m live_agent                                 # real agents (uses quota)
sudo ./scripts/acceptance.sh /mnt/disk1 /media/me/disk2          # end-to-end on your disks (synthetic fixtures only)
sudo ./scripts/acceptance.sh --agents /mnt/disk1                 # + live agent checks
python3 scripts/gen_cli_reference.py                             # regenerate CLI_REFERENCE.md after changing options
```

The acceptance script creates `pf-acceptance-XXXXXX` under each path you pass, exercises protect/verify/run/restore on
that and removes it; it never protects your existing files. If it is interrupted it removes its fixture.
