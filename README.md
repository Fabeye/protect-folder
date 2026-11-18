# protect-folder

Keep **local AI coding agents** (Claude Code, OpenCode, Codex, or any command) away from directories you
choose - on any disk, in any number - using four independent layers. Linux only, Python >= 3.10, standard
library only.

> ## ⚠ Read this first: it is not a boundary against *you* or `sudo`
>
> Everything here protects against an agent that runs **as your user inside the wrapper**. It is **not** a
> defence against root, a kernel exploit, a privileged helper, or a process that runs as your Unix user and can
> use your **sudo** credentials (cached `sudo`, passwordless sudo, membership of `docker`/`lxd`/`disk`, ...).
> The same user who types a password for `sudo` can undo any protection. Run `sudo -K` after administrative
> commands, never launch an agent with `sudo`, and run `protect-folder doctor` to see which same-user escalation
> paths exist on this machine. Agents started **outside** `protect-folder run` (an IDE extension, a background
> service) are not confined.

## The four layers

| Layer | What | Strength |
|---|---|---|
| **L1** agent permissions | the agent's own deny rules (`permissions.deny` for Claude Code, `permissions` for OpenCode) | advisory: the agent enforces it on itself |
| **L2** pre-execution inspection | a hook/plugin reads the command **and the scripts it would run** before execution and blocks references to protected paths | best-effort: static analysis cannot be complete; fails closed on error |
| **L3** sandbox | Anthropic Sandbox Runtime (bubblewrap): protected paths are masked, trusted files read-only, network allow-list | enforced by the kernel for everything inside the wrapper |
| **L4** Linux permissions | the directory becomes `root:root 0700` (original owner/mode/ACL snapshotted for exact restore) | enforced by the kernel for every process, wrapper or not |

L3 and L4 are the guarantees; L1 and L2 are defence in depth and early, readable refusals. Layers are **never
reported as working unless they were verified**: `list`/`status` distinguish `✓ verified`, `? configured but not
verified`, `— disabled`, `✗ failed`.

### Per-directory configuration

`add` enables all four by default. Turn individual layers off per directory:

```bash
sudo protect-folder add /data/notes --no-linux          # keep owner/mode (e.g. a shared dir); L1-L3 stay on
sudo protect-folder set-layers /data/notes --no-hook    # change later; only the layers you name change
sudo protect-folder set-layers /data/notes --all
```

Nothing is enabled or disabled implicitly; disabling both SRT and Linux permissions needs an explicit
confirmation (`--accept-no-fs-enforcement`). Nested directories are allowed: a child can never switch off a layer
its protected parent enforces. Disabling L4 restores the original owner/mode/ACL (after an identity check).

## Quick start

```bash
sudo apt install bubblewrap socat ripgrep acl            # system tools
npm install -g @anthropic-ai/sandbox-runtime@0.0.83      # as your user; node + srt get vendored root-owned
sudo ./install.sh --dry-run && sudo ./install.sh         # offline, auditable (see the script header)
# node + srt are found in YOUR nvm/npm prefixes (root's PATH is not trusted). If they live elsewhere:
#   sudo ./install.sh --node /path/to/node --srt-package /path/to/node_modules/@anthropic-ai/sandbox-runtime
protect-folder doctor

sudo protect-folder add '/path/to/directory'             # [--dry-run] [--yes]; spaces/Unicode are fine
protect-folder list
protect-folder verify                                    # independent per-layer tests, synthetic markers only
protect-folder run -- claude                             # also: opencode, codex, python3 script.py ...
```

`list` right after `add` (real output; `?` = configured but **not verified yet**, never counted as a pass):

```
ID        Directory                                Agent   Hook   SRT    Linux   Status
58b2943c  /mnt/fast ssd/Acme credentials           ?       ?      ?      ✓       1/4
e393e394  ~/private/notes                          ?       ?      ?      —       0/4

✓ enabled and verified   ? enabled, NOT verified yet   ✗ enabled, verification FAILED   — disabled
* protection inherited from a protected parent directory   Status = verified layers / 4
```

Here `Linux ✓` is a live check of the directory's owner/mode; after `protect-folder verify` (and `verify --agent
claude --live` for the agent layers) the `?` cells become `✓` or `✗`. `list --json`, `--no-color`, narrow terminals,
spaces and Unicode are supported.

## Agents

| Agent | L1 | L2 | L3 | L4 | Notes |
|---|---|---|---|---|---|
| Claude Code | ✓ `permissions.deny` via `--settings` | ✓ `PreToolUse` hook (`onFailure: block`) | ✓ | ✓ | verified live |
| OpenCode (v2) | ✓ `permissions` via `OPENCODE_CONFIG_CONTENT` | ✓ server plugin; load proven by a handshake before every launch | ✓ | ✓ | always `--standalone`; refuses `--server`/`service`; the project's own `opencode.jsonc` is ignored |
| Codex | **UNSUPPORTED** | **UNSUPPORTED** | ✓ | ✓ | runs `--sandbox danger-full-access` *inside* SRT; see SECURITY.md for why |
| anything else | n/a | n/a | ✓ | ✓ | |

`protect-folder adapters` prints the declared capability matrix; `verify --agent NAME [--live]` tests it. A
`PASS` is cached per policy revision **and agent version**; an agent update turns it into `STALE`.

## Network profiles

`run` is closed by default. Built-in profiles were derived by running the real agent in the sandbox and
watching what the proxy blocked: `offline`, `claude` (`api.anthropic.com`), `opencode-cloud` (`opencode.ai`),
`opencode-local-ollama` (host Ollama on `127.0.0.1:11434` via a fixed in-sandbox relay), `codex` (`chatgpt.com`).
Add your own in the root-owned `/etc/protect-folder/policy.json` (`examples/policy.json`). Telemetry and MCP hosts
the agents also try are intentionally blocked.

## Behaviour worth knowing

* **Restart**: a session started before `add`/`set-layers` keeps its old policy; `list`/`status` mark it
  *restart pending*.
* **Missing disk**: `run` refuses if a protected directory is absent, replaced, or no longer root-locked.
* **Rename**: L4 protects the directory, not its name: if its *parent* is writable by the agent, the entry can be
  renamed (the data stays protected, but it is no longer at that path). Protect parents you do not trust the
  agent with, or keep agents out of writable parents (L3 does for wrapper sessions).
* **No sudo in `run`**, ever; `run` refuses to launch as root.
* **Not recursive**: `add` changes the one directory's owner/mode, never its contents.

## Uninstall

```bash
sudo ./uninstall.sh --restore-all      # restores every directory first; refuses otherwise while any is protected
```

## Documentation

**`protect-folder help`** (built-in: `help COMMAND`, `help TOPIC`, `help all`; topics: layers, agents, profiles, exit-codes, env, files, safety) · **`EXAMPLES.md`** (copy-paste recipes for every command and situation, with a table of messages and what to do) · `CLI_REFERENCE.md` (the same, generated from the parser: every argument and option, profiles, environment variables, exit codes) · `ARCHITECTURE.md` · `SECURITY.md` (threat model, verified facts,
known limits) · `examples/` · `scripts/acceptance.sh` (end-to-end acceptance on your own disks).

## Tests

```bash
python3 -m pytest -m "not privileged and not live_agent"            # default, temporary fixtures only
sudo env PF_PRIVILEGED_TESTS=1 python3 -m pytest -m privileged tests/integration   # real chown/chmod/ACL
PF_LIVE_AGENT_TESTS=1 python3 -m pytest -m live_agent               # real agents (uses quota)
```

Skipped tests are reported as `SKIPPED`, never as passed.

## License

Apache License 2.0: see `LICENSE`. The sandbox runtime (`@anthropic-ai/sandbox-runtime`) and node are **not** part of this repository; `install.sh` copies them from your own installation, under their own licences.
