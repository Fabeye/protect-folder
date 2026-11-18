# Security model and known limits

## What this protects against

An AI coding agent (or any program) running **as your ordinary Unix user, launched through
`protect-folder run`**, that tries - by mistake or by prompt injection - to read, list, copy, modify, delete or
exfiltrate directories you registered. Registered directories can live on any disk.

## What it does not protect against (read this)

* **root**, a kernel/bubblewrap/SRT vulnerability, or a privileged helper.
* **Your own sudo.** A process running as your user can use cached or passwordless `sudo`, or membership of the
  `docker`, `lxd`, `lxc` or `disk` groups, to become root and undo everything. `protect-folder` cannot
  cryptographically prevent elevation by the same Unix identity. It mitigates: `run` refuses to launch as root;
  dangerous environment variables are dropped; elevation commands are denied by L1/L2; SRT blocks unix sockets and
  `sudo`/`su` do not work inside it (tested); `doctor` reports group membership, writable Docker/LXD sockets and
  cached sudo credentials. Run `sudo -K` after administrative commands.
* **Anything not launched through `protect-folder run`**: IDE-extension agents, background services, another
  terminal. `doctor` lists agent processes that are running outside the launcher.
* **Parent-directory rename**: L4 locks the directory itself. If the agent can write the *parent*, it can
  rename or replace the directory entry. The data stays root-locked but is no longer at that path. L3 hides it for
  wrapper sessions; outside the wrapper, protect an ancestor you do not trust the agent with.
* **Name confidentiality**: the registry and generated policy must be readable by the launcher, so protected
  *paths* are visible to your user. Contents are protected, names are not secret.
* **Completeness of L2**: static inspection of commands and scripts is bounded (1 MiB, 2 s) and cannot resolve
  paths assembled at runtime (`os.environ[...]`, decoded payloads). This is by design: such inputs are reported
  `INCOMPLETE`; `strict` mode blocks them, `balanced` (default) defers to L3/L4. Tests pin both halves.

## Trust and tamper resistance

* Root-owned: `/etc/protect-folder/` (registry, policy), `/var/lib/protect-folder/` (snapshots, journal; 0700),
  `/usr/local/lib/protect-folder/` (code, hook, plugin, vendored node + SRT with recorded SHA-256 hashes),
  `/usr/local/bin/protect-folder`. Ownership/mode of all of it is verified on **every launch**; a tampered file,
  a pending recovery, a changed runtime hash, a missing/replaced target or a non-effective root lock makes `run`
  refuse (fail closed).
* The generated SRT policy denies write to every trusted path and read+write to every protected path (as literal
  paths, never globs). `allowRead` is always empty (it would override `denyRead`). SRT's weakening flags
  (`enableWeakerNestedSandbox`, `allowNestedUserNamespaces`, ...) are compiled as `false` and refused otherwise.
* `install.sh` stages the sources in a root-owned directory and runs the installer from there, so a user-writable
  checkout cannot change what root executes. Nothing is downloaded.
* Hook logs live in the user's `~/.local/state/protect-folder/` and are **best-effort, not tamper-proof**. Admin
  actions are logged by root in `/var/log/protect-folder/admin.log`. No log ever contains file contents or source.

## Facts established by experiment (tested versions)

Tested with: Claude Code 2.1.327, OpenCode 2.3.0, codex-cli 0.159.3, srt 0.0.83, bubblewrap 0.6.1, Ubuntu 22.04
(kernel 6.8). An agent update invalidates cached L1/L2 results (`STALE`) until re-verified.

**Claude Code** - a failing hook is *non-blocking* unless `"onFailure": "block"`, so the adapter always sets it;
`permissions.deny` `Read(//abs)` rules beat an explicit `--allowedTools`.

**OpenCode** (each point was reproduced; see `src/protect_folder/adapters/opencode.py`)
* The v2 config key is `permissions` (last matching rule wins, any deny wins). `read`/`edit` deny rules do **not**
  cover `glob`/`grep`; `external_directory` deny rules do (for directories outside the project), and the L2 plugin
  inspects their `path` input for the rest.
* A project `opencode.jsonc` can redefine an agent with `allow` rules appended after ours and defeat them.
  `OPENCODE_DISABLE_PROJECT_CONFIG=1` removes that; the cost is that the project's own OpenCode config is ignored.
* OpenCode **starts normally when a plugin fails to load** (missing path, syntax error, throwing `setup`). The launcher
  therefore requires a nonce handshake from the plugin *inside the real sandbox* before every launch.
* Throwing from `execute.before` or setting `effect = "deny"` in `permission.evaluate` both block; the plugin
  does both. The `policies` config form did not deny anything and is not used.
* OpenCode v2 defaults to a shared background service with its own configuration; the wrapper forces
  `--standalone` and refuses `--server`, `service`, `attach`, `serve`, `web`. OpenCode follows `$PWD` over the
  process cwd, so the launcher sets it.

**Codex** - L1/L2 are **UNSUPPORTED**, and this is reported, not hidden: hooks can only be defined in
`hooks.json`/`config.toml` behind a trust review (no documented per-launch injection), the documentation states a
hook error or malformed output lets the tool run and calls hooks "a useful guardrail, not a complete enforcement
boundary", and file reads are not a covered tool; permission-profile `deny` paths are enforced by Codex's own
bubblewrap sandbox, which cannot start inside SRT (`bwrap: No permissions to create new namespace`, tested). Codex
therefore runs `--sandbox danger-full-access` **inside SRT**, which then provides the isolation (a protected path
was invisible to `codex exec` and to the interactive TUI; the TUI result is a single observation). `--remote`,
`app-server`, `remote-control`, `exec-server` and `agents` (shared daemon) are refused.

**Network** - SRT's allow-list is by name; a client inside the sandbox dials the *sandbox's* loopback, so host
Ollama needs the allow-listed literal `127.0.0.1:11434` **and** a fixed in-sandbox relay (`sandbox_relay.py`) that
forwards through SRT's authenticated proxy (OpenCode's Ollama discovery ignores the proxy). The relay binds only
loopback, has one fixed upstream that must itself be allow-listed, and refuses to start the agent if it cannot
bind. A real OpenCode inference against host Ollama through it was verified.

## Verification evidence and what "VERIFIED" means

`verify` runs independent, executable tests with synthetic random markers (never real secrets) and reports per
layer `PASS / FAIL / UNVERIFIED / UNSUPPORTED / STALE / DISABLED`. A model that never attempted a tool call makes a
live check `UNVERIFIED`, not `PASS`. A `PASS` is evidence about the tested paths and mechanisms, not a proof against
all bypasses. Evidence is cached per directory, per policy revision and agent version.

## Reporting a vulnerability

Open a private security advisory with the repository host, or contact the maintainer directly. Please include the
exact command line, the registry/policy in use (paths may be redacted) and `protect-folder doctor` output.
