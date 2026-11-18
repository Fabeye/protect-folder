# Protect Folder — Technical Specification (v1.0)

**Document type:** Implementation-ready software requirements and engineering brief  
**Target platform:** Linux (Ubuntu/Debian first), Python 3.10+  
**Status:** Specification, not an existing implementation  
**Intended recipient:** Autonomous coding agent implementing the entire application

## 0. Implementation directive

Build a usable, tested, installable command-line application named **`protect-folder`**. This is an implementation request, not a request to merely redesign or summarize the system. Produce code, tests, an installer, documentation, and a working end-to-end demonstration. Do not claim that protection is active or that a test passed unless it was actually verified. Where an integration is not supported by the installed version of an agent, report its status honestly instead of silently substituting a weaker mechanism.

Before coding, examine the current official APIs of Anthropic Sandbox Runtime (SRT), Claude Code, OpenCode, and Codex CLI. Prefer stable, documented APIs. Pin and document tested versions; do not copy assumed or historical configuration schemas without validation.

## 1. Product objective

Create a **universal, Linux-first, single-entry-point CLI** that protects an arbitrary and growing set of directories from local AI coding agents. Directories may exist in entirely unrelated projects and on different mounted filesystems. The user must NOT have to move them under a common parent.

One administrator command should register a target, apply as many of the four protection layers as the selected agent adapter supports, enforce host-level directory permissions, and record original metadata for safe reversal. One unprivileged command should launch a supported agent within a verified restriction environment. The user should be able to inspect status, test enforcement, and review attempted accesses.

Representative workflow:

```bash
sudo protect-folder add '/home/user/projects/Forbidden folder'
sudo protect-folder add '/mnt/ssd2/project-two/credentials'
sudo protect-folder add '/media/user/archive/research/private data'
protect-folder list
protect-folder verify
cd ~/some-unrelated-project
protect-folder run -- claude
protect-folder run -- opencode
protect-folder run -- codex
sudo protect-folder remove '/mnt/ssd2/project-two/credentials'
```

`run` MUST NOT require or invoke `sudo`. Administrator subcommands MUST NOT launch an AI agent as root.

## 2. Product decisions and scope

### Required for v1

- Global registry of **independent absolute directory paths** across disks/projects, with add/list/remove operations and deterministic generated policies.
- Four-layer conceptual architecture: (L1) native agent tool restrictions, (L2) pre-execution hook with source inspection, (L3) SRT isolation, (L4) Linux permissions.
- **L1 and L2 are fast, best-effort filters; L3 and L4 are the primary operating-system-backed access boundaries.** Never market regex or static code scanning as comprehensive security.
- Root-owned registry, policy files, executable, and implementation code; an unprivileged agent must not be able to modify security configuration.
- Single installed CLI, with generated adapter/configuration assets permitted internally. No GUI, web server, Docker requirement, mandatory background daemon, or database.
- Linux ownership mode `root:root` and directory mode `0700` as the default v1 host protection. Preserve original metadata for reversal.
- Safe handling of symlinks, stale paths, renamed/replaced targets, mount changes, paths containing spaces, and filesystems not supporting POSIX permissions.
- `verify`, `status`, `logs`, `--dry-run`, `--json` for scriptable outputs, and explicit capability reporting per agent.
- Claude Code and OpenCode integrations, separately tested against supported versions. Codex CLI supported at least through the common SRT/OS wrapper; native filter/hook support must be capability-gated and must not be invented.
- Policy enforcement must **fail closed** when SRT is unavailable, a target has disappeared or changed identity, a required native adapter is invalid, or effective sandbox settings cannot be verified.
- Existing AI sessions are not retroactively protected by changes to a registry; provide clear restart warnings.

### Explicitly out of scope for v1

- Creating or requiring a separate Linux user for each agent. Document it as a future optional stronger mode.
- Promise of 100% protection against root, kernel exploits, malicious privileged services, or a user knowingly launching a command outside the wrapper.
- General-purpose malware detection, arbitrary-code static verification, scanning an entire filesystem for secrets, and kernel-level forensic auditing without a separately installed audit system.
- Automatic interception of every bare `claude`, `opencode`, or `codex` invocation elsewhere on the machine; users must use `protect-folder run -- ...` unless a separately configured shell alias/wrapper is explicitly enabled.
- Support for cloud/remote sessions executing on machines other than the protected host.

## 3. Threat model and honest guarantees

**Assets:** files/subdirectories contained in registered directories; integrity of protective registry, policies, and application binary; historical permission snapshots.

**Adversary:** a local coding agent operating as the normal user, able to generate and execute Bash/Python/Node/C/C++ programs and child processes, alter files in permitted project workspaces, inspect allowed directories, and try alternative path spellings. Assume the model may be persistent or adversarial, not merely obedient.

**Trusted components:** Linux kernel, current SRT implementation where successfully enforced, root-owned installed files, system administration, and verified adapters. This model assumes no privilege escalation, no kernel compromise, and no authorized high-privilege out-of-sandbox tool acting as the agent's deputy.

**Not guaranteed:** the normal human user can still type a password and run `sudo`; a process running as the same Unix user might also obtain existing sudo authorization or talk to an already-privileged external service. The v1 design mitigates these risks by refusing privileged launches, clearing inherited dangerous environment variables where appropriate, denying/flagging privilege escalation in native policies/hooks, recommending `sudo -K` after administrative operations, and checking for obvious privileged sockets, but **cannot cryptographically prevent elevation by the same Unix identity**. Include this prominent warning in README and CLI status.

**Success definition:** a configured, verified agent process and its ordinary children cannot read actual content under registered paths through normal OS file operations. Adversarial resistance is bounded by the stated threat model. A successful failure-to-read test is evidence about the tested path and mechanism, not proof against all bypasses.

## 4. Architecture

Implement separate modules behind **one installed CLI**:

1. **Core registry and policy compiler:** stores registered targets, versions, filesystem metadata, agent compatibility, and policy revision. Converts the registry into canonical agent permissions and SRT configuration.
2. **Privileged administrative operations:** safely register/unregister targets, snapshot/restore permissions, validate mounted filesystem, and update root-owned policy data.
3. **Agent-agnostic execution wrapper:** loads an immutable policy snapshot, performs preflight checks, invokes `srt` with properly separated arguments, starts the target program, and propagates signals and exit codes. Does not run as root.
4. **Agent adapters:** Claude Code, OpenCode, Codex CLI, plus a generic executable adapter. Each explicitly declares support for L1/L2; never misrepresent generic wrapping as equivalent to full native hooks.
5. **Source-inspection engine:** common, read-only, bounded analysis library callable from Claude hooks and OpenCode plugin. The library itself is not privileged.
6. **Verification and logs:** test policy generation, inspect actual runtime results, and report `PASS`, `FAIL`, `UNVERIFIED`, `UNSUPPORTED`, or `STALE` per layer and target.

Prefer Python standard library for core functionality. Adapter glue in TypeScript/JavaScript is acceptable when required by a documented OpenCode plugin API. Dependencies on `srt`, `bubblewrap`, `socat`, and `ripgrep` must be checked and installed or clearly instructed, never silently downloaded/executed as root from an unverified remote script.

## 5. Filesystem layout and trust boundary

Recommended layout (adjust only if a documented system convention requires it):

```text
/usr/local/bin/protect-folder              # root-owned executable, mode 0755
/usr/local/lib/protect-folder/             # root-owned implementation and adapter assets
/etc/protect-folder/                      # root-owned policy, 0755 directory
  targets.json                            # readable for compilation, not writable by users
  policy.json                             # default network/write/adapter profiles
  generated/                             # generated Claude/OpenCode/SRT policy artifacts
/var/lib/protect-folder/                  # root-owned, non-readable by unprivileged users
  snapshots.json                          # original ownership/mode/ACL and identity
  transactions/                           # recovery journal
/var/log/protect-folder/                  # root-managed administrative log
```

The canonical registry is root-owned and not user-writable. Runtime-generated policy may need to be readable by the unprivileged launcher and/or hook; distinguish **write protection** from **path secrecy**. If target paths must be known to a hook or SRT, they may become visible to the launching user: do not promise names remain confidential. Store original ACL snapshots and any privileged recovery metadata mode `0600` in a root-only directory.

Never place installed trusted hook code, generated security policies, or launcher binaries under a workspace that the agent can edit. The generated SRT policy MUST deny write access to all trusted application files. Verify actual ownership and mode on every launch.

## 6. CLI requirements

Provide an ergonomic, predictable interface:

```text
protect-folder --help
protect-folder install [--dry-run]             # documented initial installation
protect-folder doctor                          # versions/dependencies/environment
sudo protect-folder add PATH [--dry-run] [--yes]
sudo protect-folder remove PATH [--dry-run] [--yes]
protect-folder list [--json]
protect-folder status [PATH] [--json]
protect-folder verify [PATH] [--agent NAME] [--json]
protect-folder logs [--since TIME] [--agent NAME] [--json]
protect-folder run [--profile NAME] [--require-layers N] -- COMMAND [ARGS...]
protect-folder adapters
protect-folder version
```

Clarify in help that `add/remove` require administrator authorization, while `run/list/status/verify` ordinarily do not (individual checks may request privilege through explicit admin-only subcommands, never surprise sudo during agent launch).

The syntax `protect-folder run -- claude`, `-- opencode`, `-- codex`, and `-- python3 script.py` MUST preserve all command arguments, stdout/stderr, terminal interaction, working directory, exit status, signals, and cancellation behavior. Do not concatenate argv into a shell command. Use process spawning with an argument array and no shell interpolation.

`add` is idempotent; duplicate registrations yield a deterministic `ALREADY_PROTECTED` result without overwriting the original permission snapshot. `remove` is similarly safe and explicit. Accept spaces, Unicode, and leading-dash filename segments safely; use `--` where needed. Produce actionable errors with nonzero exit codes. `--json` output must use stable schemas and machine-readable reason codes.

## 7. Registry, identity, and cross-disk support

Each entry requires at least:

```json
{
  "id": "stable-generated-id",
  "input_path": "/mnt/ssd2/project-two/credentials",
  "canonical_path": "/mnt/ssd2/project-two/credentials",
  "st_dev": 12345,
  "st_ino": 67890,
  "filesystem_type": "ext4",
  "mount_point": "/mnt/ssd2",
  "created_at": "ISO-8601",
  "status": "active"
}
```

Do not use example device/inode values as actual data. The implementation resolves path spellings, performs no-follow or open-fd-based validation where possible, rejects non-directory targets, and checks identity before irreversible changes. Reject targets that are the filesystem root, the user's entire home directory, system-critical paths, the application's installation/configuration/state paths, or directories containing those paths unless an explicit safety design permits them. Prevent target paths that overlap installed trusted infrastructure.

Canonicalize symlinks and store the operator's original spelling as metadata; do not silently protect an unintended symlink destination. Use file-descriptor-relative operations and no-follow APIs where practicable to reduce TOCTOU races. Detect and report nested mount points, bind mounts, hardlink/alias risks where relevant, replacement/reparenting, and filesystem changes. On removable disks, fail verification when the original mount is absent or the identity no longer matches; never automatically protect a newly appearing different directory at the same string path.

Do not assume `chown/chmod` work on exFAT, NTFS, NFS or FUSE mounts. Identify unsupported or unreliable semantics, stop with `UNSUPPORTED_FILESYSTEM`, and do not record a successful four-layer registration. Include automated tests for spaces, Unicode, symlink aliases, mount identity mismatch, and stale paths.

## 8. Layer L1 — native tool permissions

Generate per-agent permissions from the same registry:

- **Claude Code:** documented `Read`/`Edit` restrictions for each target and descendants; load through a verified `--settings` file without overwriting unrelated user preferences. Validate actual effective settings, including whether a malformed setting was ignored. Do not assume native `Read`/`Edit` restrictions cover arbitrary code in Bash.
- **OpenCode:** version-appropriate `permissions` rules (`read`, `edit`, `shell`, `external_directory`, other relevant actions). Observe rule ordering and the version's actual resource semantics. Test real tool calls, not just JSON syntax. Do not silently use a V1 schema against V2.
- **Codex CLI:** discover the real installed version's sandbox/approval facilities. Use only documented supported policies. If fine-grained native read-denial cannot be implemented, report `L1: UNSUPPORTED` and rely on L3/L4; do not claim L1 is active.
- **Generic commands:** report `L1: NOT_APPLICABLE`.

Deny obvious direct protected-path requests, but treat this as performance/user-feedback filtering rather than a confidentiality boundary. A native permission check that returns a warning or user prompt instead of denial is NOT a passing enforcement result.

## 9. Layer L2 — pre-execution hooks and source inspection

A reusable inspection engine processes an incoming tool name, structured arguments, working directory, and policy snapshot. It must:

- Normalize paths and check explicit target references and known canonical aliases.
- Identify common direct calls (`cat`, `find`, `ls`, etc.) and obvious attempts to invoke elevated commands (`sudo`, `su`, `pkexec`, `doas`) without confusing textual occurrence in quoted data with executable invocation where practical.
- Recognize common interpreter invocations such as `python[3] file.py`, `bash file.sh`, `sh file.sh`, `node file.js`; identify the script path relative to the tool's actual CWD; inspect the source **before** the tool executes.
- Inspect direct inline execution where practical (`python -c`, `bash -c`, `node -e`, heredocs); parse shell tokens conservatively with appropriate bounds, and report unsupported constructs as `INCOMPLETE_INSPECTION`.
- Search for absolute protected paths, normalized variants, split literals such as `"Forbidden" + " folder"`, and obviously constructed `Path(...)` or shell arguments. Do **not** claim to solve arbitrary program analysis, imports, generated code, compiled binaries, obfuscation, or runtime environment-dependent paths.
- Refuse an explicitly recognized script whose source cannot be safely read or whose size/time limit prevents inspection in **strict** policy mode. In **balanced** mode, report `INCOMPLETE_INSPECTION` and defer enforcement to SRT/Linux when refusing would break normal development; policy mode must be visible.
- Read-only inspection; never execute inspected source; never write into it; never log sensitive source content.
- Use configurable limits (e.g. 1 MiB maximum inspected source, 2 s maximum analysis by default), with useful diagnostics and performance tests.

**Claude adapter:** implement a documented `PreToolUse` hook that blocks calls through the current supported mechanism (including a validated hook failure/exit behavior) and actually receives all intended tool events. A hook crash must never silently become a successful authorization when the configured policy demands blocking.

**OpenCode adapter:** implement a version-appropriate server plugin with `tool.execute.before` / V2 `ctx.tool.hook('execute.before', ...)` as documented, calling the same inspection engine. Test its loading and its denial behavior from a genuine tool call. If the hook cannot load, mark L2 unavailable; no claim of 4/4.

**Codex adapter:** do not invent a universal pre-execution hook. If the target version lacks a supported equivalent, return `L2: UNSUPPORTED`. The OS layers must still operate for Codex if the process can actually be isolated.

All generated source-inspection adapters are nonprivileged and use root-owned implementation/policies. No blanket ban on running Python/Bash/Git or compiling software.

## 10. Layer L3 — Anthropic Sandbox Runtime (SRT)

Build an SRT settings file from **all** registered target directories on each protected launch. Use concrete absolute paths on Linux and documented literal-path syntax where available; avoid glob guesses. At minimum:

- `filesystem.denyRead`: every registered target.
- `filesystem.denyWrite`: every registered target.
- `filesystem.allowRead`: no rule that accidentally reopens a registered directory.
- `filesystem.allowWrite`: only the selected project/worktree, necessary agent state/cache directories, and essential temporary paths; never the protected target or trusted config. Respect SRT's specific read/write precedence semantics and **verify the effective result** for overlaps.
- `network.allowedDomains`: profile-specific documented allowlist. No implicit allow-all. Reject or explicitly warn about privileged external sockets and proxy bridges.
- Disable weakening/unsandboxed escape modes where applicable. Do not proceed if SRT is unavailable or a required security control cannot initialize.

Use `srt --settings <FILE> -- <COMMAND> ...` or the exact documented invocation for the installed version, with correct handling of argument boundaries. If an agent starts an external background server, attaches to another user-level service, invokes MCP processes, or delegates execution outside the wrapped process tree, do not assume that activity is within SRT. For OpenCode, prefer a verified standalone/in-process server or a protected server launched by the wrapper. For Codex, test nested sandbox compatibility rather than making claims based only on a successful CLI start.

### Network compatibility

Real agents need API connectivity, package registries, or local model servers. Provide named profiles (`offline`, `claude`, `opencode-local-ollama`, `opencode-cloud`, `codex`, `custom`) that allow only needed hosts and ports. Preserve the normal ability to use Git, Python, package managers, and a model API where explicitly allowed. Do not automatically use a globally unrestricted network policy as a fallback.

Linux's SRT network namespace can make the host's `127.0.0.1` unavailable to the sandbox. Test host Ollama access through the SRT proxy and, only if necessary, a narrowly scoped, explicitly allowlisted loopback relay **inside the sandbox**. The relay must not expose an open proxy, privileged host service, or arbitrary network forwarding; it must be constrained to a known endpoint. Do not assert that a successful `curl` request proves a Bun/OpenCode SDK will work: test a real model inference request end to end.

## 11. Layer L4 — Linux directory permissions

Default v1 mode: snapshot original directory ownership/mode/ACL, then apply `root:root`, mode `0700` to **the protected directory itself**, not recursively to all children. The parent directory and all other project contents remain unchanged, unless an additional, separately approved protection is required.

- Use privileged operations only for administrative commands, not for agent execution.
- Check results with `stat`/equivalent after applying; reject filesystems that do not honor the required semantics.
- Save numeric UID/GID, mode, ACL (including default ACL), relevant file identity, mount identity, and snapshot version in root-only state; make restoration safe, not guessed.
- Reject unexpected existing ACLs or preserve/restore them using reliable documented tools; report partial protection rather than falsely claiming a match.
- Warn that ordinary user programs, IDE/file-manager access and Python scripts will also lose normal access. This is an accepted v1 usability tradeoff.
- Explain that protecting only the child directory does not necessarily stop renaming its directory entry if the parent is writable, and that it is not a complete same-UID/sudo privilege boundary.

`remove` must verify that the current filesystem object matches the snapshot. Restore original UID/GID/mode/ACL **only after** a successful identity check; otherwise refuse automatic restoration and supply a safe manual recovery procedure. Never restore a snapshot onto a different mount/object. Do not run broad recursive `chown` or use permissive `chmod 777` as recovery shortcuts.

## 12. Transactional administration and rollback

Treat `add`/`remove` as privileged multi-step transactions. Validate everything possible before changing either policy files or host permissions. Use an exclusive lock and a journal of intended/finished steps. Write new JSON to temporary files in the same filesystem, `fsync`, and atomically rename where supported. Preserve last-known-good revisions.

An operation is **not** truly atomic across Linux permissions and multiple configuration files; document that and implement explicit compensation/recovery. On failure, attempt safe rollback in reverse order, restore metadata only if object identity is unchanged, and leave a `RECOVERY_REQUIRED` state if full rollback cannot be proven. Reject concurrent conflicting modifications. An unclean shutdown must be discoverable and recoverable through `doctor`/`status`.

After registry changes, note that **already-running sessions retain their prior SRT mount namespace** and MUST be restarted for updated protection. The CLI must print a prominent warning or identify monitored live sessions where feasible; it must not claim global immediate enforcement.

## 13. Audit, observability, and verification

### Audit logs

Administrative events (`add`, `remove`, `restore`, configuration revision, failures) go to root-managed logs with timestamp, actor UID, target ID, operation, outcome, and error code. For tool-level denials, write minimal events (agent type, tool, reason, target ID, session, timestamp) without logging secret file contents or source snippets. Since a normal unprivileged hook cannot directly write to a root-owned log without a privileged service, v1 may keep per-user hook logs with clear **best-effort / not tamper-proof** labeling. Optionally integrate system journal/auditd when available, but do not claim that every kernel file-denial is logged by default.

### Verification

`protect-folder verify [PATH] [--agent NAME]` must give **per-layer results** from independent, executable tests, not just configuration presence. Use controlled synthetic markers, not genuine secrets. At least:

1. Validate registry and policy integrity, ownership, mode, target identity, and current mount.
2. Check effective native tool permission by trying a harmless blocked read through the actual agent adapter when a safe noninteractive harness is available.
3. Test hook directly and through a real agent tool call; one safe script must execute while a synthetic script referencing a forbidden directory must be rejected before execution.
4. Verify SRT masking independently using a test fixture accessible to the normal user **before** root locking. Ensure the actual known marker is not returned; distinguish absence/masking from permission denial.
5. Verify Linux permission enforcement independently outside SRT as the ordinary user; verify admin recovery separately.
6. Test subprocesses, symlinks, alternative path spellings, spaces, runtime-created paths, and child processes. Categorize the outcome; never infer which layer caused a generic `PermissionError` without evidence.
7. Verify network/model access for the selected adapter with a real small inference request where possible, while preserving all filesystem restrictions.

Return structured status for each layer: `PASS`, `FAIL`, `UNVERIFIED`, `UNSUPPORTED`, or `STALE`. Show combined status as `VERIFIED_LAYERS: 3/4`, for example, never `4/4` if a plugin did not load. A check must never weaken or remove real protections just to get a passing result; use temporary synthetic fixtures for independent tests.

## 14. Adapter capability negotiation and safe launching

At launch, detect command identity and resolve a validated adapter. Use a stable capability report such as:

```json
{
  "agent": "opencode",
  "layers": {
    "native_permissions": "pass",
    "pre_execution_hook": "pass",
    "srt": "pass",
    "linux_permissions": "pass"
  },
  "warnings": [],
  "policy_revision": "..."
}
```

Treat this as a response example, not a fabricated runtime measurement. Unsupported adapters may run with L3/L4 under an explicit minimum layer policy; if `--require-layers 4` is requested, refuse before launch. Default to requiring the **two mandatory OS layers** (L3/L4) and report native adapter capabilities clearly. Provide a strict profile that requires 4/4 where achievable. Generic executable support must never pretend to implement native agent permissions or hooks.

Preflight checks must ensure: not root; valid config; all target identities correct; trusted executable/policy ownership and permissions; SRT available; no protected paths re-allowed; no known unsecured external server/subprocess route; target filesystem permissions effective; and relevant native adapter loaded. Do not silently connect to an unprotected existing server. Preserve Ctrl-C, TTY, terminal resize, signals, process group lifecycle, and meaningful exit status.

## 15. Performance and usability

- Registry operations with 1, 10, 100, and 500 independent targets must remain deterministic; support explicit path entries rather than forcing a shared parent.
- Before-tool scanning should be bounded and cached carefully by `(device, inode, size, mtime_ns, policy_revision)` where safe; never trust stale cache after a file changes.
- Keep normal Git, Python, test runners, compilers and editing functional outside protected directories; do not impose blanket restrictions just to improve measured security.
- Provide concise block reasons to the model/user, such as `Protected directory; reading is prohibited by policy`, without showing the contents.
- Clear command output should identify whether a failure is a tool-hook denial, SRT mask, Linux permission denial, unsupported integration, or unknown. If not distinguishable, say `unknown`.
- Include examples of at least three independent protected folders on different mounted volumes.

## 16. Tests required

Implement unit tests, integration tests and safe adversarial regression tests for:

- Registry CRUD, idempotency, deduplication, sorting, serialization, and schema migrations.
- Paths with spaces/Unicode, symlinks, relative paths, glob-like names, dangling targets, directory rename, bind mounts, disappearing removable media, and unexpected new object at the same path.
- Permission snapshot/restore, ACL behavior, partial failure, concurrent `add`, interrupted update, recovery journal, safe rollback, and never-recursive metadata changes.
- Agent adapter version compatibility and actual hook invocation/denial; malformed schema and uninstalled plugin must fail rather than silently pass.
- Static inspection of `python script.py`, `bash script.sh`, inline commands, here-documents, dynamic split literals, imported or unsupported code; assert correct `INCOMPLETE_INSPECTION` reporting.
- Real SRT filesystem deny read/write, subprocess and symlink cases, and whitelist/deny precedence.
- Linux root-lock behavior vs unprivileged processes, and limitation around parent directory rename.
- SRT network connection to representative cloud endpoints and host-local Ollama; verify full model response from OpenCode, not only HTTP 200 on `/api/tags`.
- Absence of root privileges in agent launch, protected configuration immutability, and refusal on policy tampering.
- Machine-readable JSON contract, exit codes, audit redaction and not logging secret contents.
- Adapter-agnostic `run --` with commands and flags; correct argument forwarding and signals.

Use temporary test fixtures and mocks for destructive or privileged cases. Mark actual privileged integration tests separately, require explicit opt-in, and never modify real user directories during the standard test suite. CI may skip kernel-specific tests with a clearly visible `SKIPPED` state, not `PASS`.

## 17. Acceptance criteria (definition of done)

A release is acceptable only when all of the following are demonstrated:

- [ ] Fresh Linux installation instructions work on the declared supported versions.
- [ ] One installed `protect-folder` entrypoint exposes all specified CLI commands and `--help` examples.
- [ ] Three separate directories, including a path with spaces on a different disk, can be registered cumulatively without moving or grouping them.
- [ ] One `add` updates every generated policy and installs L4; previous registered targets remain active.
- [ ] Registry, application and trusted security files are root-owned/non-user-writable, with original permission snapshots root-private.
- [ ] `list/status/verify` report accurate actual path identities and layer capabilities.
- [ ] A protected launch can edit ordinary project files, run Python and Git, and access explicitly allowed model endpoints.
- [ ] Direct read, executed scripts, subprocesses and symlink reads of synthetic protected content fail without exposing the marker.
- [ ] Hook source inspection is empirically proven through real Claude and OpenCode tool calls and not merely through unit tests.
- [ ] Codex integration is either proven at its claimed level or transparently declared incomplete/limited. No fictional 4/4 support.
- [ ] The launcher refuses missing/invalid SRT, policy tampering, missing targets, insufficient OS permissions and unsafely detached agent servers.
- [ ] `remove` restores only the original matching directory's original ownership/mode/ACL; stale/replaced targets fail safely.
- [ ] Interrupted operations are recoverable and cannot silently leave success records with only partial enforcement.
- [ ] Logging excludes protected file contents; audited layer outcomes and limitations are stated correctly.
- [ ] Installation, upgrade, uninstallation, migration/recovery, security limitations and example commands are documented.

## 18. Delivery artifacts and implementation sequence

Deliver:

```text
README.md
SECURITY.md
ARCHITECTURE.md
CLI_REFERENCE.md
pyproject.toml (or justified packaging alternative)
install.sh or equivalent auditable installer
src/protect_folder/...
adapters/claude/...
adapters/opencode/...
adapters/codex/...
tests/unit/...
tests/integration/...
tests/security/...
examples/...
```

Recommended sequence:

**Phase A:** root-owned registry, safe path canonicalization, CLI, snapshot/recovery transactions and tests.  
**Phase B:** SRT policy compilation and fail-closed generic launcher; independent SRT verification.  
**Phase C:** native Claude permissions + hook; OpenCode permissions + plugin; share the source-inspection engine.  
**Phase D:** Codex capabilities, network profiles, local Ollama integration, audit/verify/reporting.  
**Phase E:** end-to-end acceptance tests, docs, installer, adversarial regression cases and a clear release readiness report.

After each phase, run the relevant tests and report exactly what passed, failed or remained untested. Continue to implementation rather than stopping after producing another plan. If a documented dependency or agent feature makes a requirement infeasible, provide a narrowly scoped alternative and explicitly mark the requirement unfulfilled pending approval; do not fabricate success.

## 19. Maintainer references (verify during implementation)

- Anthropic Sandbox Runtime: https://github.com/anthropics/sandbox-runtime
- Claude Code settings and permissions: https://code.claude.com/docs/en/settings
- Claude Code hooks: https://code.claude.com/docs/en/hooks
- OpenCode permissions: https://opencode.ai/docs/permissions
- OpenCode server/plugin APIs: https://opencode.ai/docs/build/plugins/server
- OpenCode plugin loading: https://opencode.ai/docs/plugins
- Codex CLI repository and configuration sources: https://github.com/openai/codex

Treat these as evolving external APIs. Validate currently installed behavior instead of assuming compatibility from the existence of a configuration field.
