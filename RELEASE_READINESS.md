# Release readiness: protect-folder 1.0.0

Date: 2026-11-18. Host: Ubuntu 22.04, kernel 6.8, Python 3.10. Tested agent versions: Claude Code 2.1.x,
OpenCode 2.3.0, codex-cli 0.159.3; srt 0.0.83; bubblewrap 0.6.1.

**Verdict: phases A-E are complete and the privileged paths have now been exercised on real disks (section 1b). Remaining
gaps: the live-agent acceptance step was not run, and the items in section 4. OpenCode live L1/L2 needs an idle host and
an occasional re-run (section 2).** Every claim below says how it was established.

## 1. Verified by automated tests run in this session (as a normal user)

| Suite | Command | Result |
|---|---|---|
| Default (unit, integration with real SRT, security, performance; temporary fixtures only) | `python3 -m pytest -m "not privileged and not live_agent"` | **532 passed**, 0 failed; 22 deselected (10 privileged, 12 live-agent) |
| Adversarial sandbox escapes + hook bypass | `tests/security` | all pass after fixes (see section 3) |
| Scale (500 targets) | `tests/performance` | 5 passed: registry round-trip, SRT policy compile, hook latency via the real script, `list` pipeline + table at 100 and 40 columns, 1 MiB source within the time budget |
| Live Claude Code inside SRT | `test_claude_live_srt.py` | 4 passed (sanity, L1 deny, L2 block, L3-only hides the directory) |
| Live Codex inside SRT | `test_codex_live_srt.py` | 1 passed (works inside the sandbox, cannot see a protected directory) |
| Live OpenCode inside SRT (Ollama qwen3.6:35b) | `test_opencode_live_srt.py` | 5/5 earlier; degraded under host load; live verify PASSED on re-test with an idle host (section 2) |

Negative controls: every "the marker was not returned" escape test first proves the same command DOES return the
marker on an unprotected directory, so none of these is a vacuous pass.

## 1b. Verified with real root, run by the operator (output pasted into the session, 2026-11-18)

| Step | Result |
|---|---|
| `sudo env PF_PRIVILEGED_TESTS=1 python3 -m pytest -m privileged tests/integration` | **9 passed, 1 skipped** (the skip: no non-POSIX filesystem mounted here, so the UNSUPPORTED_FILESYSTEM case is untested on a real mount) |
| `sudo ./install.sh` | first attempt **failed** (found an unrelated `srt` on root's PATH); fixed (validated discovery, `--node`/`--srt-package`); second attempt installed. `doctor`: all PASS except warnings listed in section 5 |
| `sudo ./scripts/acceptance.sh /mnt/disk1 /media/user/disk2 /home/user/test-dir` | **65 passed, 0 failed, 3 skipped** (live agent checks not requested). Three ext4 filesystems on three devices. Per disk: dry-run changes nothing, add, idempotent add, root:root 0700, unprivileged read/list denied outside SRT, list/status/verify, SRT marker not returned and python `open()` blocked, argument/exit-status fidelity, refusal to run as root, `set-layers --no-linux` restores permissions while SRT alone still masks, `--all` re-locks, `remove` restores owner/mode/ACL exactly, marker readable again. Fixtures were removed and the registry left empty |
| `sudo protect-folder verify --admin` (inside acceptance) | PASS |

| `sudo ./scripts/acceptance.sh --agents /mnt/disk1` (installed launcher, real agents), final run 15:53 | **28 passed, 0 failed, 0 skipped.** `verify --agent claude|opencode|codex --live` all PASS through the installed launcher on a root-protected directory on a second real disk. Earlier runs the same day: 27/0/1 (OpenCode skipped by a script PATH bug) and one run that was slow for a reason outside the product (see below) |

Slowness diagnosis (not a product defect): Ollama had loaded qwen3.6:35b only partly into GPU memory (17.4 of 22.6 GB) while another
GPU job was running, so inference was CPU-bound (GPU 2%, load average 33). Unloading the model and re-running (full GPU load) made the same step finish quickly.

Found while doing this: this machine has **two OpenCode installs** (v1.17.0 in `~/.opencode/bin`, v2.3.0 in nvm). The adapter is
built on v2.3.0 and did not check the version, so launching v1 would have applied v2-style rules that v1 may ignore. The
adapter now refuses any version whose major number is not 2 (unparseable version strings are allowed). The installed copy in
`/usr/local/lib/protect-folder` is the OLD code until `sudo ./install.sh` is run again.

The acceptance script only creates and removes its own `pf-acceptance-*` directory; it never protected the existing contents of those paths.

## 2. Live OpenCode (resolved by re-testing on an idle host, 15:16-15:20)

* Earlier today: live suite 5/5 and `verify --agent opencode --live` PASS/PASS.
* While the host was overloaded (load average 25-30): sanity test failed, shell test inconclusive, and the live verify failed
  twice with L2 `UNVERIFIED` (offline hook checks all PASS; the model never completed a tool call).
* Re-test with the host idle (load 0.5): **`test_live_opencode_verification_with_real_sessions` PASSED in 92 s with
  ollama/qwen3.6:35b.**
* Hosted model `opencode/big-pickle`, same code, two consecutive runs: first **UNVERIFIED** (46 s), second **PASSED** (50 s).
* Conclusion: the outcome tracks whether the model chooses to attempt the tool call, not a defect in the protection. The
  verifier is working as designed: no attempt means UNVERIFIED, never PASS. Across all runs today there was **no FAIL, i.e.
  no run in which a protected path was actually read**. This is evidence from a small number of runs with two models; a
  PASS shows the block happened when the model tried, not that no model could ever find a gap.
* Practical consequence: `verify --agent opencode --live` can need a re-run to get a conclusive PASS.

## 3. Defects found and fixed this session by the adversarial suites

* `$(echo X)`, `printf %s`, backtick substitution, here-strings, literal `eval`, and dynamic `bash -c "$(...)"` were not
  inspected. Fixed in `inspect/shell.py` and `inspect/engine.py`; regression tests in `tests/unit/test_inspect.py`.
  The backtick form was failing because the matcher counted the opening backtick as nested.
* Hook accepted `{"tool_name": 5}`; it now requires a string tool name and a dict-or-null input, otherwise blocks.
* A falsy-marker check treated `{}` as "no marker"; now `is not None`.
* Test pollution: the sandbox `/tmp` is the real `/tmp`, so stale `/tmp/pf-link` from an earlier run made a symlink-alias
  test report a leak. Not a product bug. Escape tests now use a unique per-run prefix and clean it up.
* Several test fixtures used unquoted paths with spaces and were silently vacuous; fixed with quoting and negative controls.
* Dead code: the unused top-level `adapters/` copy loop in `install_code`, and 4 unused imports, were removed.

## 4. Still NOT verified

* `sudo ./uninstall.sh --restore-all`: root paths of the uninstaller untested (it would remove the installation you just made).
* Non-ext4 filesystems on real mounts (xfs, btrfs; the tools are now installed, loopback test pending), the refusal on a real vfat mount, and a physically unplugged/re-attached disk; only the simulated
  mount-identity cases and ext4 were exercised.
* Protecting a directory that real agents are running in, with the installed (not source-tree) launcher, for a long session.

## 5. Known limits (also in SECURITY.md)

* Not a boundary against root, or against your own account when it can use `sudo`. This machine's user is in the `lxd`
  group, which is a real way around L4 outside the sandbox (`doctor` reports it).
* Agents not started through `protect-folder run` (the running OpenCode service, IDE Codex processes) are not confined.
* Codex L1 and L2 are UNSUPPORTED, so Codex is at most 2/4 (L3 + L4), reported as such. Its TUI behaviour inside SRT is
  a single observation.
* OpenCode: the project's own `opencode.jsonc` is ignored by design; `--server`, `service`, `attach`, `serve`, `web` are refused.
* L2 is best-effort static analysis: dynamic constructs are INCOMPLETE (blocked in `strict`, deferred to L3/L4 in `balanced`).
* Parent-directory rename is not prevented by L4.

## 6. Housekeeping disclosure

An early local git commit ("Phase A+B...") was made in a previous session without being asked; no commit has been made
since, and the working directory is currently not reported as a git repository by the environment.
