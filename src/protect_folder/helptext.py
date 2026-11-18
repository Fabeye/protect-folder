"""`protect-folder help [TOPIC|COMMAND|all]`: complete built-in documentation.

Everything that can be derived from the code (options, exit codes, profiles) is derived, never retyped, so this
cannot drift from the implementation. Hand-written topics explain concepts."""

from __future__ import annotations

import argparse

from .constants import VERSION
from .errors import EXIT_CODES

TOPICS: dict[str, str] = {
    "layers": """\
THE FOUR LAYERS
  1 agent permissions   The agent's own deny rules (Claude Code: permissions.deny; OpenCode: permissions).
                        Advisory: the agent enforces it on itself.
  2 pre-execution hook  A hook/plugin reads each command AND the scripts it would run before it executes and blocks
                        references to protected paths. Best-effort static analysis; fails closed on error.
                        Unsupported for Codex (reported as UNSUPPORTED, never faked).
  3 sandbox runtime     Anthropic Sandbox Runtime (bubblewrap): protected paths are masked for everything started by
                        'protect-folder run', network allow-listed. Enforced by the kernel.
  4 linux permissions   The directory becomes root:root 0700; original owner/mode/ACL are snapshotted and restored
                        exactly on remove. Enforced by the kernel for EVERY process, wrapper or not.

  Per directory: all four are on by default. 'add --no-hook', 'set-layers DIR --no-linux', 'set-layers DIR --all'.
  Only the layers you name change. Disabling both SRT and Linux permissions needs --accept-no-fs-enforcement.
  A nested directory can never switch off a layer its protected parent enforces (marked '*' in 'list').

DISPLAY STATES (list / status)
  ✓ VERIFIED     enabled and an executable test passed for this policy revision and agent version
  ? CONFIGURED   enabled but NOT verified yet (never counted as a pass): run 'protect-folder verify'
  ✗ FAILED       enabled and its verification failed
  — DISABLED     not enabled for this directory
  Status column = verified layers / 4.""",
    "agents": """\
AGENTS (protect-folder run -- COMMAND ...)
  claude     L1 permissions.deny via --settings; L2 PreToolUse hook (onFailure: block); L3; L4.
  opencode   L1 'permissions' via OPENCODE_CONFIG_CONTENT; L2 server plugin (its load is proven by a nonce
             handshake inside the sandbox before every launch); L3; L4. Needs OpenCode v2.x (other major versions
             are refused). Always started --standalone; --server and the subcommands service, attach, serve, web
             are refused. The project's own opencode.jsonc is ignored (OPENCODE_DISABLE_PROJECT_CONFIG=1).
  codex      L1 and L2 UNSUPPORTED (reported as such); L3 + L4 only. Runs with --sandbox danger-full-access INSIDE the
             sandbox, which then provides the isolation. --remote, app-server, remote-control, exec-server and agents
             are refused.
  anything   any other command gets L3 + L4 only ('generic').
  'protect-folder adapters' prints the declared capabilities; 'verify --agent NAME [--live]' tests them.
  Agents NOT started through 'protect-folder run' (IDE extensions, background services) are not confined.""",
    "profiles": "",      # filled from BUILTIN_PROFILES at render time
    "exit-codes": "",    # filled from EXIT_CODES at render time
    "env": """\
ENVIRONMENT VARIABLES
  NO_COLOR                 disable colour (same as --no-color)
  PF_OPENCODE_MODEL        model for 'verify --agent opencode --live' (default: local Ollama if present, else a free
                           hosted model), e.g. PF_OPENCODE_MODEL=opencode/big-pickle
  PF_PRIVILEGED_TESTS=1    test suite only: allow -m privileged tests (run under sudo)
  PF_LIVE_AGENT_TESTS=1    test suite only: allow -m live_agent tests (real agent sessions, consume quota)
  PF_BIN                   scripts/acceptance.sh only: executable to test
  The launcher removes LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, NODE_OPTIONS, BASH_ENV, SUDO_ASKPASS,
  SSH_AUTH_SOCK and similar from the agent's environment (policy.json env_drop / env_keep).""",
    "files": """\
FILES (all root-owned; never writable by your user)
  /etc/protect-folder/targets.json         the registry (schema v2; per-directory layers)
  /etc/protect-folder/srt-targets.json     generated policy input
  /etc/protect-folder/policy.json          inspection_mode (balanced|strict), default_profile, custom profiles,
                                           inspection limits, env_drop/env_keep, extra_write_paths
  /var/lib/protect-folder/                 snapshots (original owner/mode/ACL), transaction journals, lock (0700)
  /var/log/protect-folder/admin.log        administrative actions (root-written; never contains file contents)
  /usr/local/lib/protect-folder/           the installed code and the vendored node + sandbox-runtime (+ MANIFEST.json)
  /usr/local/bin/protect-folder            the launcher shim
  ~/.local/state/protect-folder/           per-user hook log and verification cache (best-effort, not tamper-proof)""",
    "safety": """\
WHAT THIS IS NOT
  It is NOT a defence against root, or against your own account if it can use sudo (cached sudo, passwordless sudo,
  membership of the docker/lxd/disk groups). 'protect-folder doctor' lists these paths. Run 'sudo -K' after
  administrative commands and never start an agent with sudo ('run' refuses to run as root).
  L2 is best-effort; the sandbox (L3) and root permissions (L4) are the guarantees.
  If a protected directory is missing, replaced, or no longer root-locked, 'run' refuses (fails closed).
  L4 protects the directory, not its name: if the PARENT is writable by the agent it can rename the entry.""",
}


def _profiles() -> str:
    from .policy.profiles import BUILTIN_PROFILES
    lines = ["NETWORK PROFILES (run --profile NAME, verify --profile NAME)",
             "  'run' is network-closed unless a profile allows hosts. There is no implicit allow-all."]
    for n, p in BUILTIN_PROFILES.items():
        hosts = ", ".join(p["allowedDomains"]) or "(none)"
        extra = "  [fixed in-sandbox relay]" if p.get("relays") else ""
        lines.append(f"  {n:<24} {hosts}{extra}")
        lines.append(f"  {'':<24} {p.get('description', '')}")
    lines.append("  Custom profiles: /etc/protect-folder/policy.json  {\"profiles\": {\"NAME\": {\"allowedDomains\": [...]}}}")
    lines.append("  Entries may be hostnames or IP:port literals; '*' is refused. Telemetry/MCP hosts agents also try are")
    lines.append("  intentionally blocked.")
    return "\n".join(lines)


def _exit_codes() -> str:
    lines = ["EXIT CODES AND REASON CODES",
             "  0 OK. When 'run' starts an agent, ITS exit status is returned (128+N when killed by signal N)."]
    for code, n in sorted(EXIT_CODES.items(), key=lambda kv: kv[1]):
        if code != "OK":
            lines.append(f"  {n:>3} {code}")
    lines.append("  Every command accepts --json: {schema, command, ok, reason_code, message, data, warnings[, hint]}.")
    return "\n".join(lines)


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    act = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return dict(act.choices)


def topic_names() -> list[str]:
    return list(TOPICS)


def render(what: str | None, parser: argparse.ArgumentParser) -> tuple[str, bool]:
    """(text, found). `what` is None (overview), a command, a topic, or 'all'."""
    subs = _subparsers(parser)
    if what is None:
        out = [f"protect-folder {VERSION}: keep local AI coding agents away from directories you choose.", "",
               "  protect-folder help COMMAND    options and examples of one command",
               "  protect-folder help TOPIC      a concept", "  protect-folder help all        everything on this page, in one go", "",
               "COMMANDS"]
        for n, sp in subs.items():
            first = next((c.help for c in next(a for a in parser._actions
                                               if isinstance(a, argparse._SubParsersAction))._choices_actions
                          if c.dest == n), "")
            out.append(f"  {n:<12} {first}")
        out += ["", "TOPICS  " + ", ".join(TOPICS), "",
                "Quick start:  sudo protect-folder add --dry-run DIR   then   sudo protect-folder add DIR",
                "              protect-folder list;  protect-folder verify;  protect-folder run -- claude"]
        return "\n".join(out), True
    if what == "all":
        parts = [render(None, parser)[0], "", "=" * 78, "COMMAND REFERENCE", "=" * 78]
        for n, sp in subs.items():
            parts += ["", f"--- protect-folder {n} " + "-" * max(4, 58 - len(n)), sp.format_help().rstrip()]
        for t in TOPICS:
            parts += ["", "=" * 78, render(t, parser)[0]]
        return "\n".join(parts), True
    if what in subs:
        return subs[what].format_help().rstrip(), True
    if what in TOPICS:
        if what == "profiles":
            return _profiles(), True
        if what == "exit-codes":
            return _exit_codes(), True
        return TOPICS[what], True
    return (f"no help for {what!r}. Commands: {', '.join(subs)}. Topics: {', '.join(TOPICS)}, all."), False
