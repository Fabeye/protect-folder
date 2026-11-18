"""Claude Code adapter.

L1: `permissions.deny` rules (Read/Edit on each protected path) plus denies for privilege-escalation
    commands, passed through `claude --settings <private file>`.
L2: a PreToolUse hook (matcher "*") with onFailure=block, running the shared inspection engine.
Both are advisory-by-nature (same user, can be altered by whatever can edit the settings): the
adapter therefore reports them as PASS only after `verify --agent claude --live` observed them
blocking real tool calls. L3/L4 remain the enforcement layers."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .base import Adapter, Prepared, UNVERIFIED

ELEVATION_DENIES = ["Bash(sudo:*)", "Bash(su:*)", "Bash(pkexec:*)", "Bash(doas:*)", "Bash(sudo *)",
                    "Bash(su *)", "Bash(pkexec *)", "Bash(doas *)"]
GITIGNORE_SPECIAL = re.compile(r"([\\*?\[\]!#])")


def escape_rule_path(path: str) -> str:
    """Claude path rules use gitignore syntax: escape glob specials so a literal name stays literal."""
    return GITIGNORE_SPECIAL.sub(r"\\\1", path)


def permission_rules(paths: list[str]) -> list[str]:
    rules: list[str] = []
    for p in paths:
        e = "//" + escape_rule_path(p.lstrip("/"))           # '//abs' = absolute filesystem path
        for tool in ("Read", "Edit"):
            rules.append(f"{tool}({e})")
            rules.append(f"{tool}({e}/**)")
    return rules


def hook_path() -> Path:
    return Path(__file__).resolve().parent.parent / "hooks" / "claude_pretooluse.py"


def build_settings(ctx: Any, paths: list[str], *, hook: bool = True, rules: bool = True,
                   extra_targets: list[str] | None = None, hook_command: str | None = None) -> dict[str, Any]:
    lo = ctx.layout
    cmd = ["/usr/bin/python3", "-I", "-S", str(hook_path())]
    if str(lo.etc_dir) != "/etc/protect-folder":
        cmd += ["--etc", str(lo.etc_dir), "--trusted-uid", str(lo.trusted_uid)]
    for t in extra_targets or []:
        cmd += ["--extra-target", t]
    command = hook_command or " ".join(_shq(c) for c in cmd)
    out: dict[str, Any] = {"disableAllHooks": False}
    if rules:
        out["permissions"] = {"deny": permission_rules(paths) + ELEVATION_DENIES}
    if hook:
        out["hooks"] = {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": command, "timeout": 10, "onFailure": "block"}]}]}
    return out


def _shq(s: str) -> str:
    import shlex
    return shlex.quote(s)


class ClaudeAdapter(Adapter):
    name = "claude"
    default_profile = "claude"
    description = "Claude Code: L1 permissions.deny + L2 PreToolUse hook (onFailure=block), L3, L4"
    commands = ("claude",)

    def state_dirs(self, home: str) -> list[str]:
        return [os.path.join(home, ".claude"), os.path.join(home, ".claude.json"),
                os.path.join(home, ".local", "state", "protect-folder"),
                os.path.join(home, ".config", "claude"), os.path.join(home, ".cache", "claude")]

    def agent_version(self, env=None) -> str | None:
        return agent_version(env)

    def verify(self, ctx: Any, reg: Any, profile: str | None, live: bool = False,
               enabled: dict[str, bool] | None = None) -> dict[str, dict[str, Any]]:
        from .claude_verify import verify_claude
        return verify_claude(ctx, reg, live, enabled)

    def capabilities(self, ctx: Any) -> dict[str, str]:
        return {"native_permissions": UNVERIFIED, "pre_execution_hook": UNVERIFIED}

    def prepare(self, ctx, argv, env, workspace, targets, policy) -> Prepared:
        # per-directory layer selection: L1 rules only for directories that enable agent_permissions;
        # the hook is installed only if some directory enables pre_execution_hook (it then reads the
        # registry itself and inspects only those directories)
        paths = [t.canonical_path for t in targets if t.layers["agent_permissions"]]
        settings = build_settings(ctx, paths, hook=any(t.layers["pre_execution_hook"] for t in targets),
                                  rules=bool(paths))
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        base = xdg if xdg and os.path.isdir(xdg) else None
        fd, path = tempfile.mkstemp(prefix="pf-claude-", suffix=".json", dir=base)
        with os.fdopen(fd, "w") as fh:
            json.dump(settings, fh, sort_keys=True)
        os.chmod(path, 0o600)
        out = list(argv)
        # insert right after the command word so user arguments (and any `--`) keep their meaning
        out[1:1] = ["--settings", path]
        warnings: list[str] = []
        if any(a in ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions") for a in argv):
            warnings.append("--dangerously-skip-permissions disables L1 prompts; L1 deny rules still apply "
                            "only if Claude honours them in that mode (verify it); L2 hook, L3 and L4 are unaffected")
        return Prepared(argv=out, env=dict(env), layers=self.cached_layers(ctx, targets, env),
                        warnings=warnings, cleanup=[path])


def agent_version(env: dict[str, str] | None = None) -> str | None:
    exe = shutil.which("claude", path=(env or os.environ).get("PATH"))
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out or None
