"""Codex CLI adapter: L3 (SRT) + L4 only. L1 and L2 are reported UNSUPPORTED, never faked.

Evidence (codex-cli 0.159.3, checked against the current docs and by experiment):
  * L2: Codex hooks exist, but they can only be defined in hooks.json/config.toml files (no per-launch
    injection is documented) behind a trust-review step, the docs state a hook error or malformed output lets
    the tool run (fail-open) and call hooks "a useful guardrail, not a complete enforcement boundary", and file
    reads are not a covered tool. That cannot meet this project's fail-closed requirement.
  * L1: permission profiles support `deny` paths, but they are enforced by Codex's own bubblewrap sandbox, which
    cannot start inside SRT (verified: "bwrap: No permissions to create new namespace"). With it disabled there
    is nothing to enforce the profile.
  * Therefore Codex runs with `--sandbox danger-full-access` INSIDE SRT, so SRT (L3) provides the isolation
    (verified: a protected path is invisible to a real `codex exec` and to the interactive TUI under SRT).
  * Codex has a shared app-server daemon and `--remote` mode; sessions attached to a daemon outside the
    sandbox are not confined by this launcher, so those modes are refused."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from ..errors import ProtectError
from .base import Adapter, Prepared, UNSUPPORTED

REFUSED_SUBCOMMANDS = {
    "app-server": "it starts or attaches to the shared app-server daemon, which runs outside the sandbox",
    "remote-control": "it manages the app-server daemon, which runs outside the sandbox",
    "exec-server": "it starts a standalone exec server that is not confined by this launcher",
    "agents": "it browses sessions on the shared app-server daemon",
}
REFUSED_FLAGS = ("--remote", "--remote-auth-token-env")
SANDBOX_FLAGS = ("-s", "--sandbox", "--dangerously-bypass-approvals-and-sandbox", "--yolo", "--full-auto")
# subcommands whose own option list accepts -s (so the flag must follow the subcommand word)
EXEC_LIKE = {"exec", "e", "review"}
VALUE_FLAGS = {"-c", "--config", "-m", "--model", "-p", "--profile", "-C", "--cd", "-i", "--image",
               "-s", "--sandbox", "-a", "--ask-for-approval", "--local-provider", "--enable", "--disable"}


def first_subcommand(argv: list[str]) -> tuple[int | None, str | None]:
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return None, None
        if a.startswith("-"):
            i += 2 if (a in VALUE_FLAGS and "=" not in a) else 1
            continue
        return i, a
    return None, None


class CodexAdapter(Adapter):
    name = "codex"
    default_profile = "codex"
    description = ("Codex CLI: L3 + L4 only; L1/L2 UNSUPPORTED (own sandbox cannot nest in SRT, hooks are "
                   "fail-open and not injectable); runs --sandbox danger-full-access inside SRT")
    commands = ("codex",)

    def state_dirs(self, home: str) -> list[str]:
        return [os.path.join(home, ".codex"), os.path.join(home, ".cache", "codex"),
                os.path.join(home, ".local", "state", "protect-folder")]

    def agent_version(self, env=None) -> str | None:
        exe = shutil.which("codex", path=(env or os.environ).get("PATH"))
        if not exe:
            return None
        try:
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30,
                                 stdin=subprocess.DEVNULL).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out or None

    def capabilities(self, ctx: Any) -> dict[str, str]:
        return {"native_permissions": UNSUPPORTED, "pre_execution_hook": UNSUPPORTED}

    def prepare(self, ctx, argv, env, workspace, targets, policy) -> Prepared:
        for a in argv[1:]:
            if a == "--":
                break
            if a in REFUSED_FLAGS or any(a.startswith(f + "=") for f in REFUSED_FLAGS):
                raise ProtectError("PREFLIGHT_FAILED",
                                   f"refusing {a.split('=')[0]}: the session would run on a server outside the sandbox",
                                   hint="Run codex without --remote; protect-folder confines the local process.")
        idx, sub = first_subcommand(argv)
        if sub in REFUSED_SUBCOMMANDS:
            raise ProtectError("PREFLIGHT_FAILED", f"refusing 'codex {sub}': {REFUSED_SUBCOMMANDS[sub]}",
                               hint="Use 'codex' or 'codex exec' (a local process confined by SRT).")
        out = list(argv)
        warnings = ["codex: L1 (permissions) and L2 (hooks) are UNSUPPORTED for this agent; protection comes from "
                    "L3 (SRT) and L4 (Linux permissions) only"]
        explicit = [a for a in argv[1:] if a == "--" or a in SANDBOX_FLAGS or a.startswith("--sandbox=")]
        explicit = explicit[:explicit.index("--")] if "--" in explicit else explicit
        if not explicit:
            pos = idx + 1 if (idx is not None and sub in EXEC_LIKE) else 1
            out[pos:pos] = ["--sandbox", "danger-full-access"]
            warnings.append("codex: started with --sandbox danger-full-access INSIDE the SRT sandbox, because Codex's "
                            "own sandbox cannot nest in SRT; SRT provides the isolation")
        else:
            warnings.append("codex: an explicit sandbox option was given; Codex's own sandbox cannot start inside "
                            "SRT, so shell commands may fail (use --sandbox danger-full-access; SRT still confines)")
        if any(t.layers["agent_permissions"] or t.layers["pre_execution_hook"] for t in targets):
            warnings.append("codex: the agent_permissions/pre_execution_hook layers enabled on a protected directory "
                            "cannot be applied to Codex (UNSUPPORTED)")
        return Prepared(argv=out, env=dict(env),
                        layers={"native_permissions": UNSUPPORTED, "pre_execution_hook": UNSUPPORTED},
                        warnings=warnings)
