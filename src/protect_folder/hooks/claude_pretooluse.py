"""PreToolUse hook (L2) shared by the Claude Code settings hook and the OpenCode plugin (same event shape:
tool_name, tool_input, cwd). Run as:  python3 -I -S <this file> [--agent NAME] [--etc DIR --trusted-uid N]

Contract with Claude Code: exit 0 = no objection; exit 2 = block the tool call, stderr is shown to the
model. This hook FAILS CLOSED: any exception, unreadable/untrusted policy, malformed input or pending
recovery results in exit 2. (The adapter additionally sets onFailure=block so that a hook which cannot
even start, e.g. a missing interpreter, also blocks.)

Best-effort audit log: ~/.local/state/protect-folder/hook.log. It lives in a user-writable location and
is NOT tamper-proof. It records tool name, verdict and reason code only; never commands, paths or source."""

from __future__ import annotations

import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
# <lib>/protect_folder/hooks/this_file -> put <lib> (never <lib>/protect_folder: its `inspect`
# subpackage would shadow the standard library module of the same name) on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))

MAX_INPUT = 8 * 1024 * 1024
_AGENT = "claude"


def _log(tool: str, verdict: str, codes: list[str], target_id: str | None, agent: str = "claude") -> None:
    try:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = os.path.join(base, "protect-folder")      # same location as protect_folder.userstate.state_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "layer": "L2", "agent": agent,
               "tool": tool[:64], "verdict": verdict, "codes": codes[:8], "target_id": target_id}
        with open(os.path.join(d, "hook.log"), "a") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    except Exception:
        pass


def _block(msg: str) -> int:
    sys.stderr.write("protect-folder: " + msg + "\n")
    return 2


def _layout(argv: list[str]):
    """Returns (layout, extra_targets). --extra-target only ever ADDS protected paths (used by
    `verify` for its synthetic fixture), so it cannot weaken a policy."""
    from protect_folder.constants import Layout
    from pathlib import Path
    etc = None
    uid = 0
    extra: list[str] = []
    global _AGENT
    i = 0
    while i < len(argv):
        if argv[i] == "--etc" and i + 1 < len(argv):
            etc = argv[i + 1]
            i += 2
        elif argv[i] == "--trusted-uid" and i + 1 < len(argv):
            uid = int(argv[i + 1])
            i += 2
        elif argv[i] == "--agent" and i + 1 < len(argv):
            _AGENT = argv[i + 1][:32]
            i += 2
        elif argv[i] == "--extra-target" and i + 1 < len(argv):
            extra.append(os.path.normpath(argv[i + 1]))
            i += 2
        else:
            raise ValueError(f"unknown argument {argv[i]!r}")
    return (Layout() if etc is None else Layout(etc_dir=Path(etc), trusted_uid=uid)), extra


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    tool = "?"
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            return _block("hook input too large; blocked (fail-closed)")
        event = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(event, dict):
            return _block("malformed hook input; blocked (fail-closed)")
        if event.get("hook_event_name") not in (None, "PreToolUse"):
            return 0
        raw_tool = event.get("tool_name")
        if not isinstance(raw_tool, str) or not raw_tool:
            return _block("hook input lacks a string tool_name; blocked (fail-closed)")
        tool = raw_tool
        if event.get("tool_input") is not None and not isinstance(event.get("tool_input"), dict):
            return _block("hook input tool_input is not an object; blocked (fail-closed)")

        from protect_folder import registry
        from protect_folder.inspect.engine import Inspector, InspectPolicy, ProtectedPath, ScanCache
        from protect_folder.policy.config import load_policy

        layout, extra = _layout(argv)
        if layout.marker_file.exists():
            return _block("a protect-folder transaction is pending (RECOVERY_REQUIRED); blocked (fail-closed)")
        if not layout.targets_file.exists():
            return _block("the protect-folder registry is missing; blocked (fail-closed)")
        reg = registry.load(layout)                       # verifies ownership/mode: TAMPERED -> exception
        pol = load_policy(layout)
        ip = InspectPolicy(
            tuple(ProtectedPath(t.id, t.canonical_path) for t in reg.with_layer("pre_execution_hook"))
            + tuple(ProtectedPath(f"extra{i}", p) for i, p in enumerate(extra)),
            pol["inspection_mode"], int(pol["inspection"]["max_source_bytes"]),
            float(pol["inspection"]["max_seconds"]), reg.policy_revision, os.path.expanduser("~"))
        cwd = event.get("cwd") or os.getcwd()
        decision = Inspector(ip, ScanCache()).inspect(tool, event.get("tool_input") or {}, str(cwd))
        _log(tool, decision.verdict, decision.codes or decision.incomplete, decision.target_id, _AGENT)
        if decision.blocked:
            return _block(decision.reason)
        return 0
    except BaseException as exc:                           # noqa: BLE001 - fail closed on anything
        _log(tool, "ERROR", [type(exc).__name__], None, _AGENT)
        return _block(f"hook error ({type(exc).__name__}); blocked (fail-closed)")


if __name__ == "__main__":
    sys.exit(main())
