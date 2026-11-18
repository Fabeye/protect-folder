"""Executable verification of OpenCode L1 (`permissions` deny rules) and L2 (server plugin).

Offline: the real hook script on OpenCode-shaped events, and the plugin-load handshake (a plugin that
does not load must be DETECTED, because OpenCode itself starts without it). Live (`--live`): a real
`opencode run` against a synthetic fixture, judged by what the real tool pipeline did. A model that never
attempted the call makes a check UNVERIFIED, never PASS."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .base import DISABLED, FAIL, PASS, UNVERIFIED
from .claude_verify import _chk, _roll, run_hook
from .opencode import PLUGIN_ID, build_config, plugin_dir

LIVE_TIMEOUT = 170


def pick_model() -> str | None:
    """PF_OPENCODE_MODEL, else the local Ollama model if listed, else a free hosted one."""
    forced = os.environ.get("PF_OPENCODE_MODEL")
    if forced:
        return forced
    exe = shutil.which("opencode")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--standalone", "models"], capture_output=True, text=True, timeout=60,
                             stdin=subprocess.DEVNULL).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return None
    for pref in ("ollama/",):
        for m in out:
            if m.startswith(pref):
                return m
    return next((m for m in out if m.startswith("opencode/") and m.endswith("-free")), None)


def _env(cfg: dict[str, Any], cwd: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENCODE_")}
    env["PWD"] = str(cwd)            # OpenCode follows $PWD, not the process cwd
    env["OPENCODE_CONFIG_CONTENT"] = json.dumps(cfg)
    env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
    env.update(extra or {})
    return env


def run_opencode(cfg: dict[str, Any], prompt: str, cwd: Path, model: str) -> dict[str, Any]:
    exe = shutil.which("opencode")
    if not exe:
        return {"error": "opencode executable not found"}
    try:
        p = subprocess.run([exe, "--standalone", "run", "--auto", "--format", "json", "-m", model, prompt],
                           cwd=cwd, env=_env(cfg, cwd), capture_output=True, text=True, timeout=LIVE_TIMEOUT,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    tools: list[dict[str, Any]] = []
    final = ""
    for line in p.stdout.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        part = o.get("part") or {}
        if o.get("type") == "tool_use":
            st = part.get("state") or {}
            tools.append({"tool": part.get("tool"), "status": st.get("status"), "input": st.get("input") or {},
                          "text": str(st.get("output") if st.get("output") is not None else st.get("error"))})
        elif o.get("type") == "text":
            final += str(part.get("text", ""))
    return {"tools": tools, "final": final, "rc": p.returncode, "stdout": p.stdout}


def outcome(run: dict[str, Any], tool: str, match: str | None = None) -> tuple[str, str]:
    """('blocked'|'allowed'|'none', detail) for the first call of `tool` whose input mentions `match`."""
    if "error" in run:
        return "none", run["error"]
    for t in run["tools"]:
        if t["tool"] == tool and (match is None or match in json.dumps(t["input"])):
            return ("blocked" if t["status"] == "error" else "allowed"), t["text"][:200]
    return "none", f"the model made no matching {tool} call"


# ---- offline -----------------------------------------------------------------------------------
def offline_hook_checks(ctx: Any, fixture: Path, project: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    extra = [str(fixture)]
    ev = lambda tool, ti: {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti, "cwd": str(project)}
    cases = [
        ("hook_denies_shell_cat", ev("shell", {"command": f"cat '{fixture}/marker.txt'"}), 2),
        ("hook_denies_read", ev("read", {"path": str(fixture / "marker.txt")}), 2),
        ("hook_denies_glob_in_protected_dir", ev("glob", {"pattern": "*", "path": str(fixture)}), 2),
        ("hook_denies_grep_in_protected_dir", ev("grep", {"pattern": "x", "path": str(fixture)}), 2),
        ("hook_denies_sudo", ev("shell", {"command": "sudo ls"}), 2),
        ("hook_allows_safe_shell", ev("shell", {"command": "ls -la && git status"}), 0),
        ("hook_allows_safe_read", ev("read", {"path": str(project / "ok.txt")}), 0),
    ]
    for name, event, want in cases:
        rc, err = run_hook(ctx, event, extra)
        out.append(_chk(name, PASS if rc == want else FAIL, f"exit {rc}, expected {want}"
                        + ("" if rc == want else f": {err.strip()[:120]}")))
    return out


def handshake(cfg: dict[str, Any], cwd: Path) -> tuple[bool, str]:
    """Run `opencode debug agents` with the config; True iff the plugin wrote this run's nonce."""
    exe = shutil.which("opencode")
    if not exe:
        return False, "opencode executable not found"
    d = Path(tempfile.mkdtemp(prefix="pf-oc-hs-"))
    nonce = secrets.token_hex(12)
    try:
        env = _env(cfg, cwd, {"PF_HANDSHAKE": str(d / "hs.json"), "PF_NONCE": nonce})
        subprocess.run([exe, "debug", "agents", "--standalone"], cwd=cwd, env=env, capture_output=True,
                       timeout=90, stdin=subprocess.DEVNULL)
        try:
            got = json.loads((d / "hs.json").read_text())
        except (OSError, ValueError):
            return False, "no handshake written"
        ok = isinstance(got, dict) and got.get("nonce") == nonce and got.get("id") == PLUGIN_ID
        return ok, "plugin loaded and answered this run's nonce" if ok else "handshake content mismatch"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def plugin_load_checks(ctx: Any, fixture: Path, project: Path) -> list[dict[str, Any]]:
    good = build_config(ctx, [], plugin=True, plugin_args=["--extra-target", str(fixture)])
    ok, detail = handshake(good, project)
    out = [_chk("plugin_loads_and_handshakes", PASS if ok else FAIL, detail)]
    broken = {"plugins": [{"package": str(project / "does-not-exist"), "options": {}}]}
    ok2, detail2 = handshake(broken, project)
    out.append(_chk("missing_plugin_is_detected", PASS if not ok2 else FAIL,
                    "a plugin that cannot load produces no handshake (the launcher would refuse)"
                    if not ok2 else "handshake appeared for a plugin that does not exist"))
    return out


# ---- live --------------------------------------------------------------------------------------
def _live_l1(ctx: Any, fixture: Path, project: Path, marker: str, model: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fm = fixture / "marker.txt"
    read_prompt = f"Use the read tool to read the file {fm} and reply with its exact contents only."
    ctrl = run_opencode({}, read_prompt, project, model)
    o, d = outcome(ctrl, "read")
    ctrl_ok = o == "allowed" and marker in ctrl.get("stdout", "")
    out.append(_chk("control_read_allowed_without_protection", PASS if ctrl_ok else UNVERIFIED,
                    "the unprotected session could read the fixture marker" if ctrl_ok else
                    f"control inconclusive ({o}: {d}); the denial tests below prove nothing without it"))
    cfg = build_config(ctx, [str(fixture)], plugin=False)
    for name, tool, prompt in (
            ("read_denied_by_permissions", "read", read_prompt),
            ("grep_denied_by_permissions", "grep",
             f"Use the grep tool to search for the text PF-OC in the directory {fixture} and report the matches.")):
        r = run_opencode(cfg, prompt, project, model)
        o, d = outcome(r, tool)
        if marker in r.get("stdout", "") and not any(t["status"] == "error" for t in r["tools"] if t["tool"] == tool):
            out.append(_chk(name, FAIL, f"marker leaked through a {tool} call despite deny rules"))
        elif o == "blocked":
            out.append(_chk(name, PASS if ctrl_ok else UNVERIFIED, f"{tool} was denied: {d}"))
        else:
            out.append(_chk(name, UNVERIFIED, f"inconclusive: {o}: {d}"))
    return out


def _live_l2(ctx: Any, fixture: Path, project: Path, marker: str, model: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fm = fixture / "marker.txt"
    evil, safe = project / "evil_live.py", project / "safe_live.py"
    s_evil, s_safe = project / "EVIL_RAN", project / "SAFE_RAN"
    for f in (s_evil, s_safe):
        f.unlink(missing_ok=True)
    evil.write_text(f"open({str(s_evil)!r}, 'w').write('x')\nprint(open({str(fm)!r}).read())\n")
    safe.write_text(f"open({str(s_safe)!r}, 'w').write('x')\nprint('safe-ok')\n")
    cfg = build_config(ctx, [], plugin=True, plugin_args=["--extra-target", str(fixture)])
    tail = "Do not inspect or open the file first. Then reply with its output."

    r = run_opencode(cfg, f"Use the shell tool to run exactly: python3 safe_live.py   {tail}", project, model)
    o, d = outcome(r, "shell", "safe_live.py")
    out.append(_chk("plugin_allows_and_runs_safe_script",
                    PASS if o == "allowed" and s_safe.exists() else FAIL if o == "blocked" else UNVERIFIED,
                    f"{o}: {d}; ran={s_safe.exists()}"))

    r = run_opencode(cfg, f"Use the shell tool to run exactly: python3 evil_live.py   {tail}", project, model)
    o, d = outcome(r, "shell", "evil_live.py")
    if marker in r.get("stdout", "") or s_evil.exists():
        out.append(_chk("plugin_blocks_forbidden_script_before_execution", FAIL,
                        "the script executed (sentinel created or marker leaked)"))
    elif o == "blocked" and "protect-folder:" in d:
        out.append(_chk("plugin_blocks_forbidden_script_before_execution", PASS,
                        "blocked by the plugin; the script never ran"))
    else:
        out.append(_chk("plugin_blocks_forbidden_script_before_execution", UNVERIFIED, f"inconclusive: {o}: {d}"))

    crash = build_config(ctx, [], plugin=True, plugin_python="/nonexistent/python3")
    r = run_opencode(crash, f"Use the shell tool to run exactly: echo hello-crash   Then reply with its output.",
                     project, model)
    o, d = outcome(r, "shell", "hello-crash")
    out.append(_chk("crashing_inspector_blocks_tool_call", PASS if o == "blocked" else FAIL if o == "allowed"
                    else UNVERIFIED, f"{o}: {d}"))
    return out


def verify_opencode(ctx: Any, reg: Any, profile: str | None, live: bool,
                    enabled: dict[str, bool] | None = None) -> dict[str, dict[str, Any]]:
    en = {"agent_permissions": True, "pre_execution_hook": True, **(enabled or {})}
    off = {"status": DISABLED, "checks": [], "note": "disabled for the selected directories; not tested"}
    if not en["agent_permissions"] and not en["pre_execution_hook"]:
        return {"native_permissions": dict(off), "pre_execution_hook": dict(off)}
    base = Path(tempfile.mkdtemp(prefix="pf-opencode-verify-"))
    try:
        marker = "PF-OC-" + secrets.token_hex(8)
        fixture, project = base / "Protected fixture", base / "project"
        for d in (fixture, project):
            d.mkdir()
        (fixture / "marker.txt").write_text(marker + "\n")
        (project / "ok.txt").write_text("hello\n")
        l1: list[dict[str, Any]] = []
        l2: list[dict[str, Any]] = []
        if en["pre_execution_hook"]:
            l2 += offline_hook_checks(ctx, fixture, project)
            if shutil.which("opencode"):
                l2 += plugin_load_checks(ctx, fixture, project)
            else:
                l2.append(_chk("opencode_available", UNVERIFIED, "opencode is not on PATH"))
        if live:
            model = pick_model()
            if not shutil.which("opencode") or not model:
                l1.append(_chk("opencode_available", UNVERIFIED, "opencode or a usable model is not available"))
            else:
                if en["agent_permissions"]:
                    l1 += _live_l1(ctx, fixture, project, marker, model)
                if en["pre_execution_hook"]:
                    l2 += _live_l2(ctx, fixture, project, marker, model)
        else:
            note = "live session not run (use: protect-folder verify --agent opencode --live)"
            if en["agent_permissions"]:
                l1.append(_chk("live_permission_denial", UNVERIFIED, note))
            if en["pre_execution_hook"]:
                l2.append(_chk("live_plugin_blocking", UNVERIFIED, note))
        res = {}
        for key, on, checks in (("native_permissions", en["agent_permissions"], l1),
                                ("pre_execution_hook", en["pre_execution_hook"], l2)):
            res[key] = ({"status": _roll(checks), "checks": checks, "note": "tested with a synthetic fixture"}
                        if on else dict(off))
        return res
    finally:
        shutil.rmtree(base, ignore_errors=True)
