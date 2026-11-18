import json
import os
import stat
import subprocess
import sys

import pytest

from protect_folder import admin
from protect_folder.adapters import by_name, detect
from protect_folder.adapters import claude as claude_mod
from protect_folder.adapters.claude import build_settings, escape_rule_path, permission_rules
from protect_folder.adapters.claude_verify import run_hook, verify_claude
from protect_folder.verify import cache


@pytest.fixture
def world(env, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    t1, t2 = env.mkdir("Forbidden folder"), env.mkdir("two", "[WIP] data*")
    for d in (t1, t2):
        (d / "secret.txt").write_text("S")
    env.install()
    for d in (t1, t2):
        assert admin.add(env.ctx, str(d), yes=True).ok
    env.is_root = False
    env.t1, env.t2 = t1, t2
    env.proj = tmp_path / "proj"
    env.proj.mkdir()
    return env


def ev(tool, ti, cwd):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti, "cwd": str(cwd)}


def test_permission_rules_escape_and_cover_dir_and_children():
    rules = permission_rules(["/mnt/a b/[x]*"])
    assert "Read(//mnt/a b/\\[x\\]\\*)" in rules and "Read(//mnt/a b/\\[x\\]\\*/**)" in rules
    assert "Edit(//mnt/a b/\\[x\\]\\*/**)" in rules
    assert escape_rule_path("a#b!c") == "a\\#b\\!c"


def test_settings_shape(world):
    s = build_settings(world.ctx, [str(world.t1)])
    hook = s["hooks"]["PreToolUse"][0]
    assert hook["matcher"] == "*" and hook["hooks"][0]["onFailure"] == "block"
    assert s["disableAllHooks"] is False
    assert "-I" in hook["hooks"][0]["command"] and "-S" in hook["hooks"][0]["command"]
    deny = s["permissions"]["deny"]
    assert any(r.startswith("Read(//") for r in deny) and "Bash(sudo *)" in deny and "Bash(pkexec:*)" in deny
    # hook-only / rules-only variants used by verify so a block is attributable
    assert "permissions" not in build_settings(world.ctx, [str(world.t1)], rules=False)
    assert "hooks" not in build_settings(world.ctx, [str(world.t1)], hook=False)


def test_detect_and_prepare_inserts_settings_after_command_word(world):
    assert detect("/usr/local/bin/claude").name == "claude" and by_name("claude").default_profile == "claude"
    reg_targets = __import__("protect_folder.registry", fromlist=["x"]).load(world.layout).sorted_targets()
    ad = by_name("claude")
    prep = ad.prepare(world.ctx, ["claude", "-p", "hi", "--", "x"], {"PATH": os.environ["PATH"]},
                      str(world.proj), reg_targets, {})
    assert prep.argv[0] == "claude" and prep.argv[1] == "--settings" and prep.argv[3:] == ["-p", "hi", "--", "x"]
    f = prep.argv[2]
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600 and f in prep.cleanup
    doc = json.load(open(f))
    assert any("Forbidden folder" in r for r in doc["permissions"]["deny"])
    # nothing is claimed that has not been verified
    assert prep.layers == {"native_permissions": "UNVERIFIED", "pre_execution_hook": "UNVERIFIED"}
    os.unlink(f)


def test_layers_come_from_cache_and_go_stale(world, monkeypatch):
    reg = __import__("protect_folder.registry", fromlist=["x"]).load(world.layout)
    ad = by_name("claude")
    monkeypatch.setattr(claude_mod, "agent_version", lambda env=None: "2.1.327 (Claude Code)")
    cache.store("claude", {"policy_revision": reg.policy_revision, "agent_version": "2.1.327 (Claude Code)",
                           "layers": {"native_permissions": "PASS", "pre_execution_hook": "PASS"}})
    got = ad.cached_layers(world.ctx, reg.sorted_targets(), {})
    assert got == {"native_permissions": "PASS", "pre_execution_hook": "PASS"}
    monkeypatch.setattr(claude_mod, "agent_version", lambda env=None: "2.1.999 (Claude Code)")
    got = ad.cached_layers(world.ctx, reg.sorted_targets(), {})
    assert got == {"native_permissions": "STALE", "pre_execution_hook": "STALE"}


# ---- the real hook script, run as Claude would run it ----------------------------------------------
def test_hook_blocks_and_allows_through_the_real_script(world):
    (world.proj / "evil.py").write_text(f"print(open({str(world.t1 / 'secret.txt')!r}).read())\n")
    rc, err = run_hook(world.ctx, ev("Bash", {"command": "python3 evil.py"}, world.proj), [])
    assert rc == 2 and "Protected directory" in err and "secret" not in err.lower().replace("secret.txt", "")
    assert run_hook(world.ctx, ev("Read", {"file_path": str(world.t2 / "secret.txt")}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("Bash", {"command": "sudo ls"}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("Bash", {"command": "ls && git status"}, world.proj), [])[0] == 0
    assert run_hook(world.ctx, ev("Read", {"file_path": str(world.proj / "a.txt")}, world.proj), [])[0] == 0
    assert run_hook(world.ctx, ev("Bash", {"command": "ls"}, world.proj), [str(world.proj)])[0] == 0
    assert run_hook(world.ctx, ev("Bash", {"command": f"ls {world.proj}"}, world.proj), [str(world.proj)])[0] == 2


@pytest.mark.parametrize("raw", [b"", b"{", b"[1]", b"null", b'{"tool_name": ""}', b'"str"', b"\xff\xfe"])
def test_hook_fails_closed_on_bad_input(world, raw):
    assert run_hook(world.ctx, None, [], raw=raw)[0] == 2


def test_hook_fails_closed_on_untrusted_or_missing_state(world):
    event = ev("Bash", {"command": "ls"}, world.proj)
    assert run_hook(world.ctx, event, [])[0] == 0
    os.chmod(world.layout.targets_file, 0o666)                       # tampered: group/world writable
    assert run_hook(world.ctx, event, [])[0] == 2
    os.chmod(world.layout.targets_file, 0o644)
    assert run_hook(world.ctx, event, [])[0] == 0
    world.layout.marker_file.write_text("{}")                        # pending recovery
    assert run_hook(world.ctx, event, [])[0] == 2
    world.layout.marker_file.unlink()
    world.layout.targets_file.write_text("{ not json")
    assert run_hook(world.ctx, event, [])[0] == 2
    world.layout.targets_file.unlink()
    assert run_hook(world.ctx, event, [])[0] == 2


def test_hook_rejects_unknown_arguments_and_logs_without_content(world, tmp_path):
    cmd = ["/usr/bin/python3", "-I", "-S", str(claude_mod.hook_path()), "--bogus"]
    p = subprocess.run(cmd, input=b"{}", capture_output=True)
    assert p.returncode == 2
    run_hook(world.ctx, ev("Bash", {"command": f"cat '{world.t1}/secret.txt'"}, world.proj), [])
    log = (__import__("pathlib").Path(__import__("tempfile").gettempdir()) / "protect-folder" / "hook.log")
    if log.exists():
        body = log.read_text()
        assert "secret.txt" not in body and "Forbidden folder" not in body


# ---- verification model ------------------------------------------------------------------------------
def test_offline_verify_is_honest_without_live_run(world):
    res = verify_claude(world.ctx, None, live=False)
    names = {c["name"]: c for c in res["pre_execution_hook"]["checks"]}
    for n in ("hook_denies_direct_bash", "hook_denies_forbidden_script", "hook_denies_sudo", "hook_denies_read_tool",
              "hook_allows_safe_command", "hook_allows_safe_read", "hook_fails_closed_on_garbage_input"):
        assert names[n]["status"] == "PASS", names[n]
    # but no PASS for the layers: the real agent has not been observed
    assert res["pre_execution_hook"]["status"] == "UNVERIFIED" and res["native_permissions"]["status"] == "UNVERIFIED"


# ---- real claude ---------------------------------------------------------------------------------------
@pytest.mark.live_agent
def test_live_claude_verification_with_real_sessions(world):
    res = verify_claude(world.ctx, None, live=True)
    dump = json.dumps(res, indent=1)
    assert res["native_permissions"]["status"] == "PASS", dump
    assert res["pre_execution_hook"]["status"] == "PASS", dump
