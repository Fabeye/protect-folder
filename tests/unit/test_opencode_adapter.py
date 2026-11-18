import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from protect_folder import admin, registry
from protect_folder.adapters import by_name, detect
from protect_folder.adapters import opencode as oc
from protect_folder.adapters.base import DISABLED, UNVERIFIED
from protect_folder.adapters.claude_verify import run_hook
from protect_folder.adapters.opencode_verify import (handshake, offline_hook_checks, outcome,
                                                     plugin_load_checks, verify_opencode)
from protect_folder.errors import ProtectError
from protect_folder.verify import cache

HAVE_OPENCODE = shutil.which("opencode") is not None


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


def set_layers(world, path, changes):
    world.is_root = True
    try:
        assert admin.set_layers(world.ctx, str(path), changes, yes=True).ok
    finally:
        world.is_root = False


def targets(world):
    return registry.load(world.layout).sorted_targets()


def prep(world, argv, env=None, tg=None):
    return by_name("opencode").prepare(world.ctx, argv, {"PATH": os.environ["PATH"], **(env or {})},
                                       str(world.proj), tg if tg is not None else targets(world), {})


def cfg_of(p):
    return json.loads(p.env["OPENCODE_CONFIG_CONTENT"])


# ---- rules -----------------------------------------------------------------------------------------
def test_permission_rules_cover_dir_and_children_for_every_action():
    rules = oc.permission_rules(["/mnt/a b/[x]*"])
    for action in ("read", "edit", "external_directory"):
        assert {"action": action, "resource": "/mnt/a b/[x]*", "effect": "deny"} in rules
        assert {"action": action, "resource": "/mnt/a b/[x]*/*", "effect": "deny"} in rules
    assert {"action": "shell", "resource": "sudo *", "effect": "deny"} in rules
    assert all(r["effect"] == "deny" for r in rules)


def test_detect_and_defaults():
    ad = detect("/home/u/.nvm/bin/opencode")
    assert ad.name == "opencode" and ad.default_profile == "opencode-local-ollama"


# ---- launch preparation -------------------------------------------------------------------------------
def test_prepare_forces_standalone_and_injects_config(world):
    p = prep(world, ["opencode", "run", "hi there"])
    assert p.argv == ["opencode", "--standalone", "run", "hi there"]
    assert p.env["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
    cfg = cfg_of(p)
    res = [r["resource"] for r in cfg["permissions"]]
    assert str(world.t1) in res and str(world.t2) in res           # literal, with spaces/glob characters
    assert cfg["plugins"][0]["package"] == str(oc.plugin_dir())
    opts = cfg["plugins"][0]["options"]
    assert opts["python"] == "/usr/bin/python3" and Path(opts["hook"]).is_file()
    assert any("opencode.jsonc" in w for w in p.warnings)
    assert p.layers == {"native_permissions": UNVERIFIED, "pre_execution_hook": UNVERIFIED}


def test_prepare_does_not_duplicate_standalone(world):
    p = prep(world, ["opencode", "--standalone", "run", "x"])
    assert p.argv.count("--standalone") == 1


@pytest.mark.parametrize("argv", [["opencode", "--server", "http://x:1", "run", "a"],
                                  ["opencode", "--server=http://x:1"],
                                  ["opencode", "run", "--server", "http://x:1", "a"],
                                  ["opencode", "service"], ["opencode", "attach", "http://x"],
                                  ["opencode", "serve"], ["opencode", "web"]])
def test_prepare_refuses_server_modes(world, argv):
    with pytest.raises(ProtectError) as e:
        prep(world, argv)
    assert e.value.code == "PREFLIGHT_FAILED"


def test_server_word_after_double_dash_is_just_text(world):
    p = prep(world, ["opencode", "run", "--", "service", "--server"])
    assert p.argv[:3] == ["opencode", "--standalone", "run"]


def test_user_config_content_is_kept_and_ours_wins_by_position(world):
    user = {"theme": "x", "permissions": [{"action": "read", "resource": "*", "effect": "allow"}],
            "plugins": ["other-plugin", {"package": "/x/y", "options": {}}]}
    cfg = cfg_of(prep(world, ["opencode", "run"], {"OPENCODE_CONFIG_CONTENT": json.dumps(user)}))
    assert cfg["theme"] == "x"
    assert cfg["permissions"][0] == user["permissions"][0]          # theirs first ...
    last_read_deny = max(i for i, r in enumerate(cfg["permissions"]) if r["effect"] == "deny")
    assert last_read_deny > 0                                       # ... ours after (last match wins)
    assert cfg["plugins"][:2] == user["plugins"] and cfg["plugins"][-1]["options"]["hook"]


@pytest.mark.parametrize("bad", ["not json", "[1,2]", '"s"'])
def test_prepare_refuses_unparseable_user_config(world, bad):
    with pytest.raises(ProtectError):
        prep(world, ["opencode", "run"], {"OPENCODE_CONFIG_CONTENT": bad})


def test_auto_flag_and_config_env_warn(world):
    p = prep(world, ["opencode", "run", "--auto", "x"], {"OPENCODE_CONFIG": "/x.json"})
    text = " | ".join(p.warnings)
    assert "--auto" in text and "OPENCODE_CONFIG" in text


# ---- per-directory layers ------------------------------------------------------------------------------
def test_layers_select_what_is_generated(world):
    set_layers(world, world.t1, {"pre_execution_hook": False})
    tg = targets(world)
    by = {t.canonical_path: t for t in tg}
    assert by[str(world.t1)].layers["pre_execution_hook"] is False
    cfg = cfg_of(prep(world, ["opencode", "run"], tg=tg))
    assert "plugins" in cfg                                          # t2 still has the hook
    set_layers(world, world.t2, {"pre_execution_hook": False})
    cfg = cfg_of(prep(world, ["opencode", "run"], tg=targets(world)))
    assert "plugins" not in cfg and "permissions" in cfg
    p = prep(world, ["opencode", "run"], tg=targets(world))
    assert p.layers["pre_execution_hook"] == DISABLED and p.layers["native_permissions"] == UNVERIFIED
    for t in (world.t1, world.t2):
        set_layers(world, t, {"agent_permissions": False})
    cfg = cfg_of(prep(world, ["opencode", "run"], tg=targets(world)))
    assert "permissions" not in cfg and "plugins" not in cfg
    assert prep(world, ["opencode", "run"], tg=targets(world)).layers["native_permissions"] == DISABLED


def test_layers_cache_goes_stale_with_agent_version(world, monkeypatch):
    ad = by_name("opencode")
    tg = targets(world)
    rev = registry.Registry(targets=list(tg)).policy_revision
    monkeypatch.setattr(type(ad), "agent_version", lambda self, env=None: "v2.3.0")
    cache.store("opencode", {"policy_revision": rev, "agent_version": "v2.3.0",
                             "layers": {"native_permissions": "PASS", "pre_execution_hook": "PASS"}})
    assert ad.cached_layers(world.ctx, tg, {}) == {"native_permissions": "PASS", "pre_execution_hook": "PASS"}
    monkeypatch.setattr(type(ad), "agent_version", lambda self, env=None: "v2.9.9")
    assert ad.cached_layers(world.ctx, tg, {}) == {"native_permissions": "STALE", "pre_execution_hook": "STALE"}


# ---- the shared hook script, with OpenCode-shaped events ------------------------------------------------------
def ev(tool, ti, cwd):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti, "cwd": str(cwd)}


def test_hook_understands_opencode_tool_names(world):
    secret = str(world.t1 / "secret.txt")
    assert run_hook(world.ctx, ev("shell", {"command": f"cat '{secret}'"}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("read", {"path": secret}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("glob", {"pattern": "*", "path": str(world.t1)}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("grep", {"pattern": "S", "path": str(world.t2)}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("shell", {"command": "sudo ls"}, world.proj), [])[0] == 2
    assert run_hook(world.ctx, ev("shell", {"command": "ls && git status"}, world.proj), [])[0] == 0
    assert run_hook(world.ctx, ev("read", {"path": str(world.proj / "a.txt")}, world.proj), [])[0] == 0


def test_offline_checks_all_pass(world, tmp_path):
    fixture, project = tmp_path / "fx", tmp_path / "pj"
    fixture.mkdir()
    project.mkdir()
    (fixture / "marker.txt").write_text("m")
    (project / "ok.txt").write_text("o")
    checks = offline_hook_checks(world.ctx, fixture, project)
    assert checks and all(c["status"] == "PASS" for c in checks), checks


def test_outcome_classification():
    run = {"tools": [{"tool": "read", "status": "error", "input": {"path": "/a"}, "text": "denied"},
                     {"tool": "shell", "status": "completed", "input": {"command": "echo hi"}, "text": "hi"}]}
    assert outcome(run, "read")[0] == "blocked"
    assert outcome(run, "shell", "echo")[0] == "allowed"
    assert outcome(run, "shell", "other")[0] == "none"
    assert outcome({"error": "timeout"}, "read")[0] == "none"


# ---- plugin source: fail-closed structure, nothing evaluated -------------------------------------------------------
def test_plugin_source_is_fail_closed_and_never_evaluates():
    src = (oc.plugin_dir() / "index.js").read_text()
    assert "throw new Error(d.reason)" in src and 'event.effect = "deny"' in src
    assert "fail-closed" in src and "r.status === null" in src
    assert "eval(" not in src and "new Function" not in src and "shell: true" not in src
    pkg = json.loads((oc.plugin_dir() / "package.json").read_text())
    assert pkg["type"] == "module" and pkg["main"] == "index.js"


# ---- real opencode: plugin load detection (no model needed) ----------------------------------------------------------
@pytest.mark.skipif(not HAVE_OPENCODE, reason="opencode not installed")
def test_plugin_loads_and_missing_plugin_is_detected_by_real_opencode(world, tmp_path):
    fixture, project = tmp_path / "fx", tmp_path / "pj"
    fixture.mkdir()
    project.mkdir()
    (fixture / "marker.txt").write_text("m")
    (project / "ok.txt").write_text("o")
    res = {c["name"]: c for c in plugin_load_checks(world.ctx, fixture, project)}
    assert res["plugin_loads_and_handshakes"]["status"] == "PASS", res
    assert res["missing_plugin_is_detected"]["status"] == "PASS", res


@pytest.mark.skipif(not HAVE_OPENCODE, reason="opencode not installed")
def test_handshake_rejects_a_plugin_that_throws_in_setup(tmp_path):
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "package.json").write_text('{"name":"bad","type":"module","main":"index.js"}')
    (bad / "index.js").write_text('export default {id:"protect-folder", async setup(){ throw new Error("boom") }}')
    ok, _ = handshake({"plugins": [{"package": str(bad), "options": {}}]}, tmp_path)
    assert ok is False


def test_offline_verify_is_honest_without_live_run(world):
    res = verify_opencode(world.ctx, None, None, live=False)
    assert res["native_permissions"]["status"] == UNVERIFIED          # never PASS without a live session
    assert res["pre_execution_hook"]["status"] in ("UNVERIFIED", "FAIL")
    dis = verify_opencode(world.ctx, None, None, live=False,
                          enabled={"agent_permissions": False, "pre_execution_hook": False})
    assert dis["native_permissions"]["status"] == DISABLED and dis["pre_execution_hook"]["status"] == DISABLED


@pytest.mark.live_agent
def test_live_opencode_verification_with_real_sessions(world):
    res = verify_opencode(world.ctx, None, None, live=True)
    assert res["native_permissions"]["status"] == "PASS", res["native_permissions"]
    assert res["pre_execution_hook"]["status"] == "PASS", res["pre_execution_hook"]


# ---- version guard: found when the operator turned out to have OpenCode 1.17 AND 2.3 installed side by side -----
def _fake_opencode(tmp_path, banner):
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    exe = d / "opencode"
    exe.write_text(f"#!/bin/sh\necho '{banner}'\n")
    exe.chmod(0o755)
    return d


@pytest.mark.parametrize("banner", ["1.17.0", "opencode v1.99.3", "3.0.0"])
def test_unsupported_major_version_is_refused(world, tmp_path, banner):
    d = _fake_opencode(tmp_path, banner)
    with pytest.raises(ProtectError) as e:
        prep(world, ["opencode"], env={"PATH": f"{d}:{os.environ['PATH']}"})
    assert e.value.code == "PREFLIGHT_FAILED" and "OpenCode" in e.value.message


def test_supported_and_unparseable_versions_are_accepted(world, tmp_path):
    for banner in ("opencode v2.3.0", "2.9.1", "dev build"):
        d = _fake_opencode(tmp_path, banner)
        prep(world, ["opencode"], env={"PATH": f"{d}:{os.environ['PATH']}"})


def test_major_version_parsing():
    assert [oc.major_version(x) for x in ("opencode v2.3.0", "1.17.0", "v10.0.1", "nope", None)] == [2, 1, 10, None, None]
