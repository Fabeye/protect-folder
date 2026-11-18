import os
import stat

import pytest

from protect_folder import runtime as rtmod
from protect_folder.errors import ProtectError
from protect_folder.policy import profiles, srt
from protect_folder.registry import Target, target_id
from protect_folder.runtime import Runtime
from pathlib import Path

RT = Runtime(Path("/rt/node"), Path("/rt/srt/dist/cli.js"), "0.0.83", "/usr/bin/bwrap", "/usr/bin/socat", "/usr/bin/rg")


def T(path, ino=1):
    return Target(id=target_id(1, ino, path), input_path=path, canonical_path=path, st_dev=1, st_ino=ino,
                  filesystem_type="ext4", mount_point="/", created_at="x")


def compile_(env, targets, **kw):
    kw.setdefault("workspace", "/work/proj")
    kw.setdefault("extra_write", ["/tmp"])
    kw.setdefault("allowed_domains", [])
    return srt.compile_settings(env.ctx, targets, rt=RT, **kw)


def test_every_target_is_a_literal_deny_for_read_and_write(env):
    ts = [T("/mnt/a/Forbidden folder", 1), T("/mnt/b/we*ird[1]?", 2), T("/media/x/ü", 3)]
    s = compile_(env, ts)
    fs = s["filesystem"]
    for t in ts:
        assert {"path": t.canonical_path, "literal": True} in fs["denyRead"]
        assert {"path": t.canonical_path, "literal": True} in fs["denyWrite"]
    assert all(isinstance(e, dict) and e["literal"] is True for e in fs["denyRead"])   # never a glob string
    assert fs["allowRead"] == []


def test_trusted_paths_denied_for_write_and_helpers_pinned(env):
    s = compile_(env, [T("/mnt/a")])
    deny_w = {e["path"] for e in s["filesystem"]["denyWrite"]}
    for p in env.layout.trusted_paths():
        assert str(p) in deny_w
    assert s["bwrapPath"] == "/usr/bin/bwrap" and s["socatPath"] == "/usr/bin/socat"


def test_weakening_flags_are_explicitly_false(env):
    s = compile_(env, [T("/mnt/a")])
    assert s["enableWeakerNestedSandbox"] is False and s["allowNestedUserNamespaces"] is False
    assert s["enableWeakerNetworkIsolation"] is False
    assert s["network"]["allowAllUnixSockets"] is False and s["network"]["deniedDomains"] == []


def test_deterministic_and_order_independent(env):
    a = compile_(env, [T("/mnt/a", 1), T("/mnt/b", 2)])
    b = compile_(env, [T("/mnt/b", 2), T("/mnt/a", 1)])
    assert a == b


@pytest.mark.parametrize("ws", ["/mnt/a", "/mnt/a/sub", "/"])
def test_allow_write_inside_or_equal_target_is_refused(env, ws):
    with pytest.raises(ProtectError) as e:
        compile_(env, [T("/mnt/a")], workspace=ws)
    assert e.value.code == "PREFLIGHT_FAILED"


def test_ancestor_workspace_is_allowed_because_deny_overrides(env):
    s = compile_(env, [T("/work/proj/credentials")])
    assert "/work/proj" in s["filesystem"]["allowWrite"]
    assert {"path": "/work/proj/credentials", "literal": True} in s["filesystem"]["denyWrite"]


def test_validate_catches_each_weakening():
    good = {"network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [{"path": "/x", "literal": True}], "allowRead": [], "allowWrite": ["/w"],
                           "denyWrite": [{"path": "/x", "literal": True}]}}
    srt.validate_settings(good, ["/x"])
    import copy
    cases = {
        "allowRead": lambda s: s["filesystem"].update(allowRead=["/x"]),
        "weaker": lambda s: s.update(enableWeakerNestedSandbox=True),
        "nested": lambda s: s.update(allowNestedUserNamespaces=True),
        "unix": lambda s: s["network"].update(allowAllUnixSockets=True),
        "disabled": lambda s: s["filesystem"].update(disabled=True),
        "allowall": lambda s: s["network"].update(allowedDomains=["*"]),
        "no-denyRead": lambda s: s["filesystem"].update(denyRead=[]),
        "glob-not-literal": lambda s: s["filesystem"].update(denyRead=["/x"]),
        "no-denyWrite": lambda s: s["filesystem"].update(denyWrite=[]),
        "write-inside": lambda s: s["filesystem"].update(allowWrite=["/x/inner"]),
    }
    for name, mutate in cases.items():
        bad = copy.deepcopy(good)
        mutate(bad)
        with pytest.raises(ProtectError, match="rejected"):
            srt.validate_settings(bad, ["/x"])


def test_find_workspace_prefers_git_toplevel_and_stops_at_home(env, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    deep = repo / "a" / "b"
    deep.mkdir(parents=True)
    assert srt.find_workspace(str(deep), set()) == str(repo)
    plain = tmp_path / "plain" / "x"
    plain.mkdir(parents=True)
    assert srt.find_workspace(str(plain), {str(tmp_path)}) == str(plain)


def test_check_workspace_refuses_home_root_and_inside_target(env):
    with pytest.raises(ProtectError):
        srt.check_workspace("/home/u", [], {"/home/u"})
    with pytest.raises(ProtectError):
        srt.check_workspace("/home", [], {"/home/u"})
    with pytest.raises(ProtectError):
        srt.check_workspace("/mnt/a/sub", [T("/mnt/a")], set())
    srt.check_workspace("/home/u/project", [T("/mnt/a")], {"/home/u"})


def test_profiles_never_allow_everything():
    assert profiles.resolve_profile("offline", {}) == []
    for bad in (["*"], ["*.*"], ["**"], [""], ["*:443"]):
        with pytest.raises(ProtectError):
            profiles.validate_domains("p", bad)
    assert profiles.resolve_profile("mine", {"profiles": {"mine": {"allowedDomains": ["b.com", "a.com", "a.com"]}}}) == ["a.com", "b.com"]
    with pytest.raises(ProtectError) as e:
        profiles.resolve_profile("nope", {})
    assert "known profiles" in e.value.hint


def test_private_settings_file_is_0600(tmp_path):
    p = srt.write_private_settings({"a": 1}, str(tmp_path))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600 and os.path.dirname(p) == str(tmp_path)


# ---- runtime trust -----------------------------------------------------------------------
def test_runtime_ok_then_each_tamper_is_detected(senv, srt_runtime_dir):
    rt = rtmod.check_runtime(senv.ctx, full_hash=True)
    assert rt.srt_version == "0.0.83" and rt.node.name == "node"
    cli = srt_runtime_dir / "srt" / "dist" / "cli.js"
    os.chmod(cli, 0o666)
    try:
        with pytest.raises(ProtectError) as e:
            rtmod.check_runtime(senv.ctx)
        assert e.value.code == "TAMPERED"
    finally:
        os.chmod(cli, 0o755)
    os.chmod(cli, 0o755)
    orig = cli.read_bytes()
    os.chmod(cli, 0o755)
    cli.write_bytes(orig + b"\n// injected\n")
    try:
        with pytest.raises(ProtectError) as e:
            rtmod.check_runtime(senv.ctx)
        assert e.value.code == "TAMPERED" and "hash" in e.value.message
    finally:
        cli.write_bytes(orig)
    rtmod.check_runtime(senv.ctx)


def test_runtime_missing_manifest_or_untested_version(env, tmp_path):
    with pytest.raises(ProtectError) as e:
        rtmod.check_runtime(env.ctx)
    assert e.value.code == "SRT_UNAVAILABLE" and "not used" in e.value.hint


def test_symlink_escaping_runtime_is_rejected(tmp_path):
    root = tmp_path / "rt"
    root.mkdir()
    (root / "ok").write_text("x")
    os.chmod(root / "ok", 0o644)
    (root / "evil").symlink_to("/etc/passwd")
    with pytest.raises(ProtectError) as e:
        rtmod.check_tree(root, os.getuid())
    assert e.value.code == "TAMPERED"
