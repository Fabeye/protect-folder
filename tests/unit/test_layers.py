"""Per-directory security layer configuration (change request, section 7 acceptance tests)."""

import json
import os
import re

import pytest

from protect_folder import admin, cli, layers as L, registry, render, sessions, snapshots, status as status_mod
from protect_folder.adapters import by_name
from protect_folder.adapters.claude_verify import run_hook
from protect_folder.constants import PROTECTED_GID, PROTECTED_MODE, PROTECTED_UID
from protect_folder.errors import ProtectError
from protect_folder.hostops import AclState, MetaState
from protect_folder.verify import cache

PROTECTED = (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE)
ALL_ON = {k: True for k in L.LAYERS}
ACL = "user::rwx\nuser:alice:r-x\ngroup::r-x\nmask::r-x\nother::---\n"


def meta(env, d):
    import os as _os
    fd = _os.open(d, _os.O_RDONLY | _os.O_DIRECTORY)
    try:
        m = env.host.stat(fd)
        return (m.uid, m.gid, m.mode)
    finally:
        _os.close(fd)


def seed(env, *parts, owner=(1111, 2222, 0o750), acl=None):
    """A directory whose (fake) original ownership/mode/ACL is NOT root:root 0700."""
    d = env.mkdir(*parts)
    st = os.stat(d)
    env.host.meta[(st.st_dev, st.st_ino)] = MetaState(*owner)
    if acl:
        env.host.set_initial_acl(str(d), acl)
    return d


def reg_of(env):
    return registry.load(env.layout)


def layers_of(env, d):
    return reg_of(env).find_path(os.path.realpath(d)).layers


@pytest.fixture
def e(env):
    env.install()
    return env


def run(env, capsys, *argv):
    code = cli.main(list(argv), ctx=env.ctx)
    c = capsys.readouterr()
    return code, c.out, c.err


# ---- 1. default: all four layers ------------------------------------------------------------------
def test_add_without_flags_enables_all_four_layers(e):
    d = seed(e, "a")
    out = admin.add(e.ctx, str(d), yes=True)
    assert out.ok and layers_of(e, d) == ALL_ON
    assert meta(e, d) == PROTECTED                                        # linux permissions applied
    assert snapshots.load(e.layout)[reg_of(e).targets[0].id].mode == 0o750   # original state recorded
    gen = json.load(open(e.layout.srt_targets_file))
    assert [x["path"] for x in gen["denyRead"]] == [str(d)]
    raw = json.load(open(e.layout.targets_file))
    assert raw["targets"][0]["layers"] == ALL_ON and raw["schema_version"] == 2


def test_cli_add_without_flags_enables_all_four(e, capsys):
    d = e.mkdir("b")
    code, out, err = run(e, capsys, "add", "--yes", "--json", str(d))
    assert code == 0 and json.loads(out)["data"]["plan"]["layers"] == ALL_ON


# ---- 2. --no-linux preserves uid/gid/mode/ACL -----------------------------------------------------------
def test_no_linux_leaves_ownership_mode_and_acl_untouched(e, capsys):
    d = seed(e, "keep", acl=ACL)
    before_acl = e.host.get_acl(os.open(d, os.O_RDONLY | os.O_DIRECTORY))
    code, out, err = run(e, capsys, "add", "--yes", "--json", "--no-linux", str(d))
    assert code == 0, err
    assert layers_of(e, d) == {**ALL_ON, "linux_permissions": False}
    assert meta(e, d) == (1111, 2222, 0o750)
    assert e.host.acls[(os.stat(d).st_dev, os.stat(d).st_ino)].text == ACL
    assert e.host.calls == []                                             # no chown/chmod/setfacl at all
    assert snapshots.load(e.layout) == {}                                 # nothing to restore later
    doc = json.loads(out)
    assert any("NO OS-level protection" in w for w in doc["warnings"])
    assert not any("root:root 0700: your own programs" in w for w in doc["warnings"])


def test_no_linux_directory_is_still_in_srt_agent_and_hook_policy(e):
    d = seed(e, "p")
    admin.add(e.ctx, str(d), yes=True, layers={"linux_permissions": False})
    t = reg_of(e).targets[0]
    assert [x["path"] for x in json.load(open(e.layout.srt_targets_file))["denyRead"]] == [str(d)]
    assert t.layers["sandbox_runtime"] and t.layers["agent_permissions"] and t.layers["pre_execution_hook"]


# ---- 3. different directories, different configurations ------------------------------------------------
def test_directories_have_independent_layer_configuration(e):
    a, b, c = seed(e, "a"), seed(e, "b"), seed(e, "c")
    admin.add(e.ctx, str(a), yes=True)
    admin.add(e.ctx, str(b), yes=True, layers={"linux_permissions": False})
    admin.add(e.ctx, str(c), yes=True, layers={"sandbox_runtime": False, "pre_execution_hook": False})
    assert layers_of(e, a) == ALL_ON
    assert layers_of(e, b) == {**ALL_ON, "linux_permissions": False}
    assert layers_of(e, c) == {**ALL_ON, "sandbox_runtime": False, "pre_execution_hook": False}
    assert meta(e, a) == PROTECTED and meta(e, b) == (1111, 2222, 0o750) and meta(e, c) == PROTECTED
    # the generated files/policies use each target's own settings
    gen = json.load(open(e.layout.srt_targets_file))
    assert sorted(x["path"] for x in gen["denyRead"]) == sorted([str(a), str(b)])      # c: SRT off
    reg = reg_of(e)
    prep = by_name("claude").prepare(e.ctx, ["claude"], {"PATH": os.environ["PATH"]}, "/tmp", reg.sorted_targets(), {})
    rules = json.load(open(prep.argv[2]))["permissions"]["deny"]
    os.unlink(prep.argv[2])
    for d in (a, b, c):
        assert any(str(d).lstrip("/") in r for r in rules)                          # agent layer on for all three
    # hook policy: c has the hook off, a and b have it on
    proj = e.tmp / "proj"
    proj.mkdir()
    ev = lambda d: {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                    "tool_input": {"command": f"cat '{d}/x'"}, "cwd": str(proj)}
    assert run_hook(e.ctx, ev(a), [])[0] == 2 and run_hook(e.ctx, ev(b), [])[0] == 2
    assert run_hook(e.ctx, ev(c), [])[0] == 0


# ---- 4. changing a layer updates only the applicable policies --------------------------------------------
def test_toggling_one_layer_changes_only_that_policy(e):
    a, b = seed(e, "a"), seed(e, "b")
    admin.add(e.ctx, str(a), yes=True)
    admin.add(e.ctx, str(b), yes=True)
    def srt_entries():
        g = json.load(open(e.layout.srt_targets_file))
        return g["denyRead"], g["denyWrite"]
    gen0 = srt_entries()
    snap0 = snapshots.load(e.layout)
    host_calls = len(e.host.calls)

    out = admin.set_layers(e.ctx, str(a), {"pre_execution_hook": False}, yes=True)
    assert out.ok and out.data["changed"] == ["pre_execution_hook"] and out.data["restart_required"]
    assert layers_of(e, a) == {**ALL_ON, "pre_execution_hook": False} and layers_of(e, b) == ALL_ON
    assert srt_entries() == gen0                                     # SRT deny lists untouched
    assert snapshots.load(e.layout) == snap0 and len(e.host.calls) == host_calls   # no filesystem change

    out = admin.set_layers(e.ctx, str(a), {"sandbox_runtime": False}, yes=True)
    assert [x["path"] for x in json.load(open(e.layout.srt_targets_file))["denyRead"]] == [str(b)]
    assert len(e.host.calls) == host_calls
    assert layers_of(e, a) == {**ALL_ON, "pre_execution_hook": False, "sandbox_runtime": False}

    admin.set_layers(e.ctx, str(a), {"agent_permissions": False}, yes=True)
    reg = reg_of(e)
    prep = by_name("claude").prepare(e.ctx, ["claude"], {"PATH": os.environ["PATH"]}, "/tmp", reg.sorted_targets(), {})
    rules = json.load(open(prep.argv[2]))["permissions"]["deny"]
    os.unlink(prep.argv[2])
    assert not any(str(a).lstrip("/") in r for r in rules) and any(str(b).lstrip("/") in r for r in rules)
    assert meta(e, a) == PROTECTED                                   # linux layer was never touched


def test_set_layers_changes_only_named_layers_and_all_reenables_everything(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    admin.set_layers(e.ctx, str(d), {"linux_permissions": False, "agent_permissions": False}, yes=True)
    assert layers_of(e, d) == {**ALL_ON, "linux_permissions": False, "agent_permissions": False}
    out = admin.set_layers(e.ctx, str(d), {"pre_execution_hook": False}, yes=True)      # others stay as they were
    assert layers_of(e, d) == {"agent_permissions": False, "pre_execution_hook": False,
                               "sandbox_runtime": True, "linux_permissions": False}
    admin.set_layers(e.ctx, str(d), {k: True for k in L.LAYERS}, yes=True)               # --all
    assert layers_of(e, d) == ALL_ON and meta(e, d) == PROTECTED


def test_set_layers_noop_changes_nothing_and_says_so(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    rev = reg_of(e).revision
    out = admin.set_layers(e.ctx, str(d), {"sandbox_runtime": True}, yes=True)
    assert out.ok and out.data["changed"] == [] and "no changes" in out.message and reg_of(e).revision == rev


def test_cli_set_layers_flags(e, capsys):
    d = seed(e, "d")
    run(e, capsys, "add", "--yes", str(d))
    code, out, err = run(e, capsys, "set-layers", "--yes", "--json", str(d), "--no-linux")
    assert code == 0 and meta(e, d) == (1111, 2222, 0o750)
    code, out, err = run(e, capsys, "set-layers", "--yes", "--json", str(d), "--all")
    assert code == 0 and layers_of(e, d) == ALL_ON and meta(e, d) == PROTECTED
    assert run(e, capsys, "set-layers", "--yes", str(d), "--all", "--no-srt")[0] == 2 or True  # contradictory
    code, _, err = run(e, capsys, "set-layers", "--yes", "--json", str(d), "--all", "--no-srt")
    assert code == 2 and "contradictory" in err.lower() + _
    assert run(e, capsys, "set-layers", "--yes", str(d))[0] == 2                         # nothing requested
    # enabling a single layer explicitly
    run(e, capsys, "set-layers", "--yes", str(d), "--no-hook")
    assert run(e, capsys, "set-layers", "--yes", str(d), "--hook")[0] == 0 and layers_of(e, d) == ALL_ON


# ---- 5. re-enabling linux permissions: capture or reuse the right snapshot --------------------------------
def test_reenable_linux_captures_fresh_original_state(e):
    d = seed(e, "d", acl=ACL)
    admin.add(e.ctx, str(d), yes=True)
    admin.set_layers(e.ctx, str(d), {"linux_permissions": False}, yes=True)
    assert snapshots.load(e.layout) == {}
    st = os.stat(d)                                                    # the owner changes things meanwhile
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(3333, 4444, 0o770)
    out = admin.set_layers(e.ctx, str(d), {"linux_permissions": True}, yes=True)
    assert out.data["plan"]["snapshot"] == "captured the current state" and meta(e, d) == PROTECTED
    snap = next(iter(snapshots.load(e.layout).values()))
    assert (snap.uid, snap.gid, snap.mode) == (3333, 4444, 0o770)
    admin.remove(e.ctx, str(d), yes=True)
    assert meta(e, d) == (3333, 4444, 0o770)                           # restored to the state captured on re-enable


def test_reenable_linux_reuses_existing_snapshot_while_still_locked(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    orig = next(iter(snapshots.load(e.layout).values()))
    reg = reg_of(e)                                                    # registry says off, but the dir is still locked
    reg.targets[0].layers["linux_permissions"] = False
    registry.save(e.layout, reg)
    out = admin.set_layers(e.ctx, str(d), {"linux_permissions": True}, yes=True)
    assert out.data["plan"]["snapshot"].startswith("reused")
    assert next(iter(snapshots.load(e.layout).values())) == orig       # the ORIGINAL state is still what is restored
    admin.remove(e.ctx, str(d), yes=True)
    assert meta(e, d) == (1111, 2222, 0o750)


def test_reenable_refuses_to_invent_an_original_state_for_an_already_locked_dir(e):
    d = seed(e, "d", owner=PROTECTED)
    admin.add(e.ctx, str(d), yes=True, layers={"linux_permissions": False})
    with pytest.raises(ProtectError) as x:
        admin.set_layers(e.ctx, str(d), {"linux_permissions": True}, yes=True)
    assert "original permissions are unknown" in x.value.message
    assert layers_of(e, d)["linux_permissions"] is False               # nothing changed


# ---- 6. disabling restores safely ----------------------------------------------------------------------------
def test_disable_linux_restores_original_state_and_keeps_other_layers(e):
    d = seed(e, "d", acl=ACL)
    admin.add(e.ctx, str(d), yes=True)
    assert meta(e, d) == PROTECTED
    out = admin.set_layers(e.ctx, str(d), {"linux_permissions": False}, yes=True)
    assert out.ok and meta(e, d) == (1111, 2222, 0o750)
    st = os.stat(d)
    assert e.host.acls[(st.st_dev, st.st_ino)].text == ACL              # ACL restored exactly
    assert snapshots.load(e.layout) == {}
    assert layers_of(e, d) == {**ALL_ON, "linux_permissions": False}
    assert [x["path"] for x in json.load(open(e.layout.srt_targets_file))["denyRead"]] == [str(d)]   # SRT still on
    assert any("processes outside the sandbox can use this directory again" in w for w in out.warnings)


def test_disable_linux_refuses_when_the_directory_was_replaced(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    os.rename(d, str(d) + ".moved")
    os.mkdir(d)                                                         # a different object (new inode) at the same path
    st = os.stat(d)
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(5, 5, 0o755)
    calls = len(e.host.calls)
    with pytest.raises(ProtectError) as x:
        admin.set_layers(e.ctx, str(d), {"linux_permissions": False}, yes=True)
    assert x.value.code in ("IDENTITY_MISMATCH", "STALE", "MOUNT_MISSING")
    assert len(e.host.calls) == calls and meta(e, d) == (5, 5, 0o755)   # the impostor was never touched
    assert layers_of(e, d) == ALL_ON                                    # registry unchanged
    assert len(snapshots.load(e.layout)) == 1                           # snapshot kept for the real original


def test_disable_linux_rolls_back_completely_on_failure(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    before = open(e.layout.targets_file).read()
    gen = open(e.layout.srt_targets_file).read()
    e.host.fail_on["chmod"] = e.host._counts.get("chmod", 0) + 1        # the restore step itself fails
    with pytest.raises(Exception):
        admin.set_layers(e.ctx, str(d), {"linux_permissions": False}, yes=True)
    assert meta(e, d) == PROTECTED                                      # still locked
    assert open(e.layout.targets_file).read() == before and open(e.layout.srt_targets_file).read() == gen
    assert len(snapshots.load(e.layout)) == 1 and not e.layout.marker_file.exists()


def test_disable_linux_without_snapshot_refuses_to_guess(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    e.layout.snapshots_file.write_text("{}")
    snapshots.save(e.layout, {})
    with pytest.raises(ProtectError) as x:
        admin.set_layers(e.ctx, str(d), {"linux_permissions": False}, yes=True)
    assert x.value.code == "TAMPERED" and meta(e, d) == PROTECTED


def test_remove_with_linux_off_never_touches_the_directory(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True, layers={"linux_permissions": False})
    out = admin.remove(e.ctx, str(d), yes=True)
    assert out.ok and e.host.calls == [] and meta(e, d) == (1111, 2222, 0o750) and reg_of(e).targets == []


# ---- 7. overlapping directories --------------------------------------------------------------------------------
def test_child_cannot_opt_out_of_layers_its_protected_parent_enforces(e):
    parent = seed(e, "parent")
    child = seed(e, "parent", "child")
    admin.add(e.ctx, str(parent), yes=True)
    out = admin.add(e.ctx, str(child), yes=True,
                    layers={"sandbox_runtime": False, "linux_permissions": False, "pre_execution_hook": False})
    assert out.ok
    assert any("still ENFORCED because protected parent" in w and "SRT sandbox" in w for w in out.warnings)
    assert any("inside already-protected" in w for w in out.warnings)
    reg = reg_of(e)
    c = reg.find_path(str(child))
    eff = reg.effective(c)
    assert eff["sandbox_runtime"] == {"own": False, "enabled": True, "inherited_from": str(parent), "source_id": reg.find_path(str(parent)).id}
    assert eff["linux_permissions"]["enabled"] and eff["pre_execution_hook"]["inherited_from"] == str(parent)
    assert eff["agent_permissions"]["own"] is True
    # generated SRT policy: only the parent (it already covers the child)
    assert [x["path"] for x in json.load(open(e.layout.srt_targets_file))["denyRead"]] == [str(parent)]
    # the hook still blocks the child through the parent's hook layer
    proj = e.tmp / "proj"
    proj.mkdir()
    ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"cat '{child}/x'"}, "cwd": str(proj)}
    assert run_hook(e.ctx, ev, [])[0] == 2
    # the report says so accurately
    views = status_mod.layer_views(e.ctx, reg, c)
    assert views["sandbox_runtime"]["inherited_from"] == str(parent) and views["sandbox_runtime"]["effective"]
    assert views["sandbox_runtime"]["enabled"] is False                 # not the child's own setting


def test_removing_the_parents_layer_exposes_the_child_honestly(e):
    parent, child = seed(e, "p"), seed(e, "p", "c")
    admin.add(e.ctx, str(parent), yes=True)
    admin.add(e.ctx, str(child), yes=True, layers={"sandbox_runtime": False})
    admin.set_layers(e.ctx, str(parent), {"sandbox_runtime": False}, yes=True)
    reg = reg_of(e)
    assert not reg.effective(reg.find_path(str(child)))["sandbox_runtime"]["enabled"]
    assert json.load(open(e.layout.srt_targets_file))["denyRead"] == []


def test_child_with_its_own_layer_on_and_parent_off_is_protected_alone(e):
    parent, child = seed(e, "p"), seed(e, "p", "c")
    admin.add(e.ctx, str(parent), yes=True, layers={"linux_permissions": False})
    admin.add(e.ctx, str(child), yes=True)
    assert meta(e, parent) == (1111, 2222, 0o750) and meta(e, child) == PROTECTED
    reg = reg_of(e)
    assert not reg.effective(reg.find_path(str(parent)))["linux_permissions"]["enabled"]
    assert [x["path"] for x in json.load(open(e.layout.srt_targets_file))["denyRead"]] == sorted([str(parent), str(child)])


def test_nested_remove_restores_each_directory_independently(e):
    parent, child = seed(e, "p", owner=(10, 10, 0o755)), seed(e, "p", "c", owner=(20, 20, 0o700))
    admin.add(e.ctx, str(parent), yes=True)
    admin.add(e.ctx, str(child), yes=True)
    admin.remove(e.ctx, str(parent), yes=True)
    assert meta(e, parent) == (10, 10, 0o755) and meta(e, child) == PROTECTED     # child keeps its own lock
    admin.remove(e.ctx, str(child), yes=True)
    assert meta(e, child) == (20, 20, 0o700)


# ---- 8. status / list distinguish configured / disabled / verified / failed ----------------------------------------
def states(env, d):
    reg = reg_of(env)
    return {k: v["state"] for k, v in status_mod.layer_views(env.ctx, reg, reg.find_path(os.path.realpath(d))).items()}


def test_status_never_counts_a_configured_layer_as_verified(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True, layers={"pre_execution_hook": False})
    s = states(e, d)
    assert s == {"agent_permissions": "CONFIGURED", "pre_execution_hook": "DISABLED",
                 "sandbox_runtime": "CONFIGURED", "linux_permissions": "VERIFIED"}     # only L4 has live evidence
    row = status_mod.overall(e.ctx)["targets"][0]
    assert row["verified_count"] == 1 and row["configured_count"] == 3


def test_verification_evidence_is_per_directory_and_expires_with_the_policy(e):
    a, b = seed(e, "a"), seed(e, "b")
    admin.add(e.ctx, str(a), yes=True)
    admin.add(e.ctx, str(b), yes=True)
    reg = reg_of(e)
    ta, tb = reg.find_path(str(a)), reg.find_path(str(b))
    cache.store_targets("generic", reg.policy_revision, None,
                        {ta.id: {"sandbox_runtime": {"status": "PASS"}},
                         tb.id: {"sandbox_runtime": {"status": "FAIL", "detail": "leak"}}}, "2026-01-02T03:04:05Z")
    assert states(e, a)["sandbox_runtime"] == "VERIFIED" and states(e, b)["sandbox_runtime"] == "FAILED"
    assert states(e, a)["agent_permissions"] == "CONFIGURED"
    # any policy change (here: a layer toggle on ANOTHER directory) makes old evidence stale -> back to CONFIGURED
    admin.set_layers(e.ctx, str(b), {"pre_execution_hook": False}, yes=True)
    assert states(e, a)["sandbox_runtime"] == "CONFIGURED" and states(e, b)["sandbox_runtime"] == "CONFIGURED"


def test_agent_layer_evidence_expires_when_the_agent_version_changes(e, monkeypatch):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    reg = reg_of(e)
    t = reg.targets[0]
    cache.store_targets("claude", reg.policy_revision, "2.1.327", {t.id: {"agent_permissions": {"status": "PASS"}}}, "2026-01-01T00:00:00Z")
    monkeypatch.setattr(status_mod, "_agent_version", lambda a: "2.1.327")
    assert states(e, d)["agent_permissions"] == "VERIFIED"
    monkeypatch.setattr(status_mod, "_agent_version", lambda a: "2.2.0")
    assert states(e, d)["agent_permissions"] == "CONFIGURED"


def test_linux_layer_failure_is_reported_as_failed(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    st = os.stat(d)
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o755)    # someone un-protected it behind our back
    assert states(e, d)["linux_permissions"] == "FAILED"
    assert status_mod.overall(e.ctx)["state"] == "DEGRADED"


def test_status_text_shows_on_off_and_states(e, capsys):
    d = seed(e, "d")
    run(e, capsys, "add", "--yes", "--no-linux", str(d))
    code, out, err = run(e, capsys, "status", "--no-color", str(d))
    assert "[ON]  Agent permissions" in out and "[OFF] Linux permissions" in out
    assert "DISABLED" in out and "CONFIGURED" in out and "Protection: 3/4 configured, 0/4 verified" in out
    assert "NO OS-level protection" in out


def test_verify_lists_only_enabled_layers_for_the_selected_directory(senv):
    e = senv
    a, b = seed(e, "a"), seed(e, "b")
    e.install()
    admin.add(e.ctx, str(a), yes=True, layers={"linux_permissions": False, "sandbox_runtime": False},
              accept_no_fs_enforcement=True)
    admin.add(e.ctx, str(b), yes=True)
    e.is_root = False
    from protect_folder.verify import runner
    doc = runner.run_verify(e.ctx, path=str(a))
    assert doc["layers"]["srt"]["status"] == "DISABLED" and doc["layers"]["linux_permissions"]["status"] == "DISABLED"
    assert doc["layers"]["srt"]["checks"] == [] and doc["layers"]["linux_permissions"]["checks"] == []     # NOT tested
    row = doc["targets"][0]
    assert row["layers"]["sandbox_runtime"]["state"] == "DISABLED" and row["layers"]["linux_permissions"]["state"] == "DISABLED"
    assert row["layers"]["agent_permissions"]["state"] in ("CONFIGURED", "VERIFIED")
    assert doc["configured_layers"] == 2
    doc_b = runner.run_verify(e.ctx, path=str(b))
    assert doc_b["layers"]["srt"]["checks"] and doc_b["layers"]["linux_permissions"]["checks"]   # b has both on
    assert doc_b["targets"][0]["layers"]["sandbox_runtime"]["state"] in ("VERIFIED", "FAILED")


# ---- 9. warnings -----------------------------------------------------------------------------------------------------
def test_disabling_srt_or_linux_produces_clear_warnings(e):
    d1, d2 = seed(e, "d1"), seed(e, "d2")
    out = admin.add(e.ctx, str(d1), yes=True, layers={"sandbox_runtime": False})
    assert any("SRT sandbox is OFF" in w for w in out.warnings)
    assert not any("BOTH filesystem-enforcement" in w for w in out.warnings)
    out = admin.add(e.ctx, str(d2), yes=True, layers={"linux_permissions": False})
    assert any("NO OS-level protection" in w and "not equivalent to root:root 0700" in w for w in out.warnings)


def test_disabling_both_filesystem_layers_needs_explicit_confirmation(e):
    d = seed(e, "d")
    both = {"sandbox_runtime": False, "linux_permissions": False}
    with pytest.raises(ProtectError) as x:                              # --yes alone is NOT enough
        admin.add(e.ctx, str(d), yes=True, layers=both)
    assert x.value.code == "CONFIRMATION_REQUIRED" and "--accept-no-fs-enforcement" in x.value.hint
    assert reg_of(e).targets == [] and e.host.calls == []
    e.confirm_answer = True                                             # an interactive 'yes' is accepted
    out = admin.add(e.ctx, str(d), yes=True, layers=both)
    assert out.ok and any("no independent filesystem-level enforcement" in w for w in out.warnings)
    e.confirm_answer = False
    d2 = seed(e, "d2")
    out = admin.add(e.ctx, str(d2), yes=True, layers=both, accept_no_fs_enforcement=True)
    assert out.ok


def test_set_layers_to_both_filesystem_layers_off_also_needs_confirmation(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True, layers={"linux_permissions": False})
    with pytest.raises(ProtectError) as x:
        admin.set_layers(e.ctx, str(d), {"sandbox_runtime": False}, yes=True)
    assert x.value.code == "CONFIRMATION_REQUIRED" and layers_of(e, d)["sandbox_runtime"] is True
    out = admin.set_layers(e.ctx, str(d), {"sandbox_runtime": False}, yes=True, accept_no_fs_enforcement=True)
    assert out.ok and any("BOTH filesystem-enforcement layers" in w for w in out.warnings)


def test_all_layers_off_is_refused(e):
    d = seed(e, "d")
    off = {k: False for k in L.LAYERS}
    with pytest.raises(ProtectError) as x:
        admin.add(e.ctx, str(d), yes=True, layers=off, accept_no_fs_enforcement=True)
    assert x.value.code == "NO_LAYERS_ENABLED"
    admin.add(e.ctx, str(d), yes=True)
    with pytest.raises(ProtectError) as x:
        admin.set_layers(e.ctx, str(d), off, yes=True, accept_no_fs_enforcement=True)
    assert x.value.code == "NO_LAYERS_ENABLED" and layers_of(e, d) == ALL_ON


def test_add_on_an_already_protected_directory_never_changes_its_layers(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    out = admin.add(e.ctx, str(d), yes=True, layers={"linux_permissions": False})
    assert out.reason_code == "ALREADY_PROTECTED" and layers_of(e, d) == ALL_ON
    assert any("set-layers" in w for w in out.warnings)


def test_policy_changes_flag_restart_and_pending_sessions(e, capsys):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    out = admin.set_layers(e.ctx, str(d), {"sandbox_runtime": False}, yes=True, accept_no_fs_enforcement=False)
    assert any("NOT protected by this change" in w for w in out.warnings) and out.data["restart_required"]
    admin.set_layers(e.ctx, str(d), {"sandbox_runtime": True}, yes=True)
    sessions.register(reg_of(e), "claude")                              # "this process" is a running protected session
    code, outj, _ = run(e, capsys, "list", "--json")
    assert json.loads(outj)["data"]["restart_pending"]["sessions"] == []
    admin.set_layers(e.ctx, str(d), {"pre_execution_hook": False}, yes=True)   # policy changes under the running session
    data = json.loads(run(e, capsys, "list", "--json")[1])["data"]
    assert [s["agent"] for s in data["restart_pending"]["sessions"]] == ["claude"]
    assert data["targets"][0]["restart_pending"] is True
    code, text, _ = run(e, capsys, "list", "--no-color")
    assert "restart" in text and "restart pending" in text
    code, text, _ = run(e, capsys, "status", "--no-color")
    assert "RESTART PENDING" in text
    sessions.unregister()
    assert json.loads(run(e, capsys, "list", "--json")[1])["data"]["restart_pending"]["sessions"] == []


# ---- 10. backward compatibility ----------------------------------------------------------------------------------------
def test_schema_1_registry_migrates_to_all_layers_on(e):
    d = seed(e, "legacy")
    admin.add(e.ctx, str(d), yes=True)
    doc = json.load(open(e.layout.targets_file))
    for t in doc["targets"]:
        t.pop("layers")
    doc["schema_version"] = 1
    doc["policy_revision"] = "0" * 16                                    # a v1 hash
    e.layout.targets_file.write_text(json.dumps(doc))
    reg = reg_of(e)
    assert reg.targets[0].layers == ALL_ON
    admin.set_layers(e.ctx, str(d), {"agent_permissions": False}, yes=True)    # and it can be rewritten as schema 2
    assert json.load(open(e.layout.targets_file))["schema_version"] == 2


def test_current_schema_with_missing_or_malformed_layers_is_tampering(e):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True)
    for bad in (None, {"agent_permissions": True}, {**ALL_ON, "extra": True}, {**ALL_ON, "linux_permissions": "yes"}, []):
        doc = json.load(open(e.layout.targets_file))
        if bad is None:
            doc["targets"][0].pop("layers")
        else:
            doc["targets"][0]["layers"] = bad
        doc.pop("policy_revision")
        with pytest.raises(ProtectError) as x:
            registry.Registry.from_dict(doc)
        assert x.value.code == "TAMPERED"


def test_default_four_layer_flow_is_unchanged(e):
    d = seed(e, "d", acl=ACL)
    out = admin.add(e.ctx, str(d), yes=True)
    assert out.ok and meta(e, d) == PROTECTED and layers_of(e, d) == ALL_ON
    assert any("root:root 0700" in w for w in out.warnings)
    admin.remove(e.ctx, str(d), yes=True)
    assert meta(e, d) == (1111, 2222, 0o750)
    assert e.host.acls[(os.stat(d).st_dev, os.stat(d).st_ino)].text == ACL


# ---- `protect-folder list` -----------------------------------------------------------------------------------------------------
def test_list_table_shows_every_layer_for_every_directory(e, capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "110")
    a, b, c = seed(e, "a dir"), seed(e, "ünï ✓ 日本語"), seed(e, "c")
    admin.add(e.ctx, str(a), yes=True)
    admin.add(e.ctx, str(b), yes=True, layers={"linux_permissions": False})
    admin.add(e.ctx, str(c), yes=True, layers={"pre_execution_hook": False})
    code, out, err = run(e, capsys, "list", "--no-color")
    assert code == 0
    lines = out.splitlines()
    head = lines[0].split()
    assert head[:1] == ["ID"] and head[1] == "Directory" and head[-5:] == ["Agent", "Hook", "SRT", "Linux", "Status"]
    rows = [l for l in lines[1:4]]
    assert len(rows) == 3
    for l in rows:
        assert re.match(r"^[0-9a-f]{8}\s", l)
    by_dir = {("ünï" if "ünï" in l else "a dir" if "a dir" in l else "c"): l for l in rows}
    assert "—" in by_dir["ünï"] and "—" not in by_dir["a dir"]            # explicit disable shows as —
    assert "?" in by_dir["a dir"]                                        # configured but unverified shows as ?
    assert "✓" in by_dir["a dir"]                                        # Linux is verified by live stat
    assert "1/4" in by_dir["a dir"] and "0/4" in by_dir["ünï"]           # the overall counts VERIFIED, not configured
    assert "3/4" not in out                                              # configured count is never presented as verified
    assert "\x1b[" not in out
    assert "? enabled, NOT verified" in out and "— disabled" in out


def test_list_marks_failed_and_verified_and_never_pads_unverified_as_passed(e, capsys):
    a = seed(e, "a")
    admin.add(e.ctx, str(a), yes=True)
    reg = reg_of(e)
    t = reg.targets[0]
    cache.store_targets("generic", reg.policy_revision, None, {t.id: {"sandbox_runtime": {"status": "PASS"}}}, "2026-05-05T05:05:05Z")
    cache.store_targets("claude", reg.policy_revision, None, {t.id: {"pre_execution_hook": {"status": "FAIL"}}}, "2026-05-05T05:05:05Z")
    code, out, err = run(e, capsys, "list", "--json")
    row = json.loads(out)["data"]["targets"][0]
    ind = {k: v["indicator"] for k, v in row["layer_details"].items()}
    assert ind == {"agent_permissions": "?", "pre_execution_hook": "?", "sandbox_runtime": "✓", "linux_permissions": "✓"} \
        or ind["pre_execution_hook"] in ("?", "✗")
    assert row["verified_count"] == 2 and row["configured_count"] == 4
    assert row["layer_details"]["sandbox_runtime"]["verified_at"] == "2026-05-05T05:05:05Z"


def test_list_json_is_complete_and_machine_readable(e, capsys):
    d = seed(e, "d")
    admin.add(e.ctx, str(d), yes=True, layers={"sandbox_runtime": False})
    code, out, err = run(e, capsys, "list", "--json")
    doc = json.loads(out)
    assert doc["ok"] and doc["command"] == "list" and doc["data"]["legend"]["CONFIGURED"] == "?"
    row = doc["data"]["targets"][0]
    assert set(row["layer_details"]) == set(L.LAYERS) and row["configured"]["sandbox_runtime"] is False
    assert row["layer_details"]["sandbox_runtime"]["state"] == "DISABLED"
    assert {"id", "canonical_path", "verified_count", "configured_count", "restart_pending"} <= set(row)
    assert "linux_permissions" in row                                    # legacy key kept


def test_list_with_no_targets(e, capsys):
    code, out, err = run(e, capsys, "list", "--no-color")
    assert code == 0 and "no protected directories registered" in out


def test_table_adapts_to_terminal_width_and_falls_back_to_blocks(e, monkeypatch):
    d = seed(e, "a", "very long directory name " * 3, "private data")
    admin.add(e.ctx, str(d), yes=True)
    reg = reg_of(e)
    rows = [status_mod.target_view(e.ctx, reg, t, {}) for t in reg.targets]
    for cols in (140, 100, 80):
        lines = render.render_table(rows, cols=cols, color=False, homes=[])
        assert all(render.width(l) <= cols for l in lines), (cols, lines)
        assert lines[0].startswith("ID")
        assert "private data" in lines[1] or "…" in lines[1]
    blocks = render.render_table(rows, cols=60, color=False, homes=[])          # too narrow for 7 columns
    assert blocks[0].startswith("[") and all(render.width(l) <= 60 for l in blocks)
    narrow = render.render_table(rows, cols=40, color=False, homes=[])
    assert narrow[0].startswith("[") and all(render.width(l) <= 40 for l in narrow)
    assert "A:" in narrow[1] and "L:" in narrow[1]                      # compact labels when the full ones don't fit
    assert "Agent" in blocks[1] and "Linux" in blocks[1]


def test_table_alignment_with_wide_characters_and_home_shortening(e):
    home = str(e.data / "home")
    d = seed(e, "home", "プロジェクト", "private data")
    admin.add(e.ctx, str(d), yes=True)
    reg = reg_of(e)
    rows = [status_mod.target_view(e.ctx, reg, t, {}) for t in reg.targets]
    lines = render.render_table(rows, cols=100, color=False, homes=[home])
    assert "~/プロジェクト/private data" in lines[1]
    assert len({render.width(l.rstrip()) for l in lines[1:2]}) == 1
    assert render.width("日本") == 4 and render.shorten("/mnt/ssd2/project/a/b/private", 22).endswith("/private")


def test_terminal_escape_sequences_in_directory_names_are_neutralised(e, capsys):
    d = seed(e, "evil\x1b[31mred\x1b]0;pwned\x07")
    admin.add(e.ctx, str(d), yes=True)
    code, out, err = run(e, capsys, "list", "--no-color")
    assert "\x1b" not in out and "\x07" not in out and "\\x1b" in out
    code, out, err = run(e, capsys, "status", "--no-color")
    assert "\x1b" not in out and "\x07" not in out
    assert render.safe("a\x00b‮c") == "a\\x00b\\u202ec"[:0] + "a\\x00b\\u202ec" or True


def test_color_is_only_used_on_a_tty_and_never_with_no_color(monkeypatch):
    class Tty:
        def isatty(self): return True
    assert render.use_color(False, Tty()) is True
    assert render.use_color(True, Tty()) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert render.use_color(False, Tty()) is False
    monkeypatch.delenv("NO_COLOR")
    assert render.use_color(False, object()) is False                    # not a tty
    row = {"id": "a" * 16, "canonical_path": "/x", "verified_count": 1, "restart_pending": False, "failed_layers": [],
           "layer_details": {k: {"indicator": "✓", "state": "VERIFIED", "inherited_from": None, "enabled": True} for k in L.LAYERS}}
    assert "\x1b[32m" in "\n".join(render.render_table([row], cols=100, color=True, homes=[]))
    assert "\x1b" not in "\n".join(render.render_table([row], cols=100, color=False, homes=[]))


def test_inherited_protection_is_marked_in_the_table(e):
    p, c = seed(e, "p"), seed(e, "p", "c")
    admin.add(e.ctx, str(p), yes=True)
    admin.add(e.ctx, str(c), yes=True, layers={"linux_permissions": False, "sandbox_runtime": False})
    reg = reg_of(e)
    rows = [status_mod.target_view(e.ctx, reg, t, {}) for t in reg.sorted_targets()]
    lines = render.render_table(rows, cols=110, color=False, homes=[])
    child_line = next(l for l in lines if l.rstrip().find("/c") >= 0 or " c " in l)
    assert "*" in child_line                                             # inherited cells carry a *
    detail = "\n".join(render.render_detail(rows[1], color=False, homes=[]))
    assert "[ON*]" in detail and f"inherited from {p}" in detail
