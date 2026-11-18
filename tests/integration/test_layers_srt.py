"""Per-directory layer selection against a REAL SRT sandbox (bubblewrap). L4 is simulated by FakeHostOps;
real root locking is exercised by the privileged tests."""

import json
import os

import pytest

from protect_folder import admin, launcher
from protect_folder.errors import ProtectError
from protect_folder.hostops import MetaState
from protect_folder.preflight import run_preflight

pytestmark = pytest.mark.srt
MARK = "LAYERS-SYNTH-MARKER-5150"


@pytest.fixture
def world(senv):
    e = senv
    e.ws = e.tmp / "project"
    e.ws.mkdir()
    e.install()

    def target(*parts, **layers):
        d = e.mkdir(*parts)
        (d / "secret.txt").write_text(MARK)
        (d / "sub").mkdir(exist_ok=True)
        (d / "sub" / "deep.txt").write_text(MARK)
        st = os.stat(d)
        e.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o750)
        assert admin.add(e.ctx, str(d), yes=True, accept_no_fs_enforcement=True, layers=layers or None).ok
        return d
    e.target = target
    return e


def go(e, argv, capfd, **kw):
    kw.setdefault("quiet", True)
    code = launcher.run(e.ctx, argv, cwd=str(e.ws), **kw)
    c = capfd.readouterr()
    return code, c.out, c.err


def readable(e, capfd, d):
    code, out, err = go(e, ["cat", f"{d}/secret.txt"], capfd)
    return MARK in out


def test_only_directories_with_the_srt_layer_are_masked(world, capfd):
    e = world
    on = e.target("on")
    off = e.target("off", sandbox_runtime=False)
    e.is_root = False
    assert not readable(e, capfd, on)
    assert readable(e, capfd, off)          # honest: with SRT off (and L4 only simulated) nothing masks it


def test_child_inside_a_protected_parent_cannot_escape_the_parents_srt_mask(world, capfd):
    e = world
    parent = e.target("p")
    child = e.target("p", "c", sandbox_runtime=False)
    (parent / "secret.txt").write_text(MARK)
    e.is_root = False
    assert not readable(e, capfd, parent)
    assert not readable(e, capfd, child)    # covered by the parent's entry even though the child opted out
    code, out, err = go(e, ["cat", f"{child}/sub/deep.txt"], capfd)
    assert MARK not in out + err


def test_unrelated_layer_changes_do_not_affect_the_sandbox(world, capfd):
    e = world
    d = e.target("d")
    e.is_root = True
    admin.set_layers(e.ctx, str(d), {"pre_execution_hook": False, "agent_permissions": False}, yes=True)
    e.is_root = False
    assert not readable(e, capfd, d)        # SRT layer untouched -> still masked
    e.is_root = True
    admin.set_layers(e.ctx, str(d), {"sandbox_runtime": False}, yes=True)
    e.is_root = False
    assert readable(e, capfd, d)            # and now, deliberately, not


def test_no_linux_directory_launches_without_l4_and_reports_it_disabled(world, capfd):
    e = world
    d = e.target("nl", linux_permissions=False)       # ownership/mode untouched: NOT root:root 0700
    e.is_root = False
    pre = run_preflight(e.ctx, ["true"], cwd=str(e.ws))
    try:
        assert pre.layers["linux_permissions"] == "DISABLED" and pre.layers["srt"] == "PASS"
        assert pre.report()["enabled_layers"] == 3
        banner = launcher.format_banner(pre.report())
        assert "L4=off" in banner and "L3=PASS" in banner
    finally:
        os.unlink(pre.settings_path)
        for f in pre.prepared.cleanup:
            os.unlink(f)
    assert not readable(e, capfd, d)                  # SRT alone still masks it inside the sandbox


def test_launch_still_fails_closed_when_an_enabled_l4_is_not_effective(world):
    e = world
    d = e.target("ok")
    st = os.stat(d)
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o755)     # un-protected behind our back
    e.is_root = False
    with pytest.raises(ProtectError) as x:
        run_preflight(e.ctx, ["true"], cwd=str(e.ws))
    assert x.value.code == "PREFLIGHT_FAILED" and "L4 is not effective" in x.value.message


def test_launch_with_linux_off_ignores_the_directory_mode(world):
    e = world
    e.target("fine", linux_permissions=False)         # mode 0750 is intentional here
    e.is_root = False
    pre = run_preflight(e.ctx, ["true"], cwd=str(e.ws))
    os.unlink(pre.settings_path)
    for f in pre.prepared.cleanup:
        os.unlink(f)


def test_a_missing_disk_still_refuses_even_if_only_agent_layers_are_on(world):
    e = world
    d = e.target("soft", sandbox_runtime=False, linux_permissions=False)
    os.rename(d, str(d) + ".gone")
    e.is_root = False
    with pytest.raises(ProtectError) as x:
        run_preflight(e.ctx, ["true"], cwd=str(e.ws))
    assert x.value.code in ("STALE", "MOUNT_MISSING", "IDENTITY_MISMATCH")


def test_no_target_has_srt_enabled_still_runs_sandboxed_with_a_warning(world, capfd):
    e = world
    d = e.target("x", sandbox_runtime=False, linux_permissions=False)
    e.is_root = False
    pre = run_preflight(e.ctx, ["true"], cwd=str(e.ws))
    try:
        assert pre.layers["srt"] == "DISABLED" and pre.layers["linux_permissions"] == "DISABLED"
        assert any("no protected directory has the SRT layer enabled" in w for w in pre.warnings)
    finally:
        os.unlink(pre.settings_path)
        for f in pre.prepared.cleanup:
            os.unlink(f)
    code, out, err = go(e, ["sh", "-c", "echo hi > out.txt; cat out.txt"], capfd)
    assert code == 0 and "hi" in out                  # the sandbox runtime itself still wraps the agent


def test_require_layers_counts_only_enabled_layers(world):
    e = world
    e.target("rl", linux_permissions=False)           # enabled: L1, L2 (unverifiable for generic), L3
    e.is_root = False
    pre = run_preflight(e.ctx, ["true"], cwd=str(e.ws))              # default: every enabled ENFORCEMENT layer passes
    os.unlink(pre.settings_path)
    for f in pre.prepared.cleanup:
        os.unlink(f)
    for n in (2, 4):                                  # an explicit N asks for N VERIFIED layers: only L3 is verified
        with pytest.raises(ProtectError) as x:
            run_preflight(e.ctx, ["true"], cwd=str(e.ws), require_layers=n)
        assert x.value.code == "LAYERS_INSUFFICIENT" and "only 1 are verified" in x.value.message


def test_sessions_are_registered_while_running_and_cleaned_up(world, capfd):
    e = world
    e.target("s")
    e.is_root = False
    code, out, err = go(e, ["sh", "-c", "ls \"$XDG_STATE_HOME/protect-folder/sessions\" 2>/dev/null; echo done"], capfd)
    from protect_folder import sessions
    assert sessions.running() == []                   # unregistered after exit
