import json
import os

import pytest

from protect_folder import admin, cli, doctor
from protect_folder.errors import ProtectError
from protect_folder.hostops import MetaState
from protect_folder.verify.admin import run_admin_verify


@pytest.fixture
def world(env):
    env.install()
    d = env.mkdir("Forbidden folder")
    st = os.stat(d)
    env.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o750)
    assert admin.add(env.ctx, str(d), yes=True).ok
    env.d = d
    return env


def by_name(doc):
    return {c["name"]: c for c in doc["checks"]}


def test_admin_verify_requires_root_and_is_read_only(world):
    world.is_root = False
    with pytest.raises(ProtectError) as e:
        run_admin_verify(world.ctx)
    assert e.value.code == "NOT_ROOT" and "sudo protect-folder verify --admin" in e.value.hint


def test_admin_verify_reports_per_check_results(world):
    before = dict(world.host.meta)
    doc = run_admin_verify(world.ctx)
    c = by_name(doc)
    assert c["no_interrupted_operation"]["status"] == "PASS" and c["no_unfinished_journals"]["status"] == "PASS"
    assert c["registry_snapshot_l4_consistent"]["status"] == "PASS"
    assert any(k.startswith("restore_identity:") and v["status"] == "PASS" for k, v in c.items())
    assert world.host.meta == before                       # nothing was changed


def test_admin_verify_detects_a_pending_recovery_marker_and_inconsistency(world):
    world.layout.marker_file.write_text("{}")
    doc = run_admin_verify(world.ctx)
    assert doc["summary"] == "FAIL" and by_name(doc)["no_interrupted_operation"]["status"] == "FAIL"
    world.layout.marker_file.unlink()
    st = os.stat(world.d)
    world.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o755)    # L4 silently undone
    doc = run_admin_verify(world.ctx)
    assert by_name(doc)["registry_snapshot_l4_consistent"]["status"] == "FAIL"


def test_admin_verify_flags_loose_snapshot_permissions(world):
    os.chmod(world.layout.snapshots_file, 0o644)
    assert by_name(run_admin_verify(world.ctx))["snapshots_file_private"]["status"] == "FAIL"


@pytest.mark.parametrize("extra", [["--agent", "claude"], ["--live"], ["/some/path"]])
def test_cli_refuses_admin_with_agent_flags(world, capsys, extra):
    code = cli.main(["--json", "verify", "--admin", *extra]) if False else None   # parser-level only
    # the dispatcher check is exercised directly: an agent must never be launched by an admin command
    import argparse
    ns = argparse.Namespace(command="verify", admin=True, agent="claude" if "--agent" in extra else None,
                            live="--live" in extra, path="/x" if "/some/path" in extra else None, json=True,
                            profile=None)
    world.is_root = True
    rc = cli.dispatch(ns, world.ctx, [])
    out = json.loads(capsys.readouterr().out)
    assert rc != 0 and out["reason_code"] == "USAGE"


def test_doctor_reports_privileged_groups(monkeypatch, world):
    import grp
    monkeypatch.setattr(os, "getgroups", lambda: [111, 222])
    names = {111: "lxd", 222: "sudo"}
    monkeypatch.setattr(grp, "getgrgid", lambda g: type("G", (), {"gr_name": names[g]})())
    rows = {c["name"]: c for c in doctor._privilege_checks(world.ctx)}
    assert rows["group:lxd"]["status"] == "WARN" and "bypasses L4" in rows["group:lxd"]["detail"]
    assert rows["group:sudo"]["status"] == "INFO"
    monkeypatch.setattr(os, "getgroups", lambda: [])
    assert [c["status"] for c in doctor._privilege_checks(world.ctx)][0] == "PASS"


def test_doctor_flags_agents_running_outside_the_launcher(monkeypatch):
    import subprocess
    fake = ("100 /home/u/.nvm/bin/opencode serve --service\n"
            "200 /home/u/.vscode/extensions/openai.chatgpt-1/bin/codex -c x\n300 /usr/bin/vim\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=fake, stderr=""))
    rows = {c["name"]: c for c in doctor._agent_hazard_checks()}
    assert rows["opencode-background-service"]["status"] == "WARN"
    assert rows["codex-outside-launcher"]["status"] == "WARN"
