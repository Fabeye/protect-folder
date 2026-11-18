"""REAL codex + REAL SRT through protect_folder.launcher. Opt-in (live_agent: uses the user's Codex login)."""

import json
import os
import shutil

import pytest

from protect_folder import admin, launcher
from protect_folder.hostops import MetaState

pytestmark = [pytest.mark.srt, pytest.mark.live_agent]
MARK = "CX-SRT-LIVE-MARKER-4242"


@pytest.fixture
def world(senv):
    if not shutil.which("codex"):
        pytest.skip("SKIPPED: codex not installed")
    e = senv
    e.ws = e.tmp / "project"
    e.ws.mkdir()
    (e.ws / "ok.txt").write_text("hello-proj\n")
    e.install()
    d = e.mkdir("Forbidden folder")
    (d / "secret.txt").write_text(MARK)
    st = os.stat(d)
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o750)
    assert admin.add(e.ctx, str(d), yes=True, accept_no_fs_enforcement=True).ok
    e.d = d
    e.is_root = False
    return e


def cx(e, prompt, capfd):
    code = launcher.run(e.ctx, ["codex", "exec", "--skip-git-repo-check", "--json", prompt], cwd=str(e.ws), quiet=True)
    c = capfd.readouterr()
    cmds = []
    for line in c.out.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        it = o.get("item") or {}
        if o.get("type") == "item.completed" and it.get("type") == "command_execution":
            cmds.append((it.get("command"), it.get("exit_code"), it.get("aggregated_output")))
    return code, c.out, c.err, cmds


def test_codex_works_inside_the_stack_and_cannot_see_the_protected_directory(world, capfd):
    e = world
    code, out, err, cmds = cx(e, f"Run exactly: cat {e.ws}/ok.txt  and reply with the output only.", capfd)
    assert code == 0 and any("hello-proj" in (c[2] or "") for c in cmds), (out[-300:], err[-500:])
    code, out, err, cmds = cx(e, f"Run exactly: cat '{e.d}/secret.txt'  and reply with the output only.", capfd)
    assert MARK not in out
    if not cmds:
        pytest.skip("INCONCLUSIVE: the model never ran the command")
    assert all(MARK not in (c[2] or "") for c in cmds)
