"""The shell scripts: syntax and every refusal that does not need root. (Their root paths are exercised by the
privileged suite and by scripts/acceptance.sh on real disks; they are NOT run here.)"""

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [ROOT / "install.sh", ROOT / "uninstall.sh", ROOT / "scripts" / "acceptance.sh"]
pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="these tests assert the non-root refusals")


def run(script, *args):
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_syntax_and_executable(script):
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    assert os.access(script, os.X_OK)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_help_exits_zero_and_unknown_option_exits_two(script):
    assert run(script, "--help").returncode == 0
    assert run(script, "--definitely-not-an-option").returncode == 2


def test_install_refuses_without_root_and_never_calls_sudo():
    p = run(ROOT / "install.sh")
    assert p.returncode == 3 and "must run as root" in p.stderr
    src = (ROOT / "install.sh").read_text()
    import re
    code = src.split("<<'MSG'")[0]                                                       # the heredoc is user-facing text
    assert not re.search(r"^\s*(exec\s+)?sudo\b|\$\(sudo\b|\|\s*sudo\b", code, re.M)       # never executes sudo itself
    assert "curl" not in src and "wget" not in src and "pip install" not in src          # downloads nothing


def test_install_dry_run_changes_nothing_and_stages_a_root_owned_copy():
    p = run(ROOT / "install.sh", "--dry-run")
    assert p.returncode == 0, p.stderr
    assert "staged source tree sha256" in p.stdout and "dry run:" in p.stdout
    src = (ROOT / "install.sh").read_text()
    assert "chown -R root:root" in src and "python3 -I" in src.replace("$PY\" -I", "python3 -I")


def test_uninstall_and_acceptance_refuse_without_root():
    assert run(ROOT / "uninstall.sh").returncode == 3
    p = run(ROOT / "scripts" / "acceptance.sh", "/tmp")
    assert p.returncode == 3 and "sudo" in p.stderr
    assert run(ROOT / "scripts" / "acceptance.sh").returncode == 2        # no paths => usage


def test_uninstall_refuses_while_directories_are_protected_unless_restore_all():
    src = (ROOT / "uninstall.sh").read_text()
    assert "--restore-all" in src and "still protected" in src and "exit 4" in src
    assert "nothing else was removed" in src                                 # a failed restore stops everything


# ---- node / sandbox-runtime discovery (found while running install.sh under sudo for real) ---------------------
def _fake_srt_pkg(root, name="@anthropic-ai/sandbox-runtime", version="0.0.83", cli=True):
    pkg = root / "lib" / "node_modules" / "@anthropic-ai" / "sandbox-runtime"
    (pkg / "dist").mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": name, "version": version}))
    if cli:
        (pkg / "dist" / "cli.js").write_text("//")
    (root / "bin").mkdir(exist_ok=True)
    node = root / "bin" / "node"
    node.write_text("#!/bin/sh\n")
    node.chmod(0o755)
    return pkg, node


def test_explicit_srt_package_is_validated_and_never_guessed(tmp_path):
    from protect_folder import install as inst
    from protect_folder.errors import ProtectError
    pkg, node = _fake_srt_pkg(tmp_path / "good")
    assert inst.find_node_and_srt(node, pkg) == (node.resolve(), pkg.resolve())
    for i, bad in enumerate((dict(name="srt"), dict(version="9.9.9"), dict(cli=False))):
        p2, _ = _fake_srt_pkg(tmp_path / f"bad{i}", **bad)
        with pytest.raises(ProtectError) as e:
            inst.find_node_and_srt(node, p2)
        assert e.value.code == "SRT_UNAVAILABLE"


def test_discovery_searches_the_sudo_users_nvm_and_ignores_a_foreign_srt_on_path(tmp_path, monkeypatch):
    """Under sudo, `srt` on root's PATH was an unrelated Python script; the installer must not use it."""
    from protect_folder import install as inst
    home = tmp_path / "home"
    ver = home / ".nvm" / "versions" / "node" / "v22.1.0"
    pkg, node = _fake_srt_pkg(ver)
    foreign = tmp_path / "usrlocal" / "bin"
    foreign.mkdir(parents=True)
    (foreign / "srt").write_text("#!/usr/bin/python3\nprint('subtitle tool')\n")
    (foreign / "srt").chmod(0o755)
    monkeypatch.setenv("PATH", str(foreign))
    monkeypatch.setattr(inst, "_user_homes", lambda: [home])
    got_node, got_pkg = inst.find_node_and_srt()
    assert got_pkg == pkg.resolve() and got_node == node.resolve()
    monkeypatch.setattr(inst, "_user_homes", lambda: [])        # nothing of the user's: the foreign srt alone fails
    from protect_folder.errors import ProtectError
    with pytest.raises(ProtectError) as e:
        inst.find_node_and_srt()
    assert e.value.code == "SRT_UNAVAILABLE" and any("not @anthropic-ai/sandbox-runtime" in x or "no readable" in x
                                                    for x in e.value.details["skipped"])


def test_acceptance_script_cleans_up_when_interrupted_and_bounds_live_steps():
    """Text-level guard only: the trap itself needs root and real directories (exercised by running the script)."""
    s = Path("scripts/acceptance.sh").read_text()
    assert "trap 'cleanup; exit 130' INT TERM" in s and "trap 'cleanup' EXIT" in s
    assert 'CURRENT_T="$T"' in s and 'CURRENT_T=""' in s          # set when a fixture exists, cleared after removal
    assert "timeout 900" in s                                     # a hung live agent cannot wedge the run forever
    assert "user_has" in s and 'command -v "$ag"' not in s          # agents are looked up on the operator's PATH
