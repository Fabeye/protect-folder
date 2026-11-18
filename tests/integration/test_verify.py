import json
import os

import pytest

from protect_folder import admin, cli
from protect_folder.errors import EXIT_CODES
from protect_folder.policy import srt as srt_policy
from protect_folder.verify import runner

pytestmark = pytest.mark.srt


@pytest.fixture
def world(senv):
    e = senv
    ds = [e.mkdir("Forbidden folder"), e.mkdir("two", "private data")]
    for d in ds:
        (d / "secret.txt").write_text("x")
    e.install()
    for d in ds:
        assert admin.add(e.ctx, str(d), yes=True).ok
    e.is_root = False
    e.targets = ds
    return e


def by_name(layer):
    return {c["name"]: c for c in layer["checks"]}


def test_l3_verification_passes_with_evidence_and_classification(world):
    doc = runner.run_verify(world.ctx)
    srt = doc["layers"]["srt"]
    assert srt["status"] == "PASS", json.dumps(srt, indent=1)
    c = by_name(srt)
    assert c["precondition_fixture_readable_outside_sandbox"]["status"] == "PASS"
    assert c["effective_policy_masks_real_targets"]["status"] == "PASS"
    assert c["marker_absent_from_sandbox_output"]["status"] == "PASS"
    for name in runner.MUST_BE_BLOCKED:
        assert c[f"blocked:{name}"]["status"] == "PASS", name
        assert c[f"blocked:{name}"]["classification"].startswith("srt_")   # attributed to SRT, with evidence
    assert all(c[f"control:{n}"]["status"] == "PASS" for n in runner.CONTROLS)
    assert c["blocked:write_into_target"]["status"] == "PASS"
    assert doc["layers"]["native_permissions"]["status"] == "NOT_APPLICABLE"
    assert doc["layers"]["pre_execution_hook"]["status"] == "NOT_APPLICABLE"


def test_verify_detects_that_fake_l4_does_not_really_deny(world):
    """FakeHostOps reports root:root 0700 but the real directory is still user-readable, so the
    independent unprivileged-access test must FAIL. (Real L4 is proven in the privileged tests.)"""
    doc = runner.run_verify(world.ctx)
    l4 = by_name(doc["layers"]["linux_permissions"])
    t = world.targets[0]
    stat_check = next(v for k, v in l4.items() if k.endswith(":stat"))
    assert stat_check["status"] == "PASS"
    denied = next(v for k, v in l4.items() if k.endswith(":unprivileged_denied"))
    assert denied["status"] == "FAIL" and denied["classification"] == "not_denied"
    assert doc["layers"]["linux_permissions"]["status"] == "FAIL"
    assert doc["verified_layers"] == "1/4"


def test_verify_FAILS_when_the_policy_is_sabotaged(world, monkeypatch):
    """A verifier that cannot fail proves nothing: drop the fixture's deny rules and require FAIL."""
    real = srt_policy.compile_settings

    def sabotaged(ctx, targets, **kw):
        s = real(ctx, [t for t in targets if t.id != "verify-fixture"], **kw)
        return s
    monkeypatch.setattr(runner.srt_policy, "compile_settings", sabotaged)
    doc = runner.run_verify(world.ctx)
    srt = doc["layers"]["srt"]
    assert srt["status"] == "FAIL"
    c = by_name(srt)
    assert c["blocked:read_direct"]["status"] == "FAIL" and c["blocked:read_direct"]["classification"] == "leak"


def test_verify_integrity_failures_are_reported(world):
    os.chmod(world.layout.targets_file, 0o666)
    doc = runner.run_verify(world.ctx)
    assert doc["integrity"]["status"] == "FAIL"
    assert doc["layers"]["srt"]["status"] == "UNVERIFIED"          # nothing is claimed without a trusted registry


def test_verify_stale_target_is_reported_not_passed(world):
    os.rename(world.targets[0], str(world.targets[0]) + ".moved")
    doc = runner.run_verify(world.ctx)
    ident = [c for c in doc["integrity"]["checks"] if c["name"].startswith("identity:")]
    assert any(c["status"] == "STALE" for c in ident)
    assert doc["layers"]["linux_permissions"]["status"] != "PASS"


def test_verify_cli_json_and_exit_code(world, capsys):
    code = cli.main(["verify", "--json"], world.ctx)
    doc = json.loads(capsys.readouterr().out)
    assert doc["command"] == "verify" and doc["data"]["verified_layers"] in ("1/4", "2/4")
    assert code == EXIT_CODES["VERIFY_FAILED"] and doc["reason_code"] == "VERIFY_FAILED"   # fake L4 -> FAIL
    assert set(doc["data"]["summary"]) == {"native_permissions", "pre_execution_hook", "srt", "linux_permissions"}


def test_verify_never_leaves_fixture_or_settings_behind(world):
    before = set(os.listdir(os.path.expanduser("~/.local/state/protect-folder"))) if os.path.isdir(
        os.path.expanduser("~/.local/state/protect-folder")) else set()
    runner.run_verify(world.ctx)
    after = set(os.listdir(os.path.expanduser("~/.local/state/protect-folder"))) if os.path.isdir(
        os.path.expanduser("~/.local/state/protect-folder")) else set()
    assert not [n for n in after - before if n.startswith("verify-") and n != "verify.json"]
