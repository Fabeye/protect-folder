import json

import pytest

from protect_folder import cli
from protect_folder.errors import EXIT_CODES


def run(env, capsys, *argv):
    code = cli.main(list(argv), env.ctx)
    out = capsys.readouterr()
    return code, out.out, out.err


def jrun(env, capsys, *argv):
    code, out, err = run(env, capsys, *argv, "--json")
    return code, json.loads(out), err


def test_help_mentions_sudo_split_and_warning(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "Administrator commands (need sudo)" in out and "NOT a privilege boundary" in out
    for c in ("install", "doctor", "add", "remove", "list", "status", "verify", "logs", "run", "adapters", "version"):
        assert c in out


def test_version_json(env, capsys):
    code, doc, _ = jrun(env, capsys, "version")
    assert code == 0 and doc["schema"] == "protect-folder/1" and doc["data"]["version"] == "1.0.0"


def test_add_list_status_remove_json_contract(env, capsys):
    d = env.mkdir("Forbidden folder")
    code, doc, _ = jrun(env, capsys, "add", "--yes", str(d))
    assert code == 0 and doc["ok"] and doc["command"] == "add" and doc["reason_code"] == "OK"
    assert set(doc) == {"schema", "command", "ok", "reason_code", "message", "data", "warnings"}
    assert doc["data"]["target"]["canonical_path"] == str(d)

    code, doc, _ = jrun(env, capsys, "list")
    (row,) = doc["data"]["targets"]
    assert code == 0 and row["linux_permissions"] == "PASS" and row["canonical_path"] == str(d)
    assert {"id", "st_dev", "st_ino", "filesystem_type", "mount_point", "created_at"} <= set(row)

    code, doc, _ = jrun(env, capsys, "status")
    layers = doc["data"]["targets"][0]["layers"]
    assert code == 0 and doc["data"]["state"] == "OK"
    assert layers["linux_permissions"] == "PASS" and layers["srt"] == "UNVERIFIED"

    code, doc, _ = jrun(env, capsys, "status", str(d))
    assert code == 0 and len(doc["data"]["targets"]) == 1

    code, doc, _ = jrun(env, capsys, "remove", "--yes", str(d))
    assert code == 0 and doc["ok"]
    code, doc, _ = jrun(env, capsys, "list")
    assert doc["data"]["targets"] == []


def test_error_envelope_and_exit_codes(env, capsys):
    env.install()
    code, doc, _ = jrun(env, capsys, "remove", "--yes", "/nope/not/registered")
    assert code == EXIT_CODES["NOT_PROTECTED"] and not doc["ok"] and doc["reason_code"] == "NOT_PROTECTED"
    code, doc, _ = jrun(env, capsys, "add", "--yes", "/etc")
    assert code == EXIT_CODES["FORBIDDEN_PATH"] and doc["reason_code"] == "FORBIDDEN_PATH"
    env.is_root = False
    code, doc, _ = jrun(env, capsys, "add", "--yes", str(env.mkdir("y")))
    assert code == EXIT_CODES["NOT_ROOT"] and "sudo" in doc["hint"]


def test_leading_dash_path_after_double_dash(env, capsys):
    d = env.mkdir("-rf")
    code, out, _ = run(env, capsys, "add", "--json", "--yes", "--", str(d))   # flags before '--'
    assert code == 0 and json.loads(out)["data"]["target"]["canonical_path"] == str(d)
    code, out, err = run(env, capsys, "add", "--yes", "--", "-rf-nonexistent")
    assert code == EXIT_CODES["PATH_NOT_FOUND"]      # parsed as a path, not as an option


def test_already_protected_is_deterministic_json(env, capsys):
    d = env.mkdir("x")
    jrun(env, capsys, "add", "--yes", str(d))
    code, doc, _ = jrun(env, capsys, "add", "--yes", str(d))
    assert code == 0 and doc["ok"] and doc["reason_code"] == "ALREADY_PROTECTED"


def test_status_exit_code_when_degraded_and_recovery(env, capsys):
    d = env.mkdir("x")
    jrun(env, capsys, "add", "--yes", str(d))
    env.host.meta.clear()          # L4 vanishes (e.g. someone chmod'ed it back)
    code, doc, _ = jrun(env, capsys, "status")
    assert code == EXIT_CODES["STALE"] and doc["data"]["state"] == "DEGRADED"
    from protect_folder import transactions
    transactions.write_marker(env.ctx, "RECOVERY_REQUIRED", "t", "add")
    code, doc, _ = jrun(env, capsys, "status")
    assert code == EXIT_CODES["RECOVERY_REQUIRED"]


def test_logs_since_agent_and_json(env, capsys):
    d = env.mkdir("x")
    jrun(env, capsys, "add", "--yes", str(d))
    code, doc, _ = jrun(env, capsys, "logs")
    assert code == 0 and doc["data"]["records"][0]["op"] == "add"
    assert "root-managed" in doc["data"]["records"][0]["source"]
    code, doc, _ = jrun(env, capsys, "logs", "--agent", "claude")
    assert doc["data"]["records"] == []
    code, doc, _ = jrun(env, capsys, "logs", "--since", "2030-01-01")
    assert doc["data"]["records"] == []
    code, doc, _ = jrun(env, capsys, "logs", "--since", "bogus")
    assert code == EXIT_CODES["USAGE"]


def test_adapters_lists_declared_capabilities(env, capsys):
    code, doc, _ = jrun(env, capsys, "adapters")
    rows = {r["name"]: r for r in doc["data"]["adapters"]}
    assert code == 0 and rows["generic"]["layers"]["native_permissions"] == "NOT_APPLICABLE"
    assert rows["generic"]["layers"]["srt"] == "AVAILABLE"


def test_run_without_command_is_a_usage_error(env, capsys):
    code, doc, _ = jrun(env, capsys, "run")
    assert code == EXIT_CODES["USAGE"] and doc["reason_code"] == "USAGE"


def test_split_run_argv_preserves_command_verbatim():
    head, cmd = cli.split_run_argv(["run", "--profile", "claude", "--", "python3", "-c", "print('a  b')", "--", "-x"])
    assert head == ["run", "--profile", "claude"]
    assert cmd == ["python3", "-c", "print('a  b')", "--", "-x"]
    assert cli.split_run_argv(["add", "--", "-weird"]) == (["add", "--", "-weird"], [])
    assert cli.split_run_argv(["--json", "run", "--", "x"]) == (["--json", "run"], ["x"])


def test_doctor_runs(env, capsys):
    code, doc, _ = jrun(env, capsys, "doctor")
    names = {c["name"] for c in doc["data"]["checks"]}
    assert {"python", "bwrap", "socat", "rg", "recovery", "srt-runtime"} <= names
