import pytest

from protect_folder.adapters import by_name, detect
from protect_folder.adapters.codex import first_subcommand
from protect_folder.errors import ProtectError


def prep(argv, targets=()):
    return by_name("codex").prepare(None, argv, {"PATH": "/usr/bin"}, "/w", list(targets), {})


def test_detect_and_capabilities_are_honest():
    ad = detect("/usr/local/bin/codex")
    assert ad.name == "codex" and ad.default_profile == "codex"
    assert ad.capabilities(None) == {"native_permissions": "UNSUPPORTED", "pre_execution_hook": "UNSUPPORTED"}
    p = prep(["codex", "exec", "hi"])
    assert p.layers == {"native_permissions": "UNSUPPORTED", "pre_execution_hook": "UNSUPPORTED"}
    assert any("UNSUPPORTED" in w for w in p.warnings)


@pytest.mark.parametrize("argv,expected", [
    (["codex", "exec", "hi"], ["codex", "exec", "--sandbox", "danger-full-access", "hi"]),
    (["codex", "e", "hi"], ["codex", "e", "--sandbox", "danger-full-access", "hi"]),
    (["codex", "-m", "gpt", "exec", "hi"], ["codex", "-m", "gpt", "exec", "--sandbox", "danger-full-access", "hi"]),
    (["codex", "hi"], ["codex", "--sandbox", "danger-full-access", "hi"]),
    (["codex"], ["codex", "--sandbox", "danger-full-access"]),
])
def test_sandbox_flag_goes_where_codex_accepts_it(argv, expected):
    assert prep(argv).argv == expected


@pytest.mark.parametrize("argv", [["codex", "exec", "-s", "read-only", "x"], ["codex", "--sandbox=workspace-write"],
                                  ["codex", "--yolo"], ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "x"]])
def test_explicit_sandbox_choice_is_respected_with_a_warning(argv):
    p = prep(argv)
    assert p.argv == argv and any("explicit sandbox" in w for w in p.warnings)


def test_sandbox_word_after_double_dash_is_prompt_text():
    p = prep(["codex", "exec", "--", "-s", "x"])
    assert p.argv[:3] == ["codex", "exec", "--sandbox"]


@pytest.mark.parametrize("argv", [["codex", "app-server"], ["codex", "remote-control"], ["codex", "exec-server"],
                                  ["codex", "agents"], ["codex", "--remote", "ws://x"], ["codex", "--remote=ws://x"],
                                  ["codex", "exec", "--remote-auth-token-env", "T", "x"]])
def test_server_and_remote_modes_are_refused(argv):
    with pytest.raises(ProtectError) as e:
        prep(argv)
    assert e.value.code == "PREFLIGHT_FAILED"


def test_remote_after_double_dash_is_not_a_flag():
    assert prep(["codex", "exec", "--", "--remote"]).argv[0] == "codex"


def test_first_subcommand_skips_option_values():
    assert first_subcommand(["codex", "-c", "a=b", "-m", "x", "exec", "p"]) == (5, "exec")
    assert first_subcommand(["codex", "--model=x", "review"]) == (2, "review")
    assert first_subcommand(["codex", "--", "exec"]) == (None, None)
