import argparse
import subprocess
import sys
from pathlib import Path

import pytest

from protect_folder import cli, helptext
from protect_folder.errors import EXIT_CODES

ROOT = Path(__file__).resolve().parents[2]


def parser_options():
    p = cli.build_parser()
    sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
    for name, sp in sub.choices.items():
        for a in sp._actions:
            if not isinstance(a, argparse._HelpAction):
                yield name, a


@pytest.mark.parametrize("name,action", [(n, a) for n, a in parser_options()],
                         ids=lambda v: v if isinstance(v, str) else (v.option_strings[:1] or [v.dest])[0])
def test_every_argument_and_option_has_a_description(name, action):
    assert action.help and action.help != argparse.SUPPRESS, f"{name} {action.option_strings or action.dest} lacks help"


def run_help(capsys, *args):
    rc = cli.main(["help", *args])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def test_help_overview_lists_every_command_and_topic(capsys):
    rc, out, _ = run_help(capsys)
    assert rc == 0
    for c in cli.SUBCOMMANDS:
        assert c in out
    for t in helptext.topic_names():
        assert t in out


def test_help_all_contains_every_option_string_and_no_placeholder(capsys):
    rc, out, _ = run_help(capsys, "all")
    assert rc == 0 and "==SUPPRESS==" not in out
    for name, a in parser_options():
        for o in a.option_strings:
            assert o in out, f"{name} {o} missing from 'help all'"


@pytest.mark.parametrize("topic", helptext.topic_names())
def test_every_topic_renders(capsys, topic):
    rc, out, _ = run_help(capsys, topic)
    assert rc == 0 and len(out.strip().splitlines()) >= 3


def test_exit_codes_topic_is_derived_from_the_real_table(capsys):
    _, out, _ = run_help(capsys, "exit-codes")
    assert all(code in out for code in EXIT_CODES)


def test_profiles_topic_lists_every_builtin_profile(capsys):
    from protect_folder.policy.profiles import BUILTIN_PROFILES
    _, out, _ = run_help(capsys, "profiles")
    assert all(n in out for n in BUILTIN_PROFILES)


def test_help_for_a_command_equals_its_own_help(capsys):
    _, out, _ = run_help(capsys, "set-layers")
    assert "--all" in out and "--no-hook" in out


def test_unknown_topic_is_an_error_on_stderr(capsys):
    rc, out, err = run_help(capsys, "nope")
    assert rc == 2 and not out and "no help for 'nope'" in err


def test_bare_invocation_points_to_help(capsys):
    assert cli.main([]) == 0
    assert "protect-folder help" in capsys.readouterr().out


def test_markdown_reference_is_not_stale():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_cli_reference.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, "CLI_REFERENCE.md is stale: run python3 scripts/gen_cli_reference.py"


# ---- EXAMPLES.md: every protect-folder command line must parse with the real parser ---------------------------------
def _example_commands():
    import re
    import shlex
    text = (ROOT / "EXAMPLES.md").read_text()
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("PF_") and "protect-folder" not in line:
                continue
            line = re.sub(r"^PF_\w+=\S+\s+", "", line)
            line = re.sub(r"^sudo\s+", "", line)
            if not line.startswith("protect-folder "):
                continue
            line = line.split(" | ")[0]
            line = re.split(r";\s*echo|\s#\s", line)[0]
            yield shlex.split(line, comments=True)[1:]


EXAMPLES = list(_example_commands())


def test_examples_file_has_a_meaningful_number_of_commands():
    assert len(EXAMPLES) >= 60


@pytest.mark.parametrize("argv", EXAMPLES, ids=lambda a: " ".join(a)[:70])
def test_every_example_command_parses(argv):
    head, run_argv = cli.split_run_argv(argv)
    ns = cli.build_parser().parse_args(head)       # SystemExit (exit 2) on an unknown flag/command
    assert ns.command in cli.SUBCOMMANDS
    if ns.command == "run":
        assert run_argv, "run example without a command after --"


def test_examples_mention_every_command():
    text = (ROOT / "EXAMPLES.md").read_text()
    for c in cli.SUBCOMMANDS:
        assert f"protect-folder {c}" in text, f"EXAMPLES.md has no example for '{c}'"
