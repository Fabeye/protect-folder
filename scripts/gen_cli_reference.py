#!/usr/bin/env python3
"""Regenerate the complete option listing inside CLI_REFERENCE.md from the real argparse parser.

    python3 scripts/gen_cli_reference.py          # rewrite the generated section
    python3 scripts/gen_cli_reference.py --check  # exit 1 if CLI_REFERENCE.md is stale (used by the test suite)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from protect_folder import cli                    # noqa: E402
from protect_folder.policy.profiles import BUILTIN_PROFILES   # noqa: E402

BEGIN = "<!-- BEGIN GENERATED OPTIONS (scripts/gen_cli_reference.py) -->"
END = "<!-- END GENERATED OPTIONS -->"
NEEDS_ROOT = {"install", "add", "set-layers", "remove", "recover"}

ENV_VARS = [
    ("NO_COLOR", "any command with a table/report", "disable colour (same as --no-color)"),
    ("PF_OPENCODE_MODEL", "`verify --agent opencode --live`", "force the model used for the live OpenCode checks, e.g. `opencode/big-pickle`; default: the local Ollama model if present, else a free hosted one"),
    ("PF_PRIVILEGED_TESTS=1", "test suite", "allow `-m privileged` tests (real chown/chmod/ACL; run under sudo)"),
    ("PF_LIVE_AGENT_TESTS=1", "test suite", "allow `-m live_agent` tests (real agent sessions; consume quota)"),
    ("PF_BIN", "`scripts/acceptance.sh`", "path of the protect-folder executable to test (default `/usr/local/bin/protect-folder`)"),
    ("SUDO_USER / SUDO_UID", "set by sudo", "identify the operator for audit records and for finding node/srt in `install`; never trusted for authorisation (euid 0 is)"),
]


def _flags(a: argparse.Action) -> str:
    if not a.option_strings:
        return f"`{a.metavar or a.dest}`" + ("" if a.nargs not in ("?", "*") else " (optional)")
    meta = ""
    if a.nargs != 0:
        meta = " " + (a.metavar or a.dest.upper())
    return ", ".join(f"`{o}{meta}`" for o in a.option_strings)


def render() -> str:
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {c.dest: c.help for c in sub._choices_actions}
    out = [BEGIN, "", "## Complete option listing (generated from the parser)", "",
           "Every command also accepts `-h/--help`. `--json` prints the envelope described above instead of text.", ""]
    for name, sp in sub.choices.items():
        out += [f"### `protect-folder {name}`" + ("  (needs sudo)" if name in NEEDS_ROOT else ""), ""]
        if helps.get(name):
            out += [helps[name][0].upper() + helps[name][1:] + ".", ""]
        rows = [a for a in sp._actions if not isinstance(a, argparse._HelpAction)]
        if rows:
            out += ["| Argument / option | Meaning | Default |", "|---|---|---|"]
            for a in rows:
                d = a.default
                dflt = "" if d in (None, False, argparse.SUPPRESS) else f"`{d}`"
                if a.nargs == 0 and a.default is False:
                    dflt = "off"
                text = (a.help or "").replace("|", "\\|").replace("\n", " ")
                if a.choices:
                    text += f" (one of: {', '.join(map(str, a.choices))})"
                out.append(f"| {_flags(a)} | {text} | {dflt} |")
            out.append("")
    out += ["## Built-in network profiles (`run --profile`, `verify --profile`)", "",
            "| Name | Allowed hosts | Notes |", "|---|---|---|"]
    for n, p in BUILTIN_PROFILES.items():
        hosts = ", ".join(f"`{h}`" for h in p["allowedDomains"]) or "none"
        relay = "; fixed in-sandbox relay" if p.get("relays") else ""
        out.append(f"| `{n}` | {hosts} | {p.get('description', '')}{relay} |")
    out += ["", "Custom profiles go in `/etc/protect-folder/policy.json` (see `examples/policy.json`).", "",
            "## Environment variables", "", "| Variable | Used by | Effect |", "|---|---|---|"]
    out += [f"| `{v}` | {u} | {e} |" for v, u, e in ENV_VARS]
    out += ["", "protect-folder itself reads no other environment variables for configuration: locations are fixed, "
            "and the launcher removes `LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS` and similar from the agent's "
            "environment (see `policy.json` `env_drop`/`env_keep`).", "", END]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    path = ROOT / "CLI_REFERENCE.md"
    text = path.read_text()
    block = render()
    if BEGIN in text:
        head, rest = text.split(BEGIN, 1)
        tail = rest.split(END, 1)[1]
        new = head + block + tail
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"
    if "--check" in argv:
        if new != text:
            print("CLI_REFERENCE.md is stale: run python3 scripts/gen_cli_reference.py", file=sys.stderr)
            return 1
        return 0
    path.write_text(new)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
