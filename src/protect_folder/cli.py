"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from . import admin, audit, doctor as doctor_mod, layers as layers_mod, registry, render, status as status_mod, userstate
from .constants import JSON_SCHEMA_ID, VERSION
from .context import Context, default_context
from .errors import EXIT_CODES, ProtectError

EPILOG = """\
Administrator commands (need sudo):  add, remove, set-layers, recover, install
Unprivileged commands:               run, list, status, verify, logs, adapters, doctor, version

examples:
  sudo protect-folder add '/mnt/ssd2/project-two/credentials'
  sudo protect-folder add '/data/notes' --no-linux          # keep its ownership/mode; other layers on
  sudo protect-folder set-layers '/data/notes' --all        # turn every layer back on
  protect-folder list --json
  protect-folder run -- claude

NOT a privilege boundary against your own account: a process running as your user that can use
sudo can undo any of this.  Run 'sudo -K' after administrative commands.
"""

SUBCOMMANDS = {"install", "doctor", "add", "remove", "set-layers", "recover", "list", "status", "verify",
               "logs", "run", "adapters", "version", "help"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="protect-folder", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Protect arbitrary directories from local AI coding agents.", epilog=EPILOG)
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    def common(sp: argparse.ArgumentParser, json_flag: bool = True) -> None:
        if json_flag:
            sp.add_argument("--json", action="store_true", help="machine-readable output")

    def layer_flags(sp: argparse.ArgumentParser, enable: bool) -> None:
        g = sp.add_argument_group("protection layers (default: all four enabled)")
        g.add_argument("--no-agent-permissions", action="store_true", help="disable layer 1: native agent permission rules")
        g.add_argument("--no-hook", action="store_true", help="disable layer 2: pre-execution command/script inspection")
        g.add_argument("--no-srt", action="store_true", help="disable layer 3: SRT sandbox masking of this directory")
        g.add_argument("--no-linux", action="store_true",
                       help="disable layer 4: root:root 0700 (ownership, mode and ACL stay/return as they were)")
        if enable:
            g.add_argument("--agent-permissions", dest="enable_agent_permissions", action="store_true",
                           help="enable layer 1")
            g.add_argument("--hook", dest="enable_hook", action="store_true", help="enable layer 2")
            g.add_argument("--srt", dest="enable_srt", action="store_true", help="enable layer 3")
            g.add_argument("--linux", dest="enable_linux", action="store_true", help="enable layer 4")
        sp.add_argument("--accept-no-fs-enforcement", action="store_true",
                        help="explicitly accept a configuration where BOTH SRT and Linux permissions are off")

    sp = sub.add_parser("install", help="install/verify the root-owned layout (sudo)")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    sp.add_argument("--no-vendor", action="store_true",
                    help="skip vendoring node + sandbox-runtime (the launcher will then refuse to run)")
    sp.add_argument("--node", metavar="PATH", help="node executable to vendor (default: next to the srt package)")
    sp.add_argument("--srt-package", metavar="DIR",
                    help="directory of the @anthropic-ai/sandbox-runtime package to vendor (default: searched in "
                         "the invoking user's nvm/npm prefixes; a bare 'srt' on PATH is never trusted)")
    common(sp)

    sp = sub.add_parser("doctor", help="check dependencies, versions, integrity")
    common(sp)

    sp = sub.add_parser("add", help="protect a directory (sudo)",
                        epilog="Use '--' before a path that begins with '-'.")
    sp.add_argument("path", help="directory to protect (any absolute or relative path; spaces and Unicode are fine)")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    sp.add_argument("--yes", "-y", action="store_true", help="do not prompt for confirmation")
    sp.add_argument("--follow-symlinks", action="store_true",
                    help="allow the path to resolve through a symlink (protects the destination)")
    layer_flags(sp, enable=False)
    common(sp)

    sp = sub.add_parser("set-layers", help="change which protection layers are enabled for a directory (sudo)",
                        description="Only the layers you name are changed; nothing is enabled or disabled "
                                    "implicitly. --all turns every layer on.")
    sp.add_argument("path", help="path, spelling used at add time, or target id (prefix)")
    layer_flags(sp, enable=True)
    sp.add_argument("--all", action="store_true", help="enable all four layers")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    sp.add_argument("--yes", "-y", action="store_true", help="do not prompt")
    common(sp)

    sp = sub.add_parser("remove", help="unprotect a directory and restore its original permissions (sudo)")
    sp.add_argument("path", help="path, spelling used at add time, or target id")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    sp.add_argument("--yes", "-y", action="store_true", help="do not prompt for confirmation")
    sp.add_argument("--forget", action="store_true",
                    help="drop a stale registration WITHOUT touching the filesystem")
    common(sp)

    sp = sub.add_parser("recover", help="roll back an interrupted add/remove (sudo)")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    sp.add_argument("--yes", "-y", action="store_true", help="do not prompt for confirmation")
    common(sp)

    sp = sub.add_parser("list", help="list protected directories with the state of every layer")
    sp.add_argument("--no-color", action="store_true", help="plain output (also honoured: NO_COLOR, non-tty)")
    common(sp)

    sp = sub.add_parser("status", help="show identity and per-layer state of protected directories")
    sp.add_argument("path", nargs="?", help="limit to one directory (path, spelling used at add time, or id prefix)")
    sp.add_argument("--no-color", action="store_true", help="plain output (also honoured: NO_COLOR, non-tty)")
    common(sp)

    sp = sub.add_parser("verify", help="run per-layer enforcement tests")
    sp.add_argument("path", nargs="?", help="limit to one protected directory (default: all)")
    sp.add_argument("--agent", default=None, help="also verify this agent's layers: claude, opencode or codex")
    sp.add_argument("--profile", default=None, help="network profile to test with")
    sp.add_argument("--live", action="store_true",
                    help="also run real agent sessions (consumes model calls) to verify L1/L2")
    sp.add_argument("--admin", action="store_true",
                    help="root-only checks of root-owned state (snapshots, restore safety, installed code); "
                         "run as 'sudo protect-folder verify --admin'; never launches an agent")
    sp.add_argument("--no-color", action="store_true", help="plain output")
    common(sp)

    sp = sub.add_parser("logs", help="show administrative and hook logs")
    sp.add_argument("--since", help="e.g. 30m, 2h, 7d or an ISO timestamp")
    sp.add_argument("--agent", help="only hook-log records of this agent")
    common(sp)

    sp = sub.add_parser("run", help="run a command inside the protection sandbox (never uses sudo)",
                        usage="protect-folder run [--profile NAME] [--require-layers N] -- COMMAND [ARGS...]")
    sp.add_argument("--profile", default=None,
                    help="network profile (see 'protect-folder help profiles'; default: the agent's own profile)")
    sp.add_argument("--require-layers", type=int, default=None, metavar="N",
                    help="also require N verified layers (default: every enabled enforcement layer must pass)")
    sp.add_argument("--json", action="store_true", help="print the capability report as JSON on stderr")
    sp.add_argument("--quiet", "-q", action="store_true", help="suppress the capability banner")
    sp.add_argument("cmd", nargs="*", metavar="COMMAND", help="after '--': the command and its arguments, passed "
                    "through verbatim (no shell), e.g. -- claude   or   -- python3 script.py 'a b'")

    sp = sub.add_parser("adapters", help="show agent adapter capabilities")
    common(sp)

    sub.add_parser("version", help="print version").add_argument("--json", action="store_true",
                                                                help="machine-readable output")

    sp = sub.add_parser("help", help="complete built-in documentation (topics, commands, 'all')",
                        description="help             overview and topic list\n"
                                    "help COMMAND     options of one command (same as COMMAND --help)\n"
                                    "help TOPIC       layers, agents, profiles, exit-codes, env, files, safety\n"
                                    "help all         the whole reference", formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("topic", nargs="?", help="a command name, a topic name, or 'all'")
    return p


# ------------------------------------------------------------------------------------------
def _envelope(command: str, ok: bool, reason: str, message: str, data: Any = None,
              warnings: list[str] | None = None, hint: str | None = None) -> dict[str, Any]:
    env = {"schema": JSON_SCHEMA_ID, "command": command, "ok": ok, "reason_code": reason,
           "message": message, "data": data if data is not None else {}, "warnings": warnings or []}
    if hint:
        env["hint"] = hint
    return env


def _emit(args: argparse.Namespace, env: dict[str, Any], text: str | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(env, indent=2, sort_keys=True, ensure_ascii=True))
        return
    stream = sys.stdout if env["ok"] else sys.stderr
    if text is not None:
        print(text, file=sys.stdout)
    elif env["message"]:
        print(env["message"], file=stream)
    for w in env["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    if not env["ok"] and env.get("hint"):
        print(f"hint: {env['hint']}", file=sys.stderr)


def _parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    m = re.fullmatch(r"(\d+)([smhd])", value.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
                 "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
        return datetime.now(timezone.utc) - delta
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtectError("USAGE", f"cannot parse --since {value!r} (use 30m, 2h, 7d or ISO-8601)") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _homes(ctx: Context) -> list[str]:
    return sorted({*(ctx.homes or ()), os.path.expanduser("~")})


def _cmd_list(ctx: Context, args: argparse.Namespace) -> tuple[dict, str]:
    from . import sessions
    reg = registry.load(ctx.layout)
    pending = sessions.pending_restarts(reg)
    l4: dict[str, tuple[str, str]] = {}
    rows = [status_mod.target_view(ctx, reg, t, pending, l4) for t in reg.sorted_targets()]
    for r in rows:      # legacy field kept for scripts written against schema 1
        r["linux_permissions"] = {"VERIFIED": "PASS", "FAILED": "FAIL"}.get(
            r["layer_details"]["linux_permissions"]["state"],
            "DISABLED" if r["layer_details"]["linux_permissions"]["state"] == "DISABLED" else "STALE")
    color = render.use_color(getattr(args, "no_color", False))
    lines = render.render_table(rows, cols=render.term_width(), color=color, homes=_homes(ctx))
    if rows:
        lines += render.legend(rows, pending)
    data = {"revision": reg.revision, "policy_revision": reg.policy_revision, "targets": rows,
            "restart_pending": pending,
            "legend": {"VERIFIED": "✓", "CONFIGURED": "?", "FAILED": "✗", "DISABLED": "—"}}
    return data, "\n".join(lines)


def _cmd_status(ctx: Context, args: argparse.Namespace) -> tuple[dict, str, str, list[str]]:
    full = status_mod.overall(ctx)
    if args.path is not None:
        wanted = {t.id for t in status_mod.select(ctx, args.path)}
        full["targets"] = [r for r in full["targets"] if r["id"] in wanted]
    color = render.use_color(getattr(args, "no_color", False))
    lines = [f"state: {full['state']}  revision: {full['revision']}  policy: {full['policy_revision']}"]
    if full["marker"]:
        lines.append(f"  !! {full['marker']}  -> run 'sudo protect-folder recover'")
    for r in full["targets"]:
        lines.append("")
        lines += render.render_detail(r, color=color, homes=_homes(ctx))
    if full["restart_pending"].get("sessions"):
        lines.append("")
        lines.append("Restart pending for: " + ", ".join(
            f"pid {x['pid']} ({x['agent']}, started {x['started_at']})" for x in full["restart_pending"]["sessions"]))
    lines.append("")
    lines.append("CONFIGURED means enabled but not verified; run 'protect-folder verify' to establish VERIFIED. "
                 "This is not a defence against root/sudo by your own account.")
    code = {"OK": "OK", "DEGRADED": "STALE", "RECOVERY_REQUIRED": "RECOVERY_REQUIRED"}[full["state"]]
    ok = full["state"] == "OK"
    return full, "\n".join(lines), code, ([] if ok else [f"state is {full['state']}"])


def _cmd_logs(ctx: Context, args: argparse.Namespace) -> tuple[dict, str]:
    since = _parse_since(args.since)
    records = []
    for rec in audit.read_admin_log(ctx):
        rec = dict(rec, source="admin-log (root-managed)")
        records.append(rec)
    hook = str(userstate.state_dir() / "hook.log")
    try:
        with open(hook, "rb") as fh:
            for raw in fh:
                try:
                    rec = json.loads(raw.decode("utf-8"))
                except ValueError:
                    continue
                rec["source"] = "hook-log (per-user, best-effort, NOT tamper-proof)"
                records.append(rec)
    except FileNotFoundError:
        pass

    def keep(rec: dict) -> bool:
        if args.agent and rec.get("agent") != args.agent:
            return False
        if since and rec.get("ts"):
            try:
                ts = datetime.fromisoformat(str(rec["ts"]).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                return ts >= since
            except ValueError:
                return True
        return True

    records = sorted((r for r in records if keep(r)), key=lambda r: str(r.get("ts")))
    text = "\n".join(f"{r.get('ts')}  {r.get('op') or r.get('tool')}  {r.get('outcome', '')}  "
                     f"{r.get('reason_code', r.get('reason', ''))}  {r.get('target_id') or ''}  "
                     f"[{r['source'].split(' ')[0]}]" for r in records) or "no log records"
    return {"records": records}, text


def _format_verify(doc: dict) -> str:
    lines = [f"agent: {doc['agent']}   policy: {doc['policy_revision']}",
             f"integrity: {doc['integrity']['status']}"]
    for c in doc["integrity"]["checks"]:
        lines.append(f"  [{c['status']:11}] {c['name']}: {c['detail']}")
    names = {"native_permissions": "L1 agent permissions", "pre_execution_hook": "L2 pre-execution hook",
             "srt": "L3 SRT sandbox", "linux_permissions": "L4 Linux permissions"}
    for key, label in names.items():
        layer = doc["layers"][key]
        lines.append(f"{label}: {layer['status']}" + (f"  ({layer['note']})" if layer.get("note") else ""))
        for c in layer["checks"]:
            cls = f" <{c['classification']}>" if c.get("classification") else ""
            lines.append(f"  [{c['status']:11}] {c['name']}: {c['detail']}{cls}")
    if doc.get("targets"):
        lines.append("per directory:")
        for t in doc["targets"]:
            lines.append(f"  {t['canonical_path']}")
            for key in layers_mod.LAYERS:
                v = t["layers"][key]
                tag = "[ON] " if v["enabled"] and v["own"] else ("[ON*]" if v["enabled"] else "[OFF]")
                lines.append(f"    {tag} {layers_mod.LABEL[key]:20} {v['state']}"
                             + (f"  (verified {v['verified_at']})" if v.get("verified_at") else "")
                             + (f"  inherited from {t['layers'][key]['inherited_from']}" if v.get("inherited_from") and not v["own"] else ""))
    lines.append(f"VERIFIED_LAYERS: {doc['verified_layers']}   CONFIGURED_LAYERS: {doc.get('configured_layers', 4)}/4")
    lines.append("A PASS is evidence about the tested paths and mechanisms, not proof against all bypasses. "
                 "Not a defence against root/sudo by your own account.")
    return "\n".join(lines)


def _cmd_adapters(ctx: Context) -> tuple[dict, str]:
    from . import adapters as adapters_mod
    rows = []
    for a in [*adapters_mod.all_adapters(), adapters_mod.GenericAdapter()]:
        caps = a.capabilities(ctx)
        rows.append({"name": a.name, "description": a.description, "commands": list(a.commands),
                     "default_profile": a.default_profile,
                     "layers": {"native_permissions": caps.get("native_permissions", "NOT_APPLICABLE"),
                                "pre_execution_hook": caps.get("pre_execution_hook", "NOT_APPLICABLE"),
                                "srt": "AVAILABLE", "linux_permissions": "AVAILABLE"}})
    lines = []
    for r in rows:
        lay = r["layers"]
        lines.append(f"{r['name']:9} L1={lay['native_permissions']:15} L2={lay['pre_execution_hook']:15} "
                     f"L3={lay['srt']} L4={lay['linux_permissions']}  {r['description']}")
    lines.append("These are declared capabilities, not verification results; run 'protect-folder verify'.")
    return {"adapters": rows}, "\n".join(lines)


def dispatch(args: argparse.Namespace, ctx: Context, run_argv: list[str]) -> int:
    cmd = args.command
    try:
        if cmd == "version":
            _emit(args, _envelope(cmd, True, "OK", VERSION, {"version": VERSION}), VERSION)
            return 0
        if cmd in ("add", "remove", "recover", "set-layers"):
            if cmd == "add":
                out = admin.add(ctx, args.path, dry_run=args.dry_run, yes=args.yes,
                                follow_symlinks=args.follow_symlinks,
                                layers=layers_mod.parse_changes(args, allow_enable=False),
                                accept_no_fs_enforcement=args.accept_no_fs_enforcement)
            elif cmd == "set-layers":
                out = admin.set_layers(ctx, args.path, layers_mod.parse_changes(args, allow_enable=True),
                                       dry_run=args.dry_run, yes=args.yes,
                                       accept_no_fs_enforcement=args.accept_no_fs_enforcement)
            elif cmd == "remove":
                out = admin.remove(ctx, args.path, dry_run=args.dry_run, yes=args.yes, forget=args.forget)
            else:
                out = admin.recover(ctx, dry_run=args.dry_run, yes=args.yes)
            _emit(args, _envelope(cmd, out.ok, out.reason_code, out.message, out.data, out.warnings),
                  out.message)
            return 0 if out.ok else EXIT_CODES[out.reason_code]
        if cmd == "list":
            data, text = _cmd_list(ctx, args)
            _emit(args, _envelope(cmd, True, "OK", "", data), text)
            return 0
        if cmd == "status":
            data, text, code, warns = _cmd_status(ctx, args)
            ok = code == "OK"
            _emit(args, _envelope(cmd, ok, code, "" if ok else warns[0], data, warns), text)
            return 0 if ok else EXIT_CODES[code]
        if cmd == "doctor":
            data = doctor_mod.run(ctx)
            text = "\n".join(f"[{c['status']:4}] {c['name']}: {c['detail']}" for c in data["checks"])
            text += f"\nsummary: {data['summary']}"
            ok = data["summary"] != "FAIL"
            _emit(args, _envelope(cmd, ok, "OK" if ok else "ERROR", "" if ok else "doctor found problems",
                                  data), text)
            return 0 if ok else EXIT_CODES["ERROR"]
        if cmd == "logs":
            data, text = _cmd_logs(ctx, args)
            _emit(args, _envelope(cmd, True, "OK", "", data), text)
            return 0
        if cmd == "run":
            from . import launcher
            if not run_argv:
                raise ProtectError("USAGE", "no command to run",
                                   hint="usage: protect-folder run [--profile NAME] [--require-layers N] "
                                        "-- COMMAND [ARGS...]")
            return launcher.run(ctx, run_argv, profile=args.profile, require_layers=args.require_layers,
                                quiet=args.quiet, json_report=args.json)
        if cmd == "verify" and getattr(args, "admin", False):
            if args.agent or args.live or args.path:
                raise ProtectError("USAGE", "'verify --admin' cannot be combined with PATH, --agent or --live",
                                   hint="Administrative commands never launch an agent as root.")
            from .verify import admin as admin_verify
            doc = admin_verify.run_admin_verify(ctx)
            ok = doc["summary"] != "FAIL"
            text = "\n".join([f"  [{c['status']:11}] {c['name']}: {c['detail']}" for c in doc["checks"]]
                             + [f"admin verification: {doc['summary']}"])
            _emit(args, _envelope(cmd, ok, "OK" if ok else "VERIFY_FAILED", "" if ok else "admin checks failed", doc), text)
            return 0 if ok else EXIT_CODES["VERIFY_FAILED"]
        if cmd == "verify":
            from .verify import runner
            doc = runner.run_verify(ctx, path=args.path, agent=args.agent, profile=getattr(args, "profile", None),
                                    live=getattr(args, "live", False))
            bad = [k for k, v in doc["summary"].items() if v == "FAIL"] + (
                ["integrity"] if doc["integrity"]["status"] == "FAIL" else [])
            ok = not bad
            _emit(args, _envelope(cmd, ok, "OK" if ok else "VERIFY_FAILED",
                                  "" if ok else "failed: " + ", ".join(bad), doc), _format_verify(doc))
            return 0 if ok else EXIT_CODES["VERIFY_FAILED"]
        if cmd == "install":
            from . import install as install_mod
            from pathlib import Path
            pkg_dir = Path(__file__).resolve().parent
            src = None if pkg_dir == ctx.layout.lib_dir / "protect_folder" else pkg_dir.parent
            res = install_mod.install(ctx, dry_run=args.dry_run, source_dir=src, vendor=not args.no_vendor,
                                      node=args.node, srt_package=args.srt_package)
            msg = ("dry run: " if args.dry_run else "installed: ") + "; ".join(res["steps"])
            _emit(args, _envelope(cmd, True, "OK", msg, res), msg)
            return 0
        if cmd == "adapters":
            data, text = _cmd_adapters(ctx)
            _emit(args, _envelope(cmd, True, "OK", "", data), text)
            return 0
        raise ProtectError("USAGE", "no command given; try --help")
    except ProtectError as exc:
        env = _envelope(cmd or "", False, exc.code, exc.message, exc.details, [], exc.hint)
        _emit(args, env)
        return exc.exit_code


def split_run_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """For 'run', everything after the first '--' is the command, passed through verbatim."""
    idx = next((i for i, a in enumerate(argv) if a in SUBCOMMANDS), None)
    if idx is None or argv[idx] != "run" or "--" not in argv[idx:]:
        return argv, []
    cut = argv.index("--", idx)
    return argv[:cut], argv[cut + 1:]


def main(argv: Sequence[str] | None = None, ctx: Context | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    head, run_argv = split_run_argv(raw)
    parser = build_parser()
    try:
        args = parser.parse_args(head)
    except SystemExit as exc:  # argparse already printed usage
        return int(exc.code) if isinstance(exc.code, int) else 2
    if args.command is None:
        parser.print_help()
        print("\nMore: 'protect-folder help' (topics), 'protect-folder help all' (complete reference).")
        return 0
    if args.command == "help":
        from . import helptext
        text, found = helptext.render(args.topic, parser)
        print(text, file=sys.stdout if found else sys.stderr)
        return 0 if found else 2
    return dispatch(args, ctx or default_context(), run_argv)


if __name__ == "__main__":
    sys.exit(main())
