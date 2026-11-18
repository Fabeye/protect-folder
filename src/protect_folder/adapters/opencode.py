"""OpenCode (v2) adapter.

Facts this adapter is built on (each verified against opencode v2.3.0, see tests/unit/test_opencode_adapter.py
and the live tests):
  * Config is injected per launch through OPENCODE_CONFIG_CONTENT. The v2 key is `permissions` (an ordered
    array of {action, resource, effect}; the LAST matching rule wins, any deny wins).
  * A project-level opencode.jsonc can redefine an agent (`agents.build.permissions`) with allow rules that
    are appended AFTER ours and so defeat them. OPENCODE_DISABLE_PROJECT_CONFIG=1 removes that attack surface,
    so the adapter always sets it (documented trade-off: the project's own opencode.jsonc is ignored).
  * `read`/`edit` deny rules cover the read/edit/list tools only. glob/grep are gated by a pattern resource,
    not a path, so rules alone do NOT stop them; the L2 plugin inspects their structured `path` input.
  * OpenCode starts normally when a plugin fails to load. The L2 plugin therefore writes a nonce handshake and
    the launcher refuses to start unless it is observed inside the real sandbox.
  * OpenCode v2 defaults to a shared background service whose config/permissions are NOT ours:
    --standalone is forced and attaching to any server is refused.
  * The `policies` config form did not deny anything in testing and is not used."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..errors import ProtectError
from .base import Adapter, DISABLED, NOT_APPLICABLE, Prepared, UNVERIFIED

ELEVATION_RULES = ["sudo *", "su *", "pkexec *", "doas *", "sudo", "su", "pkexec", "doas"]
# subcommands that talk to / start a server that is not under this launcher's policy
REFUSED_SUBCOMMANDS = {"service": "the shared background service is outside the sandbox policy",
                       "attach": "attaching to a server runs the session under that server's configuration",
                       "serve": "headless server mode is not verified by protect-folder",
                       "web": "web server mode is not verified by protect-folder"}
PLUGIN_ID = "protect-folder"
SUPPORTED_MAJOR = 2          # the permission/plugin facts below were established on v2.3.0 only


def major_version(text: str | None) -> int | None:
    """'opencode v2.3.0' / '1.17.0' -> 2 / 1; None when no version number is present."""
    import re
    m = re.search(r"(\d+)\.\d+\.\d+", text or "")
    return int(m.group(1)) if m else None


def plugin_dir() -> Path:
    return Path(__file__).resolve().parent / "opencode_plugin"


def hook_script() -> Path:
    return Path(__file__).resolve().parent.parent / "hooks" / "claude_pretooluse.py"


def permission_rules(paths: list[str], *, elevation: bool = True) -> list[dict[str, str]]:
    """Deny rules for every protected path. Order matters (last match wins), so these are emitted last."""
    rules: list[dict[str, str]] = []
    for p in paths:
        for action in ("read", "edit", "external_directory"):
            rules.append({"action": action, "resource": p, "effect": "deny"})
            rules.append({"action": action, "resource": p.rstrip("/") + "/*", "effect": "deny"})
    if elevation:
        rules += [{"action": "shell", "resource": r, "effect": "deny"} for r in ELEVATION_RULES]
    return rules


def plugin_options(ctx: Any, extra_args: list[str] | None = None, python: str | None = None) -> dict[str, Any]:
    lo = ctx.layout
    args = ["--agent", "opencode"]
    if str(lo.etc_dir) != "/etc/protect-folder":
        args += ["--etc", str(lo.etc_dir), "--trusted-uid", str(lo.trusted_uid)]
    args += list(extra_args or [])
    return {"python": python or "/usr/bin/python3", "hook": str(hook_script()), "args": args}


def build_config(ctx: Any, perm_paths: list[str], *, plugin: bool, base: dict[str, Any] | None = None,
                 plugin_args: list[str] | None = None, plugin_python: str | None = None) -> dict[str, Any]:
    """OPENCODE_CONFIG_CONTENT document. `base` is whatever the user already had in that variable: its
    keys are kept, our rules are appended after theirs (last match wins) and our plugin is appended."""
    cfg: dict[str, Any] = dict(base or {})
    cfg.setdefault("$schema", "https://opencode.ai/config.json")
    if perm_paths:
        perms = cfg.get("permissions")
        cfg["permissions"] = (list(perms) if isinstance(perms, list) else []) + permission_rules(perm_paths)
    if plugin:
        plugins = cfg.get("plugins")
        cfg["plugins"] = [p for p in (plugins if isinstance(plugins, list) else [])
                          if not (isinstance(p, dict) and p.get("package") == str(plugin_dir()))] + [
            {"package": str(plugin_dir()), "options": plugin_options(ctx, plugin_args, plugin_python)}]
    return cfg


def classify_argv(argv: list[str]) -> tuple[str | None, bool]:
    """(first subcommand or None, server flag present). Only looks before a bare `--`."""
    sub = None
    server = False
    for a in argv[1:]:
        if a == "--":
            break
        if a == "--server" or a.startswith("--server="):
            server = True
        if sub is None and not a.startswith("-"):
            sub = a
    return sub, server


class OpenCodeAdapter(Adapter):
    name = "opencode"
    default_profile = "opencode-local-ollama"
    description = ("OpenCode v2: L1 `permissions` deny rules via OPENCODE_CONFIG_CONTENT + L2 server plugin "
                   "(load proven by handshake), forced --standalone, project config disabled")
    commands = ("opencode",)

    def state_dirs(self, home: str) -> list[str]:
        return [os.path.join(home, ".local", "share", "opencode"), os.path.join(home, ".local", "state", "opencode"),
                os.path.join(home, ".cache", "opencode"), os.path.join(home, ".local", "state", "protect-folder")]

    def agent_version(self, env=None) -> str | None:
        exe = shutil.which("opencode", path=(env or os.environ).get("PATH"))
        if not exe:
            return None
        try:
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30,
                                 stdin=subprocess.DEVNULL).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out.splitlines()[-1].strip() if out else None

    def capabilities(self, ctx: Any) -> dict[str, str]:
        return {"native_permissions": UNVERIFIED, "pre_execution_hook": UNVERIFIED}

    # ---------------------------------------------------------------------------------------
    def preflight_extra(self, ctx, argv, env) -> list[str]:
        return []

    def prepare(self, ctx, argv, env, workspace, targets, policy) -> Prepared:
        sub, server = classify_argv(argv)
        if server:
            raise ProtectError("PREFLIGHT_FAILED",
                               "refusing --server: the session would run under another server's configuration",
                               hint="Run without --server; protect-folder starts a private --standalone instance.")
        if sub in REFUSED_SUBCOMMANDS:
            raise ProtectError("PREFLIGHT_FAILED", f"refusing 'opencode {sub}': {REFUSED_SUBCOMMANDS[sub]}",
                               hint="Use 'opencode' or 'opencode run' (always started --standalone).")
        exe = shutil.which(argv[0], path=env.get("PATH")) if os.sep not in argv[0] else argv[0]
        ver = self.agent_version({**env, "PATH": os.path.dirname(exe) + os.pathsep + env.get("PATH", "")}) if exe else None
        major = major_version(ver)
        if major is not None and major != SUPPORTED_MAJOR:
            raise ProtectError("PREFLIGHT_FAILED",
                               f"{exe} is OpenCode {ver}; protect-folder's L1/L2 rules are built for OpenCode "
                               f"v{SUPPORTED_MAJOR}.x and an older/newer config format may be silently ignored",
                               hint="Launch OpenCode v2 (for example the one in your nvm bin) or run it through the "
                                    "'generic' adapter limits (L3+L4 only).")
        perm_paths = [t.canonical_path for t in targets if t.layers["agent_permissions"]]
        use_plugin = any(t.layers["pre_execution_hook"] for t in targets)
        warnings: list[str] = []
        base: dict[str, Any] = {}
        raw = env.get("OPENCODE_CONFIG_CONTENT")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    base = parsed
                else:
                    raise ValueError("not an object")
            except ValueError:
                raise ProtectError("PREFLIGHT_FAILED", "OPENCODE_CONFIG_CONTENT is set but is not a JSON object",
                                   hint="Unset it or fix it; protect-folder will not guess.") from None
        cfg = build_config(ctx, perm_paths, plugin=use_plugin, base=base)
        new_env = dict(env)
        new_env["OPENCODE_CONFIG_CONTENT"] = json.dumps(cfg, sort_keys=True)
        new_env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
        for k in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR"):
            if new_env.get(k):
                warnings.append(f"{k} is set: configuration from there is loaded below the protect-folder "
                                "rules, but any plugin or agent it defines is not inspected")
        out = list(argv)
        if "--standalone" not in out[1:]:
            out.insert(1, "--standalone")
        warnings.append("opencode: the project's own opencode.jsonc/.opencode config is ignored "
                        "(OPENCODE_DISABLE_PROJECT_CONFIG=1) because it can override the deny rules")
        if "--auto" in out[1:] or any(a.startswith("--auto=") for a in out[1:]):
            warnings.append("--auto approves every permission request that is not explicitly denied; deny rules, "
                            "the L2 plugin, L3 and L4 still apply")
        return Prepared(argv=out, env=new_env, layers=self.cached_layers(ctx, targets, env), warnings=warnings)

    # ---------------------------------------------------------------------------------------
    def sandbox_check(self, ctx, rt, settings_path, prepared, workspace, targets) -> None:
        """Prove the L2 plugin is loaded INSIDE the sandbox with the exact environment the agent will get.
        OpenCode silently continues when a plugin fails to load, so absence of the handshake is a refusal."""
        if not any(t.layers["pre_execution_hook"] for t in targets):
            return
        from ..verify.probes import run_in_sandbox
        exe = shutil.which("opencode", path=prepared.env.get("PATH"))
        if not exe:
            raise ProtectError("PREFLIGHT_FAILED", "opencode executable not found")
        nonce = secrets.token_hex(16)
        d = tempfile.mkdtemp(prefix="pf-oc-hs-", dir="/tmp")
        hs = os.path.join(d, "handshake.json")
        try:
            env = dict(prepared.env)
            env["PF_HANDSHAKE"] = hs
            env["PF_NONCE"] = nonce
            proc = run_in_sandbox(rt, settings_path, [exe, "debug", "agents", "--standalone"], cwd=workspace,
                                  env=env, timeout=90.0)
            got = None
            try:
                with open(hs) as fh:
                    got = json.load(fh)
            except (OSError, ValueError):
                pass
            if not isinstance(got, dict) or got.get("nonce") != nonce or got.get("id") != PLUGIN_ID:
                raise ProtectError(
                    "PREFLIGHT_FAILED",
                    "the OpenCode L2 plugin did not load inside the sandbox (OpenCode would have started "
                    "without pre-execution inspection)",
                    details={"returncode": proc.returncode, "stderr": proc.stderr.strip()[-300:]},
                    hint="Run 'protect-folder doctor' and 'protect-folder verify --agent opencode'. "
                         "The agent was NOT launched.")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def verify(self, ctx: Any, reg: Any, profile: str | None, live: bool = False,
               enabled: dict[str, bool] | None = None) -> dict[str, dict[str, Any]]:
        from .opencode_verify import verify_opencode
        return verify_opencode(ctx, reg, profile, live, enabled)
