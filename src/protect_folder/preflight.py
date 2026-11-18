"""Fail-closed checks that must all pass before an agent is launched."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import adapters as adapters_mod
from . import jsonio, mounts as mnt, paths, registry, runtime as runtime_mod
from .adapters.base import (Adapter, DISABLED, NOT_APPLICABLE, PASS, UNSUPPORTED, UNVERIFIED, Prepared)
from . import layers as layers_mod
from .constants import PROTECTED_GID, PROTECTED_MODE, PROTECTED_UID
from .context import Context
from .errors import ProtectError
from .policy import profiles as profiles_mod
from .policy import srt as srt_policy
from .policy.config import load_policy
from .registry import Registry
from .transactions import refuse_if_pending
from .verify import probes

LAYER_ORDER = ("native_permissions", "pre_execution_hook", "srt", "linux_permissions")


@dataclass
class Preflight:
    adapter: Adapter
    reg: Registry
    policy: dict[str, Any]
    rt: runtime_mod.Runtime
    workspace: str
    profile: str
    settings: dict[str, Any]
    settings_path: str
    prepared: Prepared
    layers: dict[str, str]
    warnings: list[str] = field(default_factory=list)
    relays: list[tuple[str, str]] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        n = sum(1 for k in LAYER_ORDER if self.layers.get(k) == PASS)
        return {"enabled_layers": sum(1 for k in LAYER_ORDER if self.layers.get(k) != DISABLED),"agent": self.adapter.name, "profile": self.profile, "workspace": self.workspace,
                "layers": dict(self.layers), "verified_layers": f"{n}/4",
                "warnings": list(self.warnings), "policy_revision": self.reg.policy_revision,
                "target_count": len(self.reg.targets)}


def sanitize_env(env: dict[str, str], policy: dict[str, Any]) -> dict[str, str]:
    drop = set(policy.get("env_drop", [])) - set(policy.get("env_keep", []))
    return {k: v for k, v in env.items() if k not in drop}


def check_targets(ctx: Context, reg: Registry) -> None:
    table = ctx.read_mounts()
    for t in reg.sorted_targets():
        ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                     t.filesystem_type, t.mount_source, t.fs_uuid, mounts=table)
        if ident.status != "OK":
            code = ident.reason if ident.reason in ("MOUNT_MISSING", "IDENTITY_MISMATCH", "STALE") else "STALE"
            raise ProtectError(code, f"protected directory {t.canonical_path!r}: {ident.detail}",
                               hint="Refusing to launch with a missing or changed target. Fix it "
                                    "(re-mount the disk) or 'sudo protect-folder remove'.")
        if not t.layers["linux_permissions"]:
            continue                      # explicitly disabled for this directory: nothing to enforce
        fd = paths.open_dir_nofollow(t.canonical_path)
        try:
            m = ctx.host.stat(fd)
        finally:
            os.close(fd)
        if (m.uid, m.gid, m.mode) != (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE):
            raise ProtectError("PREFLIGHT_FAILED",
                               f"L4 is not effective on {t.canonical_path!r} "
                               f"(owner {m.uid}:{m.gid} mode {m.mode:04o}, expected 0:0 0700)",
                               hint="Re-run 'sudo protect-folder add' for it or 'sudo protect-folder recover'.")


def run_preflight(ctx: Context, argv: list[str], *, cwd: str, profile: str | None = None,
                  require_layers: int | None = None, env: dict[str, str] | None = None) -> Preflight:
    """require_layers=None: every ENABLED enforcement layer (SRT, Linux permissions) must pass.
    An explicit N additionally demands N verified layers (capped at the number of enabled layers)."""
    if require_layers is not None and (require_layers < 2 or require_layers > 4):
        raise ProtectError("USAGE", "--require-layers must be 2, 3 or 4")
    if not argv:
        raise ProtectError("USAGE", "no command given", hint="protect-folder run -- COMMAND [ARGS...]")
    if ctx.euid() == 0:
        raise ProtectError("IS_ROOT", "refusing to launch an agent as root",
                           hint="Run 'protect-folder run' as your ordinary user, without sudo.")
    lo = ctx.layout
    if ctx.check_installed_code:
        if not lo.lib_dir.exists():
            raise ProtectError("NOT_INSTALLED", f"{lo.lib_dir} is missing",
                               hint="Run 'sudo protect-folder install'.")
        registry.check_trusted_chain(lo.lib_dir, lo.trusted_uid)
        runtime_mod.check_tree(lo.lib_dir, lo.trusted_uid)
        registry.check_trusted_file(lo.bin_path, lo.trusted_uid)
    refuse_if_pending(ctx)
    reg = registry.load(lo)
    # generated artifacts must match the registry exactly, or something was edited by hand
    try:
        gen = jsonio.read_json(lo.srt_targets_file)
    except (OSError, ValueError) as exc:
        raise ProtectError("TAMPERED", f"generated policy {lo.srt_targets_file} is missing/unreadable",
                           hint="Run 'sudo protect-folder recover'.") from exc
    registry.check_trusted_file(lo.srt_targets_file, lo.trusted_uid)
    if gen != registry.generated_srt_targets(reg):
        raise ProtectError("TAMPERED", "generated SRT policy does not match the registry",
                           hint="Policy files were modified outside protect-folder.")
    policy = load_policy(lo)
    check_targets(ctx, reg)
    rt = runtime_mod.check_runtime(ctx)

    adapter = adapters_mod.detect(argv[0])
    homes = ctx.homes if ctx.homes is not None else paths.home_directories()
    workspace = srt_policy.find_workspace(cwd, homes)
    srt_policy.check_workspace(workspace, reg.sorted_targets(), homes)

    base_env = sanitize_env(dict(os.environ if env is None else env), policy)
    prepared = adapter.prepare(ctx, argv, base_env, workspace, reg.sorted_targets(), policy)
    warnings = list(prepared.warnings) + adapter.preflight_extra(ctx, argv, prepared.env)

    profile_name = profile or policy.get("default_profile") or adapter.default_profile
    domains = profiles_mod.resolve_profile(profile_name, policy)
    relays = profiles_mod.resolve_relays(profile_name, policy, domains)

    home = os.path.expanduser("~")
    state = [p for p in adapter.state_dirs(home)]
    for d in state:
        if not d.endswith(".json"):
            os.makedirs(d, exist_ok=True)
    extra_write = ["/tmp", *state, *policy.get("extra_write_paths", []), *prepared.extra_write]
    tmpdir = prepared.env.get("TMPDIR")
    if tmpdir and os.path.isdir(tmpdir):
        extra_write.append(os.path.realpath(tmpdir))
    cache = os.path.join(home, ".cache")
    if os.path.isdir(cache):
        extra_write.append(cache)
    sandbox_targets = reg.with_layer("sandbox_runtime")
    settings = srt_policy.compile_settings(ctx, sandbox_targets, workspace=workspace,
                                           extra_write=extra_write, allowed_domains=domains, rt=rt)
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    settings_path = srt_policy.write_private_settings(settings, xdg)
    try:
        # empirical check that the effective sandbox masks every real target
        # only directories whose sandbox layer is ON are probed (a disabled one is deliberately readable)
        probes.probe_masks(rt, settings_path, [t.canonical_path for t in sandbox_targets],
                           cwd=workspace, env=prepared.env)

        adapter.sandbox_check(ctx, rt, settings_path, prepared, workspace, reg.sorted_targets())

        def layer(cfg: str, got: str) -> str:
            return got if (not reg.targets or reg.with_layer(cfg)) else DISABLED
        layers = {"native_permissions": layer("agent_permissions",
                                              prepared.layers.get("native_permissions", NOT_APPLICABLE)),
                  "pre_execution_hook": layer("pre_execution_hook",
                                              prepared.layers.get("pre_execution_hook", NOT_APPLICABLE)),
                  "srt": layer("sandbox_runtime", PASS),
                  "linux_permissions": layer("linux_permissions", PASS)}
        if reg.targets:
            for cfg, key in (("agent_permissions", "native_permissions"), ("pre_execution_hook", "pre_execution_hook")):
                if not reg.with_layer(cfg):
                    layers[key] = DISABLED
        enabled = sum(1 for k in LAYER_ORDER if layers[k] != DISABLED)
        have = sum(1 for k in LAYER_ORDER if layers[k] == PASS)
        if require_layers is not None and have < min(require_layers, enabled):
            raise ProtectError(
                "LAYERS_INSUFFICIENT",
                f"{require_layers} verified layers required but only {have} are verified for {adapter.name!r}",
                details={"layers": layers},
                hint="Run 'protect-folder verify --agent " + adapter.name + "' to establish native "
                     "layers, or lower --require-layers.")
        if reg.targets and not reg.with_layer("sandbox_runtime"):
            warnings.append("no protected directory has the SRT layer enabled: the agent still runs inside "
                            "the sandbox runtime (writes/network confined) but no protected directory is masked")
    except BaseException:
        for f in [settings_path, *prepared.cleanup]:
            try:
                os.unlink(f)
            except OSError:
                pass
        raise
    if not reg.targets:
        warnings.append("no protected directories are registered; the sandbox restricts only writes/network")
    return Preflight(adapter, reg, policy, rt, workspace, profile_name, settings, settings_path,
                     prepared, layers, warnings, relays)
