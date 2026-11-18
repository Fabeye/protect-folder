"""Read-only inspection of registered targets (safe to run unprivileged)."""

from __future__ import annotations

import os
from typing import Any

from . import layers as layers_mod, paths, registry
from .constants import PROTECTED_GID, PROTECTED_MODE, PROTECTED_UID
from .context import Context
from .errors import ProtectError
from .registry import Registry, Target
from .transactions import read_marker

LAYER_KEYS = ("native_permissions", "pre_execution_hook", "srt", "linux_permissions")


def l4_state(ctx: Context, t: Target) -> tuple[str, str]:
    """(PASS|FAIL|STALE, detail) from stat of the exact registered object, no-follow."""
    ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                 t.filesystem_type, t.mount_source, t.fs_uuid,
                                 mounts=ctx.read_mounts())
    if ident.status != "OK":
        return "STALE", f"{ident.status}: {ident.detail}"
    fd = paths.open_dir_nofollow(t.canonical_path)
    try:
        m = ctx.host.stat(fd)
    finally:
        os.close(fd)
    if (m.uid, m.gid, m.mode) == (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE):
        return "PASS", "root:root 0700" + ("; " + "; ".join(ident.warnings) if ident.warnings else "")
    return "FAIL", f"owner/mode is {m.uid}:{m.gid} {m.mode:04o}, expected 0:0 0700"


def _agent_version(agent: str) -> str | None:
    try:
        from . import adapters as adapters_mod
        return adapters_mod.by_name(agent).agent_version()
    except Exception:                                              # noqa: BLE001 - unknown agent / probe failure
        return None


def layer_views(ctx: Context, reg: Registry, t: Target, l4_cache: dict[str, tuple[str, str]] | None = None
                ) -> dict[str, dict[str, Any]]:
    """Per-layer state of one directory. CONFIGURED means enabled but NOT verified; VERIFIED requires evidence:
    a live stat (Linux permissions) or a `verify` result recorded for the current policy revision and,
    for agent layers, the currently installed agent version."""
    from .verify import cache
    eff = reg.effective(t)
    out: dict[str, dict[str, Any]] = {}
    versions: dict[str, str | None] = {}

    def version_of(agent: str) -> str | None:
        if agent not in versions:
            versions[agent] = _agent_version(agent)
        return versions[agent]

    for layer in layers_mod.LAYERS:
        e = eff[layer]
        view = {"enabled": e["own"], "effective": e["enabled"], "inherited_from": e["inherited_from"],
                "state": layers_mod.DISABLED, "indicator": layers_mod.INDICATOR[layers_mod.DISABLED],
                "verified_at": None, "detail": "explicitly disabled", "agent": None}
        if e["enabled"]:
            src = reg.find_id(e["source_id"]) or t
            status, at, detail, agent = None, None, "", None
            rec = (cache.target_layer(t.id, layer, reg.policy_revision, version_of)
                   or cache.target_layer(src.id, layer, reg.policy_revision, version_of))
            if rec:
                status, at, detail, agent = rec["status"], rec["at"], rec.get("detail", ""), rec.get("agent")
            if layer == "linux_permissions":
                key = src.id
                if l4_cache is not None and key in l4_cache:
                    live, live_detail = l4_cache[key]
                else:
                    live, live_detail = l4_state(ctx, src)
                    if l4_cache is not None:
                        l4_cache[key] = (live, live_detail)
                if live == "FAIL":
                    status, detail, at = "FAIL", live_detail, ctx.now()
                elif live == "PASS" and status != "FAIL":
                    status, at = "PASS", ctx.now()
                    detail = f"{live_detail} (live stat check; run 'verify' for the unprivileged-denial test)"
                elif live == "STALE" and status != "FAIL":
                    status, detail = None, live_detail
            st = layers_mod.state_for(True, status)
            view.update(state=st, indicator=layers_mod.INDICATOR[st], verified_at=at if st == layers_mod.VERIFIED else None,
                        detail=detail or ("enabled; not verified yet (run 'protect-folder verify')"
                                          if st == layers_mod.CONFIGURED else ""), agent=agent)
        out[layer] = view
    return out


def target_view(ctx: Context, reg: Registry, t: Target, pending: dict[str, Any],
                l4_cache: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    lv = layer_views(ctx, reg, t, l4_cache)
    verified = sum(1 for v in lv.values() if v["state"] == layers_mod.VERIFIED)
    configured = sum(1 for v in lv.values() if v["effective"])
    failed = [k for k, v in lv.items() if v["state"] == layers_mod.FAILED]
    pids = pending.get("by_target", {}).get(t.id, [])
    notes = layers_mod.layer_warnings({k: v["effective"] for k, v in lv.items()})
    return {
        "id": t.id, "canonical_path": t.canonical_path, "input_path": t.input_path,
        "st_dev": t.st_dev, "st_ino": t.st_ino, "filesystem_type": t.filesystem_type,
        "mount_point": t.mount_point, "created_at": t.created_at, "status": t.status,
        "configured": {k: v["enabled"] for k, v in lv.items()},
        "layer_details": lv, "verified_count": verified, "configured_count": configured,
        "failed_layers": failed, "restart_pending": bool(pids), "restart_pending_pids": pids,
        "security_notes": notes,
        # legacy keys (report vocabulary): status strings, DISABLED where off
        "layers": {layers_mod.REPORT_KEY[k]: ("PASS" if v["state"] == layers_mod.VERIFIED else
                                              "FAIL" if v["state"] == layers_mod.FAILED else
                                              "DISABLED" if v["state"] == layers_mod.DISABLED else "UNVERIFIED")
                   for k, v in lv.items()},
        "l4_detail": lv["linux_permissions"]["detail"],
        "note": "L1/L2/L3 are only established by 'protect-folder verify' (UNVERIFIED here)",
    }


def target_report(ctx: Context, t: Target, reg: Registry | None = None,
                  pending: dict[str, Any] | None = None) -> dict[str, Any]:
    reg = reg or registry.load(ctx.layout)
    return target_view(ctx, reg, t, pending or {})


def overall(ctx: Context) -> dict[str, Any]:
    from . import sessions
    marker = read_marker(ctx)
    reg: Registry = registry.load(ctx.layout)
    pending = sessions.pending_restarts(reg)
    cache4: dict[str, tuple[str, str]] = {}
    reports = [target_view(ctx, reg, t, pending, cache4) for t in reg.sorted_targets()]
    state = "OK"
    if marker is not None:
        state = "RECOVERY_REQUIRED"
    elif any(r["failed_layers"] or r["layer_details"]["linux_permissions"]["state"] == layers_mod.CONFIGURED
             and r["layer_details"]["linux_permissions"]["effective"] for r in reports):
        state = "DEGRADED"
    return {"state": state, "marker": marker, "revision": reg.revision,
            "policy_revision": reg.policy_revision, "targets": reports,
            "restart_pending": pending}


def select(ctx: Context, path: str | None) -> list[Target]:
    reg = registry.load(ctx.layout)
    if path is None:
        return reg.sorted_targets()
    from .admin import _find_for_removal  # same lookup rules as 'remove'
    try:
        return [_find_for_removal(reg, path)]
    except ProtectError:
        raise
