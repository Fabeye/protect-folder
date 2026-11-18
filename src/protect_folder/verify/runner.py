"""`protect-folder verify`: independent, executable per-layer tests."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import adapters as adapters_mod
from .. import jsonio, layers as layers_mod, paths, registry, runtime as runtime_mod
from ..adapters.base import (DISABLED, FAIL, LAYER_KEYS, NOT_APPLICABLE, PASS, STALE, UNSUPPORTED, UNVERIFIED)
from ..constants import PROTECTED_GID, PROTECTED_MODE, PROTECTED_UID, VERSION
from ..context import Context
from ..errors import ProtectError
from ..policy import profiles as profiles_mod
from ..policy import srt as srt_policy
from ..policy.config import load_policy
from ..registry import Registry, Target
from ..transactions import read_marker
from . import cache, probes
from .fixture_probe import PROBE_SRC

BLOCKED = {"masked_absent", "empty_masked", "eacces", "eperm", "erofs", "ebusy", "exdev", "enotdir"}
MUST_BE_BLOCKED = ("read_direct", "read_deep_file", "read_dotdot_spelling", "read_proc_root_spelling",
                   "read_via_preexisting_symlink", "read_via_runtime_created_symlink", "list_directory",
                   "read_via_cat_child", "read_via_python_child", "read_via_shell_glob_child",
                   "hardlink_out_of_target", "rename_target_away", "write_outside_workspace")
CONTROLS = ("control_write_workspace", "control_read_workspace", "control_python_child")


def check(name: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, **extra}


def roll_up(checks: list[dict[str, Any]]) -> str:
    st = [c["status"] for c in checks]
    if not st:
        return UNVERIFIED
    if FAIL in st:
        return FAIL
    if UNVERIFIED in st:
        return UNVERIFIED
    return PASS


# ---------------------------------------------------------------------------------------------
def verify_integrity(ctx: Context, reg: Registry | None) -> tuple[list[dict[str, Any]], Registry | None]:
    lo = ctx.layout
    out: list[dict[str, Any]] = []
    marker = read_marker(ctx)
    out.append(check("no_interrupted_operation", FAIL if marker is not None else PASS,
                     f"pending operation: {marker}" if marker is not None else "no marker present"))
    try:
        reg = registry.load(lo)
        out.append(check("registry_trusted_and_valid", PASS,
                         f"{len(reg.targets)} target(s), revision {reg.revision}, policy {reg.policy_revision}"))
    except ProtectError as exc:
        return out + [check("registry_trusted_and_valid", FAIL, f"{exc.code}: {exc.message}")], None
    try:
        gen = jsonio.read_json(lo.srt_targets_file)
        ok = gen == registry.generated_srt_targets(reg)
        out.append(check("generated_policy_matches_registry", PASS if ok else FAIL,
                         "identical" if ok else "generated policy differs from registry (tampered/stale)"))
    except (OSError, ValueError) as exc:
        out.append(check("generated_policy_matches_registry", FAIL, f"unreadable: {exc}"))
    try:
        rt = runtime_mod.check_runtime(ctx, full_hash=True)
        out.append(check("srt_runtime_integrity", PASS, f"root-owned runtime, srt {rt.srt_version}, all file hashes match"))
    except ProtectError as exc:
        out.append(check("srt_runtime_integrity", FAIL, f"{exc.code}: {exc.message}"))
    table = ctx.read_mounts()
    for t in reg.sorted_targets():
        ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                     t.filesystem_type, t.mount_source, t.fs_uuid, mounts=table)
        out.append(check(f"identity:{t.id}", PASS if ident.status == "OK" else STALE,
                         ident.detail or "same directory, same mount" + (
                             "; " + "; ".join(ident.warnings) if ident.warnings else ""),
                         target=t.canonical_path))
    return out, reg


# ---------------------------------------------------------------------------------------------
def verify_l4(ctx: Context, targets: list[Target]) -> list[dict[str, Any]]:
    out = []
    table = ctx.read_mounts()
    for t in targets:
        name = f"l4:{t.id}"
        ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                     t.filesystem_type, t.mount_source, t.fs_uuid, mounts=table)
        if ident.status != "OK":
            out.append(check(name + ":stat", STALE, ident.detail, target=t.canonical_path))
            continue
        fd = paths.open_dir_nofollow(t.canonical_path)
        try:
            m = ctx.host.stat(fd)
        finally:
            os.close(fd)
        good = (m.uid, m.gid, m.mode) == (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE)
        out.append(check(name + ":stat", PASS if good else FAIL,
                         "root:root 0700" if good else f"owner/mode {m.uid}:{m.gid} {m.mode:04o}",
                         target=t.canonical_path))
        if ctx.euid() == 0:
            out.append(check(name + ":unprivileged_denied", UNVERIFIED,
                             "running as root; the kernel denial can only be observed as an ordinary user",
                             target=t.canonical_path))
            continue
        try:
            os.listdir(t.canonical_path)
            out.append(check(name + ":unprivileged_denied", FAIL,
                             "an ordinary-user listing SUCCEEDED outside the sandbox", target=t.canonical_path,
                             classification="not_denied"))
        except PermissionError:
            out.append(check(name + ":unprivileged_denied", PASS,
                             "EACCES from the kernel for an ordinary user, outside SRT",
                             target=t.canonical_path, classification="linux_permission_denied"))
        except OSError as exc:
            out.append(check(name + ":unprivileged_denied", FAIL,
                             f"unexpected error {exc.strerror}; cannot attribute to L4",
                             target=t.canonical_path, classification="unknown"))
    return out


# ---------------------------------------------------------------------------------------------
def _pseudo_target(path: str) -> Target:
    st = os.stat(path)
    return Target(id="verify-fixture", input_path=path, canonical_path=path, st_dev=st.st_dev,
                  st_ino=st.st_ino, filesystem_type="n/a", mount_point="/", created_at="n/a")


def verify_l3(ctx: Context, reg: Registry, profile: str | None, adapter: Any,
              real_paths: list[str] | None = None) -> list[dict[str, Any]]:
    """The policy under test is the REAL effective one (every target whose sandbox layer is on); the mask
    probe covers `real_paths` (default: all of them)."""
    out: list[dict[str, Any]] = []
    try:
        rt = runtime_mod.check_runtime(ctx)
    except ProtectError as exc:
        return [check("srt_available", FAIL, f"{exc.code}: {exc.message}")]
    out.append(check("srt_available", PASS, f"trusted runtime srt {rt.srt_version}"))
    policy = load_policy(ctx.layout)
    domains = profiles_mod.resolve_profile(profile or policy.get("default_profile") or adapter.default_profile,
                                           policy)
    token = secrets.token_hex(12)
    marker = f"PF-SYNTHETIC-MARKER-{token}"
    state_root = Path(os.environ.get("XDG_RUNTIME_DIR") or os.path.join(os.path.expanduser("~"), ".local", "state"))
    base_parent = state_root / "protect-folder"
    base_parent.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="verify-", dir=base_parent))
    settings_path = None
    try:
        T, W, OUT = base / "fixture target", base / "workspace", base / "outside"
        (T / "sub").mkdir(parents=True)
        W.mkdir()
        OUT.mkdir()
        (T / "marker.txt").write_text(marker)
        (T / "sub" / "deep.txt").write_text(marker)
        (W / "control.txt").write_text("control-ok")
        os.symlink(T, W / "alias")
        # Precondition: the fixture IS readable here, outside the sandbox, by this same user.
        pre = (T / "marker.txt").read_text() == marker
        out.append(check("precondition_fixture_readable_outside_sandbox", PASS if pre else FAIL,
                         "the marker is readable without SRT, so any block inside is attributable to SRT"))
        sandbox_targets = reg.with_layer("sandbox_runtime")
        targets = sandbox_targets + [_pseudo_target(str(T))]
        settings = srt_policy.compile_settings(ctx, targets, workspace=str(W), extra_write=["/tmp"],
                                               allowed_domains=domains, rt=rt)
        settings_path = srt_policy.write_private_settings(settings, str(base_parent))
        env = {k: v for k, v in os.environ.items() if k not in policy.get("env_drop", [])}
        # 1) the effective policy masks every REAL target (mount table inside the sandbox)
        real = list(real_paths) if real_paths is not None else [t.canonical_path for t in sandbox_targets]
        try:
            probes.probe_masks(rt, settings_path, real + [str(T)], cwd=str(W), env=env)
            out.append(check("effective_policy_masks_real_targets", PASS,
                             f"{len(real)} real target(s) + synthetic fixture appear as tmpfs masks inside the sandbox"))
        except ProtectError as exc:
            out.append(check("effective_policy_masks_real_targets", FAIL, f"{exc.code}: {exc.message}"))
        # 2) behavioural tests against the synthetic fixture
        cfg = json.dumps({"T": str(T), "W": str(W), "marker": marker, "outside": str(OUT)})
        proc = probes.run_in_sandbox(rt, settings_path, [sys.executable, "-I", "-c", PROBE_SRC, cfg],
                                     cwd=str(W), env=env)
        blob = proc.stdout + proc.stderr
        try:
            results = {r["name"]: r for r in json.loads(proc.stdout.strip().splitlines()[-1])}
        except (ValueError, IndexError):
            out.append(check("sandbox_probe_ran", FAIL, f"probe produced no result (rc={proc.returncode}): "
                             f"{proc.stderr.strip()[-300:]}"))
            return out
        out.append(check("marker_absent_from_sandbox_output", PASS if marker not in blob else FAIL,
                         "the secret marker never reached the sandbox output" if marker not in blob
                         else "MARKER LEAKED into sandbox output"))
        for name in CONTROLS:
            ok = results.get(name, {}).get("outcome") in ("ok", "ok_no_marker")
            out.append(check(f"control:{name}", PASS if ok else FAIL,
                             "normal operation works inside the sandbox" if ok else
                             f"{results.get(name, {}).get('outcome')}: sandbox not functioning normally"))
        for name in MUST_BE_BLOCKED:
            outcome = results.get(name, {}).get("outcome", "missing")
            if outcome == "leak":
                out.append(check(f"blocked:{name}", FAIL, "PROTECTED CONTENT WAS READABLE", classification="leak"))
            elif outcome in BLOCKED:
                cls = "srt_mask_absent_or_empty" if outcome in ("masked_absent", "empty_masked") else \
                      f"srt_{outcome}"
                out.append(check(f"blocked:{name}", PASS, f"observed {outcome}", classification=cls))
            else:
                out.append(check(f"blocked:{name}", FAIL, f"unexpected outcome {outcome!r}",
                                 classification="unknown"))
        # write into the masked directory may "succeed" in the in-sandbox tmpfs; it must never persist
        persisted = (T / "created_by_agent.txt").exists()
        w = results.get("write_into_target", {}).get("outcome")
        out.append(check("blocked:write_into_target", FAIL if persisted else PASS,
                         "the write reached the real directory" if persisted else
                         f"write outcome {w!r} and nothing persisted on the host",
                         classification="leak" if persisted else "srt_mask_ephemeral"))
        intact = T.is_dir() and (T / "marker.txt").read_text() == marker and not (OUT / "renamed").exists()
        out.append(check("target_intact_after_attacks", PASS if intact else FAIL,
                         "fixture still at its original path with unchanged content" if intact else
                         "fixture was moved or modified"))
        out.append(check("no_file_escaped_to_outside_dir", PASS if not (OUT / "x").exists() else FAIL,
                         "nothing written outside the workspace"))
    finally:
        if settings_path:
            try:
                os.unlink(settings_path)
            except OSError:
                pass
        shutil.rmtree(base, ignore_errors=True)
    return out


# ---------------------------------------------------------------------------------------------
def _rollup_for(checks: list[dict[str, Any]], prefix: str) -> str:
    mine = [c for c in checks if c["name"].startswith(prefix)]
    return roll_up(mine) if mine else UNVERIFIED


def _inherited_l4_checks(ctx: Context, child: Target, parent_path: str) -> list[dict[str, Any]]:
    name = f"l4:{child.id}:inherited_unprivileged_denied"
    if ctx.euid() == 0:
        return [check(name, UNVERIFIED, "running as root; the denial can only be observed as an ordinary user",
                      target=child.canonical_path)]
    try:
        os.listdir(child.canonical_path)
        return [check(name, FAIL, f"an ordinary-user listing SUCCEEDED although protected parent "
                      f"{parent_path!r} should block traversal", target=child.canonical_path)]
    except PermissionError:
        return [check(name, PASS, f"EACCES for an ordinary user (blocked by protected parent {parent_path!r})",
                      target=child.canonical_path)]
    except OSError as exc:
        return [check(name, FAIL, f"unexpected error {exc.strerror}", target=child.canonical_path)]


def run_verify(ctx: Context, *, path: str | None = None, agent: str | None = None,
               profile: str | None = None, live: bool = False) -> dict[str, Any]:
    adapter = adapters_mod.by_name(agent) if agent else adapters_mod.GenericAdapter()
    integrity, reg = verify_integrity(ctx, None)
    layers: dict[str, dict[str, Any]] = {}
    caps = adapter.capabilities(ctx)
    per_target: list[dict[str, Any]] = []
    selected: list[Target] = []
    if reg is not None:
        selected = reg.sorted_targets()
        if path is not None:
            from ..status import select
            sel = {t.id for t in select(ctx, path)}
            selected = [t for t in selected if t.id in sel]
    eff = {t.id: reg.effective(t) for t in selected} if reg is not None else {}
    # a layer is tested only if it is enabled (own or inherited) for at least one SELECTED directory
    enabled = {k: any(eff[t.id][k]["enabled"] for t in selected) for k in layers_mod.LAYERS}
    disabled_layer = lambda: {"status": DISABLED, "checks": [],
                              "note": "disabled for the selected director" + ("y" if len(selected) == 1 else "ies")
                                      + "; not tested"}

    for cfg in ("agent_permissions", "pre_execution_hook"):
        key = layers_mod.REPORT_KEY[cfg]
        cap = caps.get(key, NOT_APPLICABLE)
        layers[key] = ({"status": cap, "checks": [],
                        "note": "not provided by this adapter" if cap in (NOT_APPLICABLE, UNSUPPORTED) else ""}
                       if (enabled[cfg] or reg is None) else disabled_layer())
    if reg is None:
        layers["srt"] = {"status": UNVERIFIED, "checks": []}
        layers["linux_permissions"] = {"status": UNVERIFIED, "checks": []}
    else:
        # --- L3: real effective policy; masks checked for the selected directories' sandbox sources
        if enabled["sandbox_runtime"]:
            src_ids = {eff[t.id]["sandbox_runtime"]["source_id"] for t in selected if eff[t.id]["sandbox_runtime"]["enabled"]}
            real = [x.canonical_path for x in reg.with_layer("sandbox_runtime") if x.id in src_ids]
            l3 = verify_l3(ctx, reg, profile, adapter, real_paths=real)
            layers["srt"] = {"status": roll_up(l3), "checks": l3}
        else:
            layers["srt"] = disabled_layer()
        # --- L4: own-enabled directories by stat + unprivileged denial; inherited ones by denial via the parent
        l4_checks: list[dict[str, Any]] = []
        if enabled["linux_permissions"]:
            own = {t.id: t for t in selected if eff[t.id]["linux_permissions"]["own"]}
            for t in selected:
                e = eff[t.id]["linux_permissions"]
                if e["enabled"] and not e["own"]:
                    src = reg.find_id(e["source_id"])
                    if src is not None:
                        own.setdefault(src.id, src)        # the parent's lock is what protects this child
            l4_checks = verify_l4(ctx, sorted(own.values(), key=lambda x: x.canonical_path))
            for t in selected:
                e = eff[t.id]["linux_permissions"]
                if e["enabled"] and not e["own"]:
                    l4_checks += _inherited_l4_checks(ctx, t, e["inherited_from"])
            layers["linux_permissions"] = {"status": roll_up(l4_checks), "checks": l4_checks}
        else:
            layers["linux_permissions"] = disabled_layer()
        hook = getattr(adapter, "verify", None)
        if hook and (enabled["agent_permissions"] or enabled["pre_execution_hook"]):
            for key, res in hook(ctx, reg, profile, live, enabled={
                    "agent_permissions": enabled["agent_permissions"],
                    "pre_execution_hook": enabled["pre_execution_hook"]}).items():
                layers[key] = res
        # --- per-directory view: ONLY enabled layers carry a result; configured != verified
        now = ctx.now()
        for t in selected:
            row = {"id": t.id, "canonical_path": t.canonical_path, "layers": {}}
            for cfg in layers_mod.LAYERS:
                e = eff[t.id][cfg]
                key = layers_mod.REPORT_KEY[cfg]
                if not e["enabled"]:
                    status, detail = DISABLED, "disabled for this directory"
                elif cfg == "linux_permissions":
                    status = _rollup_for(layers[key]["checks"], f"l4:{t.id}:" if e["own"] else f"l4:{t.id}:inherited")
                    detail = "root:root 0700 + unprivileged denial" if e["own"] else \
                        f"enforced through protected parent {e['inherited_from']}"
                    if e["own"] and status == UNVERIFIED and not layers[key]["checks"]:
                        status = UNVERIFIED
                else:
                    status, detail = layers[key]["status"], layers[key].get("note", "")
                row["layers"][cfg] = {"enabled": e["enabled"], "own": e["own"], "inherited_from": e["inherited_from"],
                                      "status": status, "state": layers_mod.state_for(e["enabled"], status),
                                      "verified_at": now if status == PASS else None, "detail": detail}
            per_target.append(row)
    n = sum(1 for k in LAYER_KEYS if layers[k]["status"] == PASS)
    integ_status = roll_up(integrity) if integrity else UNVERIFIED
    doc = {"agent": adapter.name, "protect_folder_version": VERSION,
           "policy_revision": reg.policy_revision if reg else None,
           "integrity": {"status": integ_status, "checks": integrity},
           "layers": layers, "verified_layers": f"{n}/4",
           "configured_layers": sum(1 for k in layers_mod.LAYERS if enabled[k]),
           "targets": per_target,
           "summary": {k: layers[k]["status"] for k in LAYER_KEYS}}
    if reg is not None:
        agent_version = adapter.agent_version() if hasattr(adapter, "agent_version") else None
        cache.store_targets(adapter.name, reg.policy_revision, agent_version,
                            {r["id"]: {c: {"status": v["status"], "detail": v["detail"][:200]}
                                       for c, v in r["layers"].items() if v["enabled"]} for r in per_target},
                            ctx.now())
        if path is None:
            cache.store(adapter.name, {"policy_revision": reg.policy_revision, "agent_version": agent_version,
                                       "layers": doc["summary"], "protect_folder_version": VERSION})
    return doc
