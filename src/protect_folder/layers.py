"""Per-directory protection layers: names, defaults, validation, effective (inherited) protection and
the display vocabulary shared by list/status/verify.

Configuration vocabulary (registry/CLI):   agent_permissions, pre_execution_hook, sandbox_runtime,
linux_permissions.  Report vocabulary (verify JSON, older code): native_permissions, pre_execution_hook,
srt, linux_permissions.  REPORT_KEY maps between them in exactly one place."""

from __future__ import annotations

from typing import Any, Iterable

from .errors import ProtectError

LAYERS = ("agent_permissions", "pre_execution_hook", "sandbox_runtime", "linux_permissions")
REPORT_KEY = {"agent_permissions": "native_permissions", "pre_execution_hook": "pre_execution_hook",
              "sandbox_runtime": "srt", "linux_permissions": "linux_permissions"}
CONFIG_KEY = {v: k for k, v in REPORT_KEY.items()}
LABEL = {"agent_permissions": "Agent permissions", "pre_execution_hook": "Pre-execution hook",
         "sandbox_runtime": "SRT sandbox", "linux_permissions": "Linux permissions"}
SHORT = {"agent_permissions": "Agent", "pre_execution_hook": "Hook", "sandbox_runtime": "SRT",
         "linux_permissions": "Linux"}
FILESYSTEM_LAYERS = ("sandbox_runtime", "linux_permissions")

# per-layer display states (spec: CONFIGURED, VERIFIED, DISABLED, FAILED)
VERIFIED, CONFIGURED, DISABLED, FAILED = "VERIFIED", "CONFIGURED", "DISABLED", "FAILED"
INDICATOR = {VERIFIED: "✓", CONFIGURED: "?", DISABLED: "—", FAILED: "✗"}


def default_layers() -> dict[str, bool]:
    return {k: True for k in LAYERS}


def validate_layers(raw: Any) -> dict[str, bool]:
    if not isinstance(raw, dict) or set(raw) != set(LAYERS) or not all(isinstance(v, bool) for v in raw.values()):
        raise ProtectError("TAMPERED", "registry entry has a malformed 'layers' object "
                           f"(expected booleans for exactly: {', '.join(LAYERS)})")
    return {k: raw[k] for k in LAYERS}


def _within(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def effective(targets: Iterable[Any], target: Any) -> dict[str, dict[str, Any]]:
    """Effective protection of `target`: a layer is on if the target enables it OR any protected
    ANCESTOR enables it (a child can never opt out of a restriction its parent imposes).
    Returns {layer: {"own": bool, "enabled": bool, "inherited_from": path|None, "source_id": id}}."""
    ancestors = sorted((o for o in targets if o.id != target.id and _within(target.canonical_path, o.canonical_path)),
                       key=lambda o: len(o.canonical_path), reverse=True)        # nearest first
    out: dict[str, dict[str, Any]] = {}
    for layer in LAYERS:
        own = bool(target.layers[layer])
        src = next((o for o in ancestors if o.layers[layer]), None)
        out[layer] = {"own": own, "enabled": own or src is not None,
                      "inherited_from": None if own or src is None else src.canonical_path,
                      "source_id": target.id if own else (src.id if src else None)}
    return out


def enabled_any(targets: Iterable[Any], layer: str) -> bool:
    return any(t.layers[layer] for t in targets)


def count_enabled(layers: dict[str, bool]) -> int:
    return sum(1 for v in layers.values() if v)


def state_for(enabled: bool, status: str | None) -> str:
    """Map a verification status (PASS/FAIL/other/None) to the display state. A layer that is merely
    configured is NEVER reported as verified."""
    if not enabled:
        return DISABLED
    if status == "PASS":
        return VERIFIED
    if status == "FAIL":
        return FAILED
    return CONFIGURED


def layer_warnings(layers: dict[str, bool]) -> list[str]:
    w: list[str] = []
    if not layers["linux_permissions"]:
        w.append("Linux permissions are OFF for this directory: its ownership/mode/ACL are unchanged, so "
                 "there is NO OS-level protection. Anything running as your user outside the sandbox can "
                 "read it; this is not equivalent to root:root 0700.")
    if not layers["sandbox_runtime"]:
        w.append("SRT sandbox is OFF for this directory: sandboxed agents started with 'protect-folder run' "
                 "can read it unless Linux permissions deny them. Agent permissions and the pre-execution "
                 "hook are advisory and can be bypassed by any program the agent runs.")
    if not layers["sandbox_runtime"] and not layers["linux_permissions"]:
        w.append("BOTH filesystem-enforcement layers (SRT and Linux permissions) are OFF: no independent "
                 "filesystem-level enforcement remains for this directory. Only the agent's own permission "
                 "rules and the pre-execution hook apply, and both are bypassable.")
    if not layers["agent_permissions"]:
        w.append("Agent permissions are OFF: the agent's native tool rules do not cover this directory.")
    if not layers["pre_execution_hook"]:
        w.append("Pre-execution hook is OFF: commands and scripts are not inspected for this directory.")
    return w


def parse_changes(ns: Any, *, allow_enable: bool) -> dict[str, bool]:
    """Turn CLI flags into {layer: bool} changes. `--no-X` disables; (set-layers only) `--X` enables;
    `--all` enables everything. Contradictory combinations are errors, never guessed."""
    flags = {"agent_permissions": "agent_permissions", "pre_execution_hook": "hook",
             "sandbox_runtime": "srt", "linux_permissions": "linux"}
    changes: dict[str, bool] = {}
    if getattr(ns, "all", False):
        changes = {k: True for k in LAYERS}
    for layer, flag in flags.items():
        off = getattr(ns, "no_" + flag.replace("-", "_"), False)
        on = allow_enable and getattr(ns, "enable_" + flag.replace("-", "_"), False)
        if off and (on or getattr(ns, "all", False)):
            raise ProtectError("USAGE", f"contradictory options for {LABEL[layer]!r}: "
                               f"--no-{flag} together with {'--all' if getattr(ns, 'all', False) else '--' + flag}")
        if off:
            changes[layer] = False
        elif on:
            changes[layer] = True
    return changes
