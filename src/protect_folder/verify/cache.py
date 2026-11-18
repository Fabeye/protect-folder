"""Per-user cache of the last `verify` result. Convenience only: not a trust anchor."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..userstate import state_dir


def cache_path() -> Path:
    return state_dir() / "verify.json"


def load() -> dict[str, Any]:
    try:
        return json.loads(cache_path().read_text())
    except (OSError, ValueError):
        return {}


def store(agent: str, record: dict[str, Any]) -> None:
    p = cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        data = load()
        data.setdefault("entries", {})[agent] = record
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, indent=2))
        os.replace(tmp, p)
    except OSError:
        pass     # best effort


def lookup(agent: str, policy_revision: str, agent_version: str | None) -> dict[str, str] | None:
    """Layer statuses from the last verify for this agent, with STALE if the policy or agent
    version changed since. None if never verified."""
    rec = load().get("entries", {}).get(agent)
    if not rec:
        return None
    layers = dict(rec.get("layers", {}))
    if rec.get("policy_revision") != policy_revision or rec.get("agent_version") != agent_version:
        return {k: ("STALE" if v == "PASS" else v) for k, v in layers.items()}
    return layers


def store_targets(agent: str, policy_revision: str, agent_version: str | None,
                  results: dict[str, dict[str, dict[str, Any]]], at: str) -> None:
    """Per-directory, per-layer results of one verify run. A different policy revision (any change to
    targets or layer selection) discards what was recorded for other revisions."""
    p = cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        data = load()
        rec = data.setdefault("entries", {}).setdefault(agent, {})
        if rec.get("targets_policy_revision") != policy_revision:
            rec["targets"] = {}
        rec["targets_policy_revision"] = policy_revision
        rec["targets_agent_version"] = agent_version
        for tid, layers in results.items():
            rec.setdefault("targets", {}).setdefault(tid, {}).update(
                {k: dict(v, at=at) for k, v in layers.items()})
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, indent=2))
        os.replace(tmp, p)
    except OSError:
        pass


def target_layer(tid: str, layer: str, policy_revision: str,
                 current_version: Any = None) -> dict[str, Any] | None:
    """Best evidence for one directory's layer under the CURRENT policy revision, across agents:
    any FAIL wins, else any PASS, else None (never verified / stale -> shown as '?').
    `current_version(agent)` supplies the installed agent version for L1/L2 freshness."""
    best: dict[str, Any] | None = None
    for agent, rec in load().get("entries", {}).items():
        if rec.get("targets_policy_revision") != policy_revision:
            continue
        r = rec.get("targets", {}).get(tid, {}).get(layer)
        if not r:
            continue
        if layer in ("agent_permissions", "pre_execution_hook") and current_version is not None:
            if current_version(agent) != rec.get("targets_agent_version"):
                continue                                  # the agent changed since: evidence is stale
        item = {"status": r.get("status"), "at": r.get("at"), "agent": agent, "detail": r.get("detail", "")}
        if item["status"] == "FAIL":
            return item
        if item["status"] == "PASS" and (best is None or str(item["at"]) > str(best["at"])):
            best = item
    return best
