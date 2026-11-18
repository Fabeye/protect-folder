"""Administrative audit log. Never records file contents or source snippets."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from .context import Context

# Fields that may be written to a log record. Anything else is dropped (defence against
# accidentally logging secrets passed in `extra`).
ALLOWED_EXTRA = {"revision", "policy_revision", "txid", "dry_run", "warnings", "agent", "tool",
                 "reason", "layers", "path_count", "detail"}


def log_admin(ctx: Context, op: str, outcome: str, reason_code: str = "OK",
              target_id: str | None = None, **extra: Any) -> None:
    rec: dict[str, Any] = {
        "ts": ctx.now(), "actor_uid": ctx.actor_uid(), "euid": ctx.euid(), "op": op,
        "outcome": outcome, "reason_code": reason_code, "target_id": target_id,
    }
    for k, v in extra.items():
        if k in ALLOWED_EXTRA:
            rec[k] = v
    line = json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n"
    try:
        ctx.layout.log_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(ctx.layout.admin_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:  # logging must never block recovery/unlock, but must be visible
        print(f"warning: could not write admin log: {exc}", file=sys.stderr)


def read_admin_log(ctx: Context) -> list[dict[str, Any]]:
    out = []
    try:
        with open(ctx.layout.admin_log, "rb") as fh:
            for raw in fh:
                try:
                    out.append(json.loads(raw.decode("utf-8")))
                except ValueError:
                    out.append({"ts": None, "op": "?", "outcome": "CORRUPT_LINE"})
    except FileNotFoundError:
        pass
    return out
