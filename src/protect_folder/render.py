"""Human-readable rendering of per-directory layer state: the `list` table and the `status` detail view.

Pure functions (width, colour and home are parameters) so they are easy to test. Everything that comes
from the filesystem is sanitised before display: a directory name can contain control characters or
terminal escape sequences, and must not be able to rewrite the operator's screen."""

from __future__ import annotations

import os
import shutil
import sys
import unicodedata
from typing import Any

from . import layers as L

GREEN, RED, YELLOW, DIM, BOLD, RESET = "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[2m", "\x1b[1m", "\x1b[0m"
COLORS = {L.VERIFIED: GREEN, L.FAILED: RED, L.CONFIGURED: YELLOW, L.DISABLED: DIM}
HEADERS = ("ID", "Directory", "Agent", "Hook", "SRT", "Linux", "Status")
MIN_DIR_WIDTH = 18


def safe(text: str) -> str:
    """Replace control / unassignable characters (incl. surrogate-escaped bytes) with visible escapes."""
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat[0] == "C" or ch in "  ":
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def wcwidth(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def width(text: str) -> int:
    return sum(wcwidth(c) for c in text)


def pad(text: str, w: int) -> str:
    return text + " " * max(0, w - width(text))


def truncate_tail(text: str, w: int) -> str:
    """Keep the END of the text (the part that identifies a directory) within `w` columns."""
    if width(text) <= w:
        return text
    out, used = [], 1                                  # 1 column for the ellipsis
    for ch in reversed(text):
        cw = wcwidth(ch)
        if used + cw > w:
            break
        out.append(ch)
        used += cw
    return "…" + "".join(reversed(out))


def tilde(path: str, homes: list[str]) -> str:
    for h in sorted(homes, key=len, reverse=True):
        if h and (path == h or path.startswith(h.rstrip("/") + "/")):
            return "~" + path[len(h.rstrip("/")):]
    return path


def shorten(path: str, w: int) -> str:
    """Fit a path into w columns, keeping the first and the trailing components: /mnt/ssd2/…/private."""
    if width(path) <= w:
        return path
    parts = path.split("/")
    lead = "/".join(parts[:2]) if path.startswith("/") and len(parts) > 2 else parts[0]
    for k in range(len(parts) - 1, 0, -1):
        cand = f"{lead}/…/" + "/".join(parts[-k:])
        if width(cand) <= w and k >= 1:
            best = cand
            break
    else:
        return truncate_tail(path, w)
    # prefer the longest trailing part that still fits
    for k in range(len(parts) - 1, 0, -1):
        cand = f"{lead}/…/" + "/".join(parts[-k:])
        if width(cand) <= w:
            return cand
    return best


def use_color(no_color: bool, stream: Any = None) -> bool:
    stream = stream or sys.stdout
    if no_color or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def term_width(default: int = 100) -> int:
    if os.environ.get("COLUMNS", "").isdigit():
        return int(os.environ["COLUMNS"])
    return shutil.get_terminal_size((default, 24)).columns


def paint(text: str, state: str, color: bool, bold: bool = False) -> str:
    if not color:
        return text
    return (BOLD if bold else "") + COLORS.get(state, "") + text + RESET


def cell(view: dict[str, Any]) -> tuple[str, str]:
    """(text, state): indicator plus '*' when the protection is inherited from a protected parent."""
    mark = "*" if (view["inherited_from"] and not view["enabled"]) else ""
    return view["indicator"] + mark, view["state"]


def status_text(row: dict[str, Any]) -> str:
    s = f"{row['verified_count']}/4"
    return s + (" ⟳ restart" if row["restart_pending"] else "")


def render_width(body: str, stat: str) -> int:
    return width(body) + 3 + width(stat)


def render_table(rows: list[dict[str, Any]], *, cols: int, color: bool, homes: list[str]) -> list[str]:
    if not rows:
        return ["no protected directories registered"]
    ids = [r["id"][:8] for r in rows]
    stat_w = max(width(status_text(r)) for r in rows + [{"verified_count": 4, "restart_pending": False}])
    fixed = [max(8, len("ID")), None, 6, 5, 5, 6, max(stat_w, len("Status"))]
    gap = 2
    dir_w = cols - sum(w for w in fixed if w) - gap * (len(fixed) - 1)
    lines: list[str] = []
    if dir_w < MIN_DIR_WIDTH:                          # too narrow for a table: one block per directory
        for r, rid in zip(rows, ids):
            lines.append(f"[{rid}] " + truncate_tail(safe(tilde(r["canonical_path"], homes)), max(8, cols - 11)))
            cells = []
            for key, short in (("agent_permissions", "Agent"), ("pre_execution_hook", "Hook"),
                               ("sandbox_runtime", "SRT"), ("linux_permissions", "Linux")):
                txt, st = cell(r["layer_details"][key])
                cells.append((short, txt, st))
            stat = status_text(r)

            def build(compact: bool) -> str:
                body = "  ".join(f"{(n[0] + ':') if compact else n + ' '}{paint(t, st, color)}" for n, t, st in cells)
                return "    " + body
            plain = lambda compact: "    " + "  ".join(f"{(n[0] + ':') if compact else n + ' '}{t}" for n, t, _ in cells)
            for compact in (False, True):
                if render_width(plain(compact), stat) <= cols:
                    lines.append(build(compact) + f"   {stat}")
                    break
            else:                                       # still too wide: status goes on its own line
                lines.append(build(True))
                lines.append("    " + truncate_tail(stat, max(4, cols - 4)))
        return lines
    widths = [fixed[0], dir_w, fixed[2], fixed[3], fixed[4], fixed[5], fixed[6]]
    head = (" " * gap).join(pad(h, w) for h, w in zip(HEADERS, widths))
    lines.append(paint(head, "", color, bold=True))
    for r, rid in zip(rows, ids):
        cells = [pad(rid, widths[0]),
                 pad(shorten(safe(tilde(r["canonical_path"], homes)), dir_w), dir_w)]
        for key, w in zip(("agent_permissions", "pre_execution_hook", "sandbox_runtime", "linux_permissions"), widths[2:6]):
            txt, st = cell(r["layer_details"][key])
            cells.append(paint(pad(txt, w), st, color))
        full = r["verified_count"] == 4
        cells.append(paint(pad(status_text(r), widths[6]),
                           L.FAILED if r["failed_layers"] else (L.VERIFIED if full else L.CONFIGURED), color))
        lines.append((" " * gap).join(cells))
    return lines


def legend(rows: list[dict[str, Any]], pending: dict[str, Any]) -> list[str]:
    out = ["", "✓ enabled and verified   ? enabled, NOT verified yet   ✗ enabled, verification FAILED   — disabled",
           "* protection inherited from a protected parent directory   Status = verified layers / 4"]
    if any(any(v["state"] == L.CONFIGURED for v in r["layer_details"].values()) for r in rows):
        out.append("'?' is not a pass: run 'protect-folder verify' (add --agent claude --live for the agent layers).")
    if pending.get("sessions"):
        n = len(pending["sessions"])
        out.append(f"⟳ restart pending: {n} running protected session(s) started before the latest policy "
                   "change are NOT covered by it; restart them with 'protect-folder run -- ...'.")
    out.append("Sessions not started through 'protect-folder run' are never covered. This is not a defence "
               "against root/sudo by your own account.")
    for r in rows:
        if not r["layer_details"]["sandbox_runtime"]["effective"] and not r["layer_details"]["linux_permissions"]["effective"]:
            out.append(f"WARNING: {r['id'][:8]}: no independent filesystem-level enforcement (SRT and Linux "
                       "permissions are both off).")
    return out


def render_detail(row: dict[str, Any], *, color: bool, homes: list[str]) -> list[str]:
    """The per-directory block of `status` / `verify`."""
    lines = [f"Directory: {safe(row['canonical_path'])}   (id {row['id'][:8]}, {row.get('filesystem_type', '')} "
             f"@ {safe(row.get('mount_point', ''))})", ""]
    for key in L.LAYERS:
        v = row["layer_details"][key]
        onoff = "[ON] " if v["enabled"] else ("[ON*]" if v["effective"] else "[OFF]")
        label = f"{L.LABEL[key]:20}"
        tail = v["state"]
        extra = ""
        if v["state"] == L.VERIFIED and v["verified_at"]:
            extra = f"  verified {v['verified_at']}" + (f" via {v['agent']}" if v.get("agent") else "")
        elif v["state"] == L.CONFIGURED:
            extra = "  (enabled, not verified)"
        elif v["state"] == L.FAILED:
            extra = f"  {safe(v['detail'])}"
        elif v["state"] == L.DISABLED:
            extra = "  (explicitly disabled)"
        if v["inherited_from"] and not v["enabled"]:
            extra += f"  [inherited from {safe(v['inherited_from'])}]"
        lines.append(f"{onoff} {label} " + paint(f"{tail:10}", v["state"], color) + extra)
    lines += ["", f"Protection: {row['configured_count']}/4 configured, {row['verified_count']}/4 verified"
              + (f", {len(row['failed_layers'])} FAILED" if row["failed_layers"] else "")]
    if row["restart_pending"]:
        lines.append(f"⟳ RESTART PENDING: {len(row['restart_pending_pids'])} running session(s) predate the "
                     "latest policy change and are not covered by it.")
    for n in row["security_notes"]:
        lines.append(f"  ! {n}")
    return lines
