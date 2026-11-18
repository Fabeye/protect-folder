"""Pre-execution inspection of an agent tool call against the protected-directory policy.

This is a fast, best-effort filter (L2). It is NOT a confidentiality boundary: it cannot solve
arbitrary program analysis, compiled code, generated code or runtime-dependent paths. Anything it
cannot model is reported as INCOMPLETE_INSPECTION rather than silently allowed or invented."""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Any

from . import shell
from .pyscan import PyScanner

ALLOW, DENY, INCOMPLETE = "ALLOW", "DENY", "INCOMPLETE_INSPECTION"
ELEVATION = ("sudo", "su", "pkexec", "doas", "sudoedit", "run0")
WRAPPERS = {"env", "command", "exec", "nohup", "time", "nice", "ionice", "timeout", "setsid", "stdbuf",
            "xargs", "watch", "builtin", "chrt", "taskset", "unbuffer", "fakeroot", "caffeinate"}
WRAPPER_ARG_OPTS = {"nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k"},
                    "env": {"-u", "-S", "-C", "-P"}, "stdbuf": {"-i", "-o", "-e"}, "xargs": {"-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s"},
                    "taskset": set(), "chrt": set(), "watch": {"-n", "-d"}}
DATA_ONLY = {"echo", "printf", "true", ":"}
SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "ash", "busybox"}
GENERIC_INTERP = {"ruby", "perl", "php", "lua", "Rscript", "julia", "tclsh", "awk", "gawk"}
NODE = {"node", "nodejs", "bun", "deno"}
BASH_TOOLS = {"bash", "shell", "execute", "run_command", "exec", "terminal"}
PATH_KEYS = {"file_path", "filepath", "filePath", "path", "notebook_path", "directory", "dir", "cwd",
             "workdir", "root", "paths", "files", "file", "target", "destination", "source"}
MAX_DEPTH = 5
MAX_FOLLOW_FILES = 25
NAME_CHARS = re.compile(r"[A-Za-z0-9_.~\-/]")
BEFORE_OK = set(" \t\r\n=:,;(\"'<>|&{[`")

REASONS = {
    "DIRECT_REFERENCE": "Protected directory; reading is prohibited by policy",
    "SCRIPT_REFERENCE": "Protected directory referenced by the script; execution is prohibited by policy",
    "ELEVATION": "Privilege escalation (sudo/su/pkexec/doas) is prohibited by policy",
}


@dataclass(frozen=True)
class ProtectedPath:
    id: str
    path: str


@dataclass
class InspectPolicy:
    targets: tuple[ProtectedPath, ...]
    mode: str = "balanced"
    max_source_bytes: int = 1 << 20
    max_seconds: float = 2.0
    policy_revision: str = ""
    home: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "InspectPolicy":
        return cls(tuple(ProtectedPath(t["id"], os.path.normpath(t["path"])) for t in d.get("targets", [])),
                   d.get("mode", "balanced"), int(d.get("max_source_bytes", 1 << 20)),
                   float(d.get("max_seconds", 2.0)), d.get("policy_revision", ""), d.get("home", ""))

    def to_dict(self) -> dict[str, Any]:
        return {"targets": [{"id": t.id, "path": t.path} for t in self.targets], "mode": self.mode,
                "max_source_bytes": self.max_source_bytes, "max_seconds": self.max_seconds,
                "policy_revision": self.policy_revision, "home": self.home}


@dataclass
class Decision:
    verdict: str
    reason: str = ""
    target_id: str | None = None
    codes: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict == DENY

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason, "target_id": self.target_id,
                "codes": self.codes, "incomplete": self.incomplete}


class _Limit(Exception):
    pass


def is_within(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


class ScanCache:
    """In-memory only, keyed by (dev, ino, size, mtime_ns, policy_revision). Deliberately not
    persisted to disk: a cache the sandboxed agent can write would let it forge 'clean' results."""

    def __init__(self, limit: int = 512):
        self.data: dict[tuple, tuple[list[tuple[str, str | None]], list[str]]] = {}
        self.limit = limit
        self.hits = 0

    def get(self, key: tuple):
        v = self.data.get(key)
        if v is not None:
            self.hits += 1
        return v

    def put(self, key: tuple, value) -> None:
        if len(self.data) >= self.limit:
            self.data.pop(next(iter(self.data)))
        self.data[key] = value


class Inspector:
    def __init__(self, policy: InspectPolicy, cache: ScanCache | None = None):
        self.p = policy
        self.cache = cache if cache is not None else ScanCache()
        self.home = policy.home or os.environ.get("HOME", "")
        self._targets = [(t.id, os.path.normpath(t.path)) for t in policy.targets]
        self._tcomps = [(tid, [c for c in tp.split("/") if c]) for tid, tp in self._targets]
        self._reset()

    def _reset(self) -> None:
        self.deadline = 0.0
        self.findings: list[tuple[str, str | None]] = []     # (code, target_id)
        self.incompletes: list[str] = []
        self.files_followed = 0
        self._cur_target: str | None = None

    # ------------------------------------------------------------------------------------------
    # engine callbacks (also handed to PyScanner)
    # ------------------------------------------------------------------------------------------
    def tick(self) -> None:
        if time.monotonic() > self.deadline:
            raise _Limit

    def incomplete(self, code: str) -> None:
        if code not in self.incompletes:
            self.incompletes.append(code)

    def deny(self, code: str, detail: str = "") -> None:
        self.findings.append((code, self._cur_target))

    def elevation(self, word: str) -> bool:
        return os.path.basename(word) in ELEVATION

    def _find_target(self, path: str) -> str | None:
        for tid, tp in self._targets:
            if is_within(path, tp):
                return tid
        return None

    def hit(self, path: str, base: str | None) -> bool:
        tid = self._hit_path(path, base)
        if tid:
            self._cur_target = tid
        return bool(tid)

    def _hit_path(self, path: str, base: str | None) -> str | None:
        if not path or "\x00" in path:
            return None
        if path.startswith("file://"):
            path = path[7:]
        if path.startswith("~"):
            path = self.home + path[1:] if self.home else path
        if not path.startswith("/"):
            if base is None:
                return None
            path = os.path.join(base, path)
        lexical = os.path.normpath(path)
        t = self._find_target(lexical)
        if t:
            return t
        try:
            real = os.path.realpath(lexical)
        except (OSError, ValueError):
            return None
        return self._find_target(real) if real != lexical else None

    def mentions(self, text: str) -> bool:
        """Does free text contain an absolute protected path (normalised, with boundary checks)?"""
        if not text or "/" not in text:
            return False
        norm = re.sub(r"/(?:\./)+", "/", re.sub(r"(?<!:)/{2,}", "/", text.replace("file://", "")))
        for tid, tp in self._targets:
            start = 0
            while True:
                j = norm.find(tp, start)
                if j < 0:
                    break
                end = j + len(tp)
                before_ok = j == 0 or norm[j - 1] in BEFORE_OK
                after_ok = end >= len(norm) or not NAME_CHARS.match(norm[end]) or norm[end] == "/"
                if before_ok and after_ok:
                    self._cur_target = tid
                    return True
                start = j + 1
        return False

    def _glob_hits(self, pattern: str, base: str | None) -> bool:
        """Could this glob pattern select the protected directory (or something inside it)?"""
        if not pattern.startswith("/"):
            if base is None:
                return False
            pattern = os.path.join(base, pattern)
        pcs = [c for c in os.path.normpath(pattern).split("/") if c]
        for tid, tcs in self._tcomps:
            if len(pcs) < len(tcs):
                continue
            ok = True
            for pc, tc in zip(pcs, tcs):
                if pc == "**":
                    break
                if not fnmatch.fnmatchcase(tc, pc):
                    ok = False
                    break
            if ok:
                self._cur_target = tid
                return True
        return False

    def shell(self, text: str, cwd: str | None) -> None:
        self._inspect_shell(text, cwd, 1)

    def follow(self, path: str, depth: int) -> None:
        if self.files_followed >= MAX_FOLLOW_FILES:
            self.incomplete("FOLLOW_LIMIT")
            return
        self.files_followed += 1
        self._scan_file(path, os.path.dirname(path), depth, kind="python")

    # ------------------------------------------------------------------------------------------
    # words / commands
    # ------------------------------------------------------------------------------------------
    def _word_check(self, w: shell.Word, cwd: str | None) -> None:
        text = w.text
        cands = [text]
        if text.startswith("-"):
            if "=" in text:
                cands.append(text.split("=", 1)[1])
            if re.match(r"^-[A-Za-z]", text) and not text.startswith("--"):
                cands.append(text[2:])
        for c in cands:
            if not c:
                continue
            if shell.DYN in c:
                prefix = c.split(shell.DYN, 1)[0]
                if prefix.startswith("/") or prefix.startswith("~"):
                    pp = self.home + prefix[1:] if prefix.startswith("~") else prefix
                    if self._hit_path(pp.rstrip("/") or "/", cwd) and pp.endswith("/"):
                        self.findings.append(("DIRECT_REFERENCE", self._find_target(os.path.normpath(pp))))
                        return
                    if len(pp) >= 2 and any(tp.startswith(pp) and tp != pp.rstrip("/") for _, tp in self._targets):
                        self.incomplete("DYNAMIC_PATH")
                continue
            if w.glob and any(ch in c for ch in "*?["):
                if self._glob_hits(c, cwd):
                    self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                    return
                continue
            if self.mentions(c):
                self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                return
            if c != "-" and not c.startswith("-") and self.hit(c, cwd):
                self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                return

    def _unwrap(self, words: list[shell.Word]) -> list[shell.Word]:
        while words:
            name = os.path.basename(words[0].text)
            if name in ELEVATION:
                self.findings.append(("ELEVATION", None))
                return words[1:]
            if name not in WRAPPERS:
                return words
            takes = WRAPPER_ARG_OPTS.get(name, set())
            i = 1
            while i < len(words):
                t = words[i].text
                if name == "env" and "=" in t and not t.startswith("-"):
                    i += 1
                elif t.startswith("-") and t != "-":
                    i += 2 if t in takes else 1
                elif name in ("timeout", "nice", "ionice", "taskset", "chrt", "watch") and re.fullmatch(r"[0-9.]+[smhd]?", t) and i == 1:
                    i += 1
                else:
                    break
            words = words[i:]
        return words

    def _inspect_shell(self, text: str, cwd: str | None, depth: int, file_contents: dict[str, str] | None = None) -> None:
        if depth > MAX_DEPTH:
            self.incomplete("DEPTH_LIMIT")
            return
        env = {"HOME": self.home} if self.home else {}
        parsed = shell.parse(text, env, cwd)
        for code in parsed.incomplete:
            self.incomplete(code)
        written: dict[str, str] = dict(file_contents or {})
        for cmd in parsed.commands:
            self.tick()
            for w in [*cmd.words, *(w for _, w in cmd.redirs)]:
                for sub in w.subs:
                    self._inspect_shell(sub, cmd.cwd, depth + 1, written)
            for w in cmd.assigns.values():
                for sub in w.subs:
                    self._inspect_shell(sub, cmd.cwd, depth + 1, written)
            idx = shell.command_word_index(cmd.words)
            words = self._unwrap(cmd.words[idx:])
            for op, w in cmd.redirs:
                if not op.startswith("<&") and not op.startswith(">&"):
                    self._word_check(w, cmd.cwd)
            if not words:
                continue
            name = os.path.basename(words[0].text)
            args = words[1:]
            # record content written to files so that a later `python file` in the same command is inspectable
            out_targets = [w for op, w in cmd.redirs if op in (">", ">>", ">|")]
            body = cmd.heredocs[-1].body if cmd.heredocs else None
            if name in ("cat", "tee") and body is not None:
                files = [w for w in (args if name == "tee" else out_targets) if not w.text.startswith("-")]
                for w in files:
                    p = w.text if w.text.startswith("/") else os.path.join(cmd.cwd or "", w.text)
                    written[os.path.normpath(p)] = body
            elif name in ("echo", "printf") and out_targets:
                content = " ".join(a.text for a in args)
                for w in out_targets:
                    p = w.text if w.text.startswith("/") else os.path.join(cmd.cwd or "", w.text)
                    written[os.path.normpath(p)] = content
            # argument checks (skip pure-data commands and commit messages)
            if name not in DATA_ONLY:
                skip_next = False
                for i, a in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                    if name == "git" and a.text in ("-m", "--message", "-F") :
                        skip_next = True
                        continue
                    if name == "git" and a.text.startswith("--message="):
                        continue
                    self._word_check(a, cmd.cwd)
            self._dispatch_interpreter(name, words, args, cmd, depth, written)

    # ------------------------------------------------------------------------------------------
    # interpreters
    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _is_python(name: str) -> bool:
        return re.fullmatch(r"python(\d+(\.\d+)*)?", name) is not None

    def _dispatch_interpreter(self, name: str, words: list[shell.Word], args: list[shell.Word],
                              cmd: shell.Simple, depth: int, written: dict[str, str]) -> None:
        cwd = cmd.cwd
        stdin_body = cmd.heredocs[-1].body if cmd.heredocs else None
        if self._is_python(name):
            kind, script, inline, rest = "python", None, None, []
            i = 0
            opts_with_arg = {"-W", "-X", "-Q", "--check-hash-based-pycs"}
            while i < len(args):
                t = args[i].text
                if t == "-c" and i + 1 < len(args):
                    inline = args[i + 1].text
                    break
                if t == "-m":
                    return
                if t == "-":
                    script = "-"
                    break
                if t.startswith("-"):
                    i += 2 if t in opts_with_arg else 1
                    continue
                script = t
                break
            if inline is not None:
                if args[i + 1].dynamic:
                    self.incomplete("DYNAMIC_INLINE_CODE")
                self._scan_source(inline, "python", cwd, None, depth)
            elif script == "-" or (script is None and stdin_body is not None):
                if stdin_body is not None:
                    self._scan_source(stdin_body, "python", cwd, None, depth)
                else:
                    self.incomplete("STDIN_PROGRAM")
            elif script is not None:
                self._run_script(script, "python", cwd, depth, written, args[i].dynamic if i < len(args) else False)
            return
        if name in SHELLS:
            script, inline = None, None
            i = 0
            while i < len(args):
                t = args[i].text
                if t == "-c" and i + 1 < len(args):
                    inline = args[i + 1].text
                    break
                if t in ("-o", "+o", "-O", "+O"):
                    i += 2
                    continue
                if t.startswith("-") or t.startswith("+"):
                    i += 1
                    continue
                script = t
                break
            if inline is not None:
                if i + 1 < len(args) and args[i + 1].dynamic:
                    self.incomplete("DYNAMIC_INLINE_CODE")
                self._inspect_shell(inline, cwd, depth + 1, written)
            elif script is not None:
                self._run_script(script, "shell", cwd, depth, written, False)
            elif stdin_body is not None:
                self._inspect_shell(stdin_body, cwd, depth + 1, written)
            return
        if name == "eval" and args:
            if not any(a.dynamic for a in args):
                self._inspect_shell(" ".join(a.text for a in args), cwd, depth + 1, written)
            return
        if name in ("source", ".") and args:
            self._run_script(args[0].text, "shell", cwd, depth, written, args[0].dynamic)
            return
        if name in NODE or name in GENERIC_INTERP:
            kind = "node" if name in NODE else "generic"
            inline_flags = {"-e", "-p", "--eval", "--print"} if kind == "node" else {"-e", "-E", "-r"}
            i = 0
            while i < len(args):
                t = args[i].text
                if t in inline_flags and i + 1 < len(args):
                    self._scan_source(args[i + 1].text, kind, cwd, None, depth)
                    return
                if t.startswith("-"):
                    i += 1
                    continue
                self._run_script(t, kind, cwd, depth, written, args[i].dynamic)
                return
            if stdin_body is not None:
                self._scan_source(stdin_body, kind, cwd, None, depth)
            return
        # a script executed directly: ./run.sh  /opt/x/tool.py
        if "/" in words[0].text and not words[0].dynamic:
            p = words[0].text
            full = p if p.startswith("/") else os.path.join(cwd or "", p)
            self._run_script(p, "auto", cwd, depth, written, False)

    def _resolve(self, p: str, cwd: str | None) -> str | None:
        if p.startswith("~"):
            p = self.home + p[1:]
        if p.startswith("/"):
            return os.path.normpath(p)
        return os.path.normpath(os.path.join(cwd, p)) if cwd else None

    def _run_script(self, p: str, kind: str, cwd: str | None, depth: int, written: dict[str, str],
                    dynamic: bool) -> None:
        if dynamic or shell.DYN in p:
            self.incomplete("DYNAMIC_SCRIPT_PATH")
            return
        full = self._resolve(p, cwd)
        if full is None:
            self.incomplete("UNKNOWN_CWD")
            return
        if self._hit_path(full, cwd):
            self.findings.append(("DIRECT_REFERENCE", self._cur_target or self._find_target(full)))
            return
        if full in written:
            self._scan_source(written[full], kind if kind != "auto" else self._guess_kind(full, written[full]),
                              cwd, full, depth)
            return
        self._scan_file(full, cwd, depth, kind)

    @staticmethod
    def _guess_kind(path: str, head: str) -> str:
        first = head.split("\n", 1)[0]
        if path.endswith(".py") or "python" in first:
            return "python"
        if path.endswith((".sh", ".bash")) or re.search(r"\b(ba|z|da|k)?sh\b", first):
            return "shell"
        if path.endswith((".js", ".mjs", ".cjs")) or "node" in first:
            return "node"
        return "generic"

    def _scan_file(self, full: str, cwd: str | None, depth: int, kind: str) -> None:
        try:
            st = os.stat(full)
        except FileNotFoundError:
            self.incomplete("SCRIPT_NOT_FOUND")
            return
        except OSError:
            self.incomplete("SCRIPT_UNREADABLE")
            return
        if not stat.S_ISREG(st.st_mode):
            self.incomplete("SCRIPT_NOT_REGULAR_FILE")
            return
        if st.st_size > self.p.max_source_bytes:
            self.incomplete("SOURCE_TOO_LARGE")
            return
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, self.p.policy_revision, kind)
        cached = self.cache.get(key)
        if cached is not None:
            for code, tid in cached[0]:
                self.findings.append((code, tid))
            for c in cached[1]:
                self.incomplete(c)
            return
        try:
            fd = os.open(full, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                data = os.read(fd, self.p.max_source_bytes + 1)
            finally:
                os.close(fd)
        except OSError:
            self.incomplete("SCRIPT_UNREADABLE")
            return
        if len(data) > self.p.max_source_bytes:
            self.incomplete("SOURCE_TOO_LARGE")
            return
        if b"\x00" in data[:4096]:
            return                       # compiled binary: out of scope, never claimed as inspected
        text = data.decode("utf-8", "replace")
        before_f, before_i = len(self.findings), len(self.incompletes)
        k = kind if kind != "auto" else self._guess_kind(full, text)
        self._scan_source(text, k, cwd, full, depth)
        self.cache.put(key, (self.findings[before_f:], self.incompletes[before_i:]))

    def _scan_source(self, text: str, kind: str, cwd: str | None, script_path: str | None, depth: int) -> None:
        if len(text.encode("utf-8", "ignore")) > self.p.max_source_bytes:
            self.incomplete("SOURCE_TOO_LARGE")
            return
        base = cwd or os.getcwd()
        if self.mentions(text):
            self.findings.append(("SCRIPT_REFERENCE", self._cur_target))
        if kind == "python":
            PyScanner(self, self.home, base, script_path).scan(text, depth)
        elif kind == "shell":
            before = len(self.findings)
            self._inspect_shell(text, cwd, depth + 1)
            for i in range(before, len(self.findings)):
                if self.findings[i][0] == "DIRECT_REFERENCE":
                    self.findings[i] = ("SCRIPT_REFERENCE", self.findings[i][1])
        elif kind in ("node", "generic"):
            self._scan_js_like(text, base, script_path)
        else:
            pass

    # JS / ruby / perl / php: fold adjacent literals and +/. concatenation, join() calls
    _LIT = re.compile(r"""(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\$]|\\.)*)`)""")

    def _scan_js_like(self, text: str, base: str, script_path: str | None) -> None:
        lits = [(m.start(), m.end(), next(g for g in m.groups() if g is not None)) for m in self._LIT.finditer(text)]
        folded: list[str] = []
        i = 0
        while i < len(lits):
            s, e, v = lits[i]
            cur = v
            j = i
            while j + 1 < len(lits):
                gap = text[lits[j][1]:lits[j + 1][0]]
                if re.fullmatch(r"\s*(?:\+|\.|\.\.)?\s*", gap):
                    cur += lits[j + 1][2]
                    j += 1
                else:
                    break
            folded.append(cur)
            i = j + 1
        for m in re.finditer(r"(?:join|resolve|Join|File\.join)\(\s*((?:(?:'[^']*'|\"[^\"]*\")\s*,?\s*)+)\)", text):
            parts = [x[0][1:-1] if x[0] else "" for x in re.findall(r"('[^']*'|\"[^\"]*\")", m.group(1))]
            parts = re.findall(r"""['"]([^'"]*)['"]""", m.group(1))
            folded.append(PyScanner._pjoin(parts))
        for v in folded:
            v = v.replace("\\/", "/")
            if v.startswith("~") and self.home:
                v = self.home + v[1:]
            if self.mentions(v) or (v.startswith("/") and self.hit(v, base)):
                self.findings.append(("SCRIPT_REFERENCE", self._cur_target))
                break
        if re.search(r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(", text):
            self.incomplete("DYNAMIC_CODE")
        if re.search(r"""(?:require\(|from\s+)['"]\.{1,2}/""", text):
            self.incomplete("UNFOLLOWED_IMPORT")
        if re.search(r"\b(?:sudo|pkexec|doas)\b\s", text) and re.search(r"exec|spawn|system|popen", text):
            for v in folded:
                if re.match(r"\s*(sudo|su|pkexec|doas)\b", v):
                    self.findings.append(("ELEVATION", None))
                    break

    # ------------------------------------------------------------------------------------------
    # tool-level entry point
    # ------------------------------------------------------------------------------------------
    def inspect(self, tool_name: str, tool_input: Any, cwd: str) -> Decision:
        self._reset()
        self.deadline = time.monotonic() + self.p.max_seconds
        try:
            self._inspect_tool(tool_name or "", tool_input if isinstance(tool_input, dict) else {"value": tool_input}, cwd)
        except _Limit:
            self.incomplete("TIME_LIMIT")
        except RecursionError:
            self.incomplete("RECURSION_LIMIT")
        return self._decide()

    def _inspect_tool(self, tool: str, ti: dict[str, Any], cwd: str) -> None:
        lname = tool.lower()
        if lname in BASH_TOOLS:
            cmd = next((ti[k] for k in ("command", "cmd", "script") if isinstance(ti.get(k), str)), None)
            workdir = ti.get("workdir") or ti.get("cwd")
            base = os.path.normpath(os.path.join(cwd, workdir)) if isinstance(workdir, str) and workdir else cwd
            if cmd is None:
                self.incomplete("NO_COMMAND_FIELD")
                return
            self._inspect_shell(cmd, base, 1)
            return
        # file tools and everything else: look at path-like fields, then any string at all
        for k, v in ti.items():
            self.tick()
            vals = v if isinstance(v, list) else [v]
            for item in vals:
                if not isinstance(item, str):
                    continue
                if k in PATH_KEYS:
                    if any(ch in item for ch in "*?[") and self._glob_hits(item, cwd):
                        self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                    elif self.hit(item, cwd) or self.mentions(item):
                        self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                elif k == "pattern":
                    base = ti.get("path") if isinstance(ti.get("path"), str) else cwd
                    if item.startswith("/") and self._glob_hits(item, base):
                        self.findings.append(("DIRECT_REFERENCE", self._cur_target))
                elif len(item) <= 200_000 and self.mentions(item):
                    self.findings.append(("DIRECT_REFERENCE", self._cur_target))

    def _decide(self) -> Decision:
        if self.findings:
            codes = []
            for c, _ in self.findings:
                if c not in codes:
                    codes.append(c)
            first = ("ELEVATION" if "ELEVATION" in codes else
                     "DIRECT_REFERENCE" if "DIRECT_REFERENCE" in codes else codes[0])
            tid = next((t for c, t in self.findings if t), None)
            return Decision(DENY, REASONS.get(first, REASONS["DIRECT_REFERENCE"]), tid, codes, list(self.incompletes))
        if self.incompletes:
            if self.p.mode == "strict":
                return Decision(DENY, "Inspection incomplete and strict policy requires refusal ("
                                + ", ".join(self.incompletes) + ")", None, [], list(self.incompletes))
            return Decision(INCOMPLETE, "Inspection incomplete (" + ", ".join(self.incompletes)
                            + "); enforcement deferred to the OS layers", None, [], list(self.incompletes))
        return Decision(ALLOW)
