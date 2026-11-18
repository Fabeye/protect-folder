"""Static, non-executing scan of Python source for references to protected paths.

Folds constant expressions (concatenation, f-strings, os.path.join, pathlib, str.join, %, format)
so that obviously constructed paths such as ``"/mnt/" + "Forbidden" + " folder"`` are recognised.
Dynamic constructs (exec/eval/computed imports) are reported as incomplete, never guessed."""

from __future__ import annotations

import ast
import os
from typing import Any, Callable

PATH_FUNCS = {
    "open", "listdir", "scandir", "walk", "stat", "lstat", "remove", "unlink", "rmdir", "rename",
    "replace", "copy", "copy2", "copyfile", "copytree", "move", "rmtree", "glob", "iglob", "exists",
    "isfile", "isdir", "islink", "getsize", "read_text", "read_bytes", "write_text", "write_bytes",
    "Path", "PurePath", "PosixPath", "PurePosixPath", "chdir", "mkdir", "makedirs", "symlink", "link",
    "readlink", "realpath", "abspath", "iterdir", "rglob", "samefile", "access", "chmod", "chown",
    "truncate", "utime", "fspath", "getmtime", "getatime", "getctime", "expanduser", "touch",
}
SHELL_FUNCS = {"system", "popen", "run", "call", "check_call", "check_output", "Popen",
               "getoutput", "getstatusoutput", "spawnv", "spawnvp", "execv", "execvp", "execl", "execlp"}
DYNAMIC_FUNCS = {"exec", "eval", "compile", "__import__"}
MAX_NODES = 400_000


class Unfoldable(Exception):
    pass


class PyScanner:
    """`hooks` supplies engine callbacks:
       hit(path_or_text, base) -> bool   path resolves inside a target
       mentions(text) -> bool            text contains an absolute target path
       elevation(argv_first) -> bool     first command word is sudo/su/...
       shell(text, cwd)                  inspect a shell command string recursively
       tick()                            deadline check
       incomplete(code)                  record an incompleteness reason
       deny(code, detail)                record a protected-path finding
       follow(path)                      scan a local imported module"""

    def __init__(self, hooks: Any, home: str, cwd: str, script_path: str | None):
        self.h = hooks
        self.home = home
        self.cwd = cwd
        self.script = script_path
        self.script_dir = os.path.dirname(script_path) if script_path else cwd
        self.env: dict[str, str] = {}
        self.chdirs: list[str] = []

    # ------------------------------------------------------------------------------------------
    def fold(self, n: ast.AST) -> str | None:
        try:
            return self._fold(n, 0)
        except (Unfoldable, RecursionError):
            return None

    def _fold(self, n: ast.AST, depth: int) -> str:
        if depth > 40:
            raise Unfoldable
        if isinstance(n, ast.Constant):
            if isinstance(n.value, str):
                return n.value
            if isinstance(n.value, bytes):
                return n.value.decode("utf-8", "replace")
            raise Unfoldable
        if isinstance(n, ast.Name):
            if n.id == "__file__" and self.script:
                return self.script
            if n.id in self.env:
                return self.env[n.id]
            raise Unfoldable
        if isinstance(n, ast.JoinedStr):
            out = []
            for v in n.values:
                if isinstance(v, ast.Constant):
                    out.append(str(v.value))
                elif isinstance(v, ast.FormattedValue) and v.conversion in (-1, 115) and v.format_spec is None:
                    out.append(self._fold(v.value, depth + 1))
                else:
                    raise Unfoldable
            return "".join(out)
        if isinstance(n, ast.BinOp):
            if isinstance(n.op, ast.Add):
                return self._fold(n.left, depth + 1) + self._fold(n.right, depth + 1)
            if isinstance(n.op, ast.Div):          # pathlib: Path("/a") / "b"
                left = self._fold(n.left, depth + 1)
                right = self._fold(n.right, depth + 1)
                return right if right.startswith("/") else left.rstrip("/") + "/" + right
            if isinstance(n.op, ast.Mod):
                fmt = self._fold(n.left, depth + 1)
                if isinstance(n.right, ast.Tuple):
                    args = tuple(self._fold(e, depth + 1) for e in n.right.elts)
                else:
                    args = (self._fold(n.right, depth + 1),)
                try:
                    return fmt % args
                except (TypeError, ValueError):
                    raise Unfoldable
        if isinstance(n, ast.Attribute):
            if n.attr in ("parent",):
                return os.path.dirname(self._fold(n.value, depth + 1).rstrip("/")) or "/"
            if n.attr == "sep":
                return "/"
            if n.attr in ("name",):
                return os.path.basename(self._fold(n.value, depth + 1))
            raise Unfoldable
        if isinstance(n, ast.Subscript):
            # os.environ["HOME"]
            if self._is_environ(n.value) and isinstance(n.slice, ast.Constant) and n.slice.value == "HOME":
                return self.home
            raise Unfoldable
        if isinstance(n, ast.Call):
            return self._fold_call(n, depth)
        raise Unfoldable

    @staticmethod
    def _is_environ(n: ast.AST) -> bool:
        return (isinstance(n, ast.Attribute) and n.attr == "environ") or (isinstance(n, ast.Name) and n.id == "environ")

    def _fold_seq(self, n: ast.AST, depth: int) -> list[str]:
        if isinstance(n, (ast.List, ast.Tuple)):
            return [self._fold(e, depth + 1) for e in n.elts]
        raise Unfoldable

    def _fold_call(self, n: ast.Call, depth: int) -> str:
        f = n.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        args = n.args
        if name in ("join", "joinpath") and isinstance(f, ast.Attribute):
            if name == "join" and isinstance(f.value, ast.Constant) and isinstance(f.value.value, str):
                return f.value.value.join(self._fold_seq(args[0], depth)) if len(args) == 1 else self._raise()
            if name == "join" and isinstance(f.value, (ast.Attribute, ast.Name)) and self._looks_like_path_mod(f.value):
                parts = [self._fold(a, depth + 1) for a in args]
                return self._pjoin(parts)
            if name == "joinpath":
                return self._pjoin([self._fold(f.value, depth + 1)] + [self._fold(a, depth + 1) for a in args])
        if name in ("Path", "PurePath", "PosixPath", "PurePosixPath"):
            return self._pjoin([self._fold(a, depth + 1) for a in args]) if args else self.cwd
        if name in ("expanduser",):
            s = self._fold(args[0], depth + 1) if args else (self._fold(f.value, depth + 1) if isinstance(f, ast.Attribute) else "")
            return self.home + s[1:] if s.startswith("~") else s
        if name == "home":
            return self.home
        if name in ("getcwd", "cwd"):
            return self.cwd
        if name in ("abspath", "normpath", "realpath", "resolve", "absolute"):
            s = self._fold(args[0], depth + 1) if args else self._fold(f.value, depth + 1)
            if not s.startswith("/"):
                s = os.path.join(self.cwd, s)
            return os.path.normpath(s)
        if name == "dirname":
            return os.path.dirname(self._fold(args[0], depth + 1)) or "/"
        if name == "basename":
            return os.path.basename(self._fold(args[0], depth + 1))
        if name in ("str", "fspath", "as_posix", "decode") :
            if args:
                return self._fold(args[0], depth + 1)
            if isinstance(f, ast.Attribute):
                return self._fold(f.value, depth + 1)
        if name in ("getenv",) and args and isinstance(args[0], ast.Constant) and args[0].value == "HOME":
            return self.home
        if name == "get" and isinstance(f, ast.Attribute) and self._is_environ(f.value) \
                and args and isinstance(args[0], ast.Constant) and args[0].value == "HOME":
            return self.home
        if name == "format" and isinstance(f, ast.Attribute):
            fmt = self._fold(f.value, depth + 1)
            pos = [self._fold(a, depth + 1) for a in args]
            kw = {k.arg: self._fold(k.value, depth + 1) for k in n.keywords if k.arg}
            try:
                return fmt.format(*pos, **kw)
            except (IndexError, KeyError, ValueError):
                raise Unfoldable
        if name in ("lower", "upper", "strip", "rstrip", "lstrip") and isinstance(f, ast.Attribute):
            v = self._fold(f.value, depth + 1)
            return getattr(v, name)(*[self._fold(a, depth + 1) for a in args])
        if name == "chr" and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
            return chr(args[0].value)
        raise Unfoldable

    @staticmethod
    def _raise() -> str:
        raise Unfoldable

    @staticmethod
    def _looks_like_path_mod(n: ast.AST) -> bool:
        return isinstance(n, ast.Attribute) and n.attr == "path" or isinstance(n, ast.Name) and n.id in ("path", "posixpath")

    @staticmethod
    def _pjoin(parts: list[str]) -> str:
        out = ""
        for p in parts:
            out = p if (p.startswith("/") or not out) else out.rstrip("/") + "/" + p
        return out

    # ------------------------------------------------------------------------------------------
    def scan(self, source: str, depth: int = 0) -> None:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self.h.incomplete("PYTHON_PARSE_FAILED")
            self._scan_raw(source)
            return
        nodes = list(ast.walk(tree))
        if len(nodes) > MAX_NODES:
            self.h.incomplete("SOURCE_TOO_COMPLEX")
            return
        # two passes of constant propagation: name = <foldable expr>
        for _ in range(2):
            for n in nodes:
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    v = self.fold(n.value)
                    if v is not None:
                        self.env[n.targets[0].id] = v
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and isinstance(n.op, ast.Add):
                    cur, add = self.env.get(n.target.id), self.fold(n.value)
                    if cur is not None and add is not None:
                        self.env[n.target.id] = cur + add
        self.h.tick()
        seen_calls: set[int] = set()
        for n in nodes:
            self.h.tick()
            if isinstance(n, ast.Call):
                self._visit_call(n)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                self._visit_import(n, depth)
        # Every foldable string expression (not only literals) that looks like an absolute path.
        for n in nodes:
            if isinstance(n, (ast.Constant, ast.BinOp, ast.JoinedStr, ast.Call)):
                v = self.fold(n)
                if v and (v.startswith("/") or v.startswith("~") or "/" in v):
                    self._check_value(v, absolute_only=True)

    def _scan_raw(self, source: str) -> None:
        if self.h.mentions(source):
            self.h.deny("SCRIPT_REFERENCE", "source mentions a protected directory")

    def _check_value(self, v: str, *, absolute_only: bool) -> None:
        if v.startswith("~"):
            v = self.home + v[1:]
        if v.startswith("/") or not absolute_only:
            for base in {self.cwd, self.script_dir, *self.chdirs}:
                if self.h.hit(v, base):
                    self.h.deny("SCRIPT_REFERENCE", "script constructs a protected path")
                    return
        if self.h.mentions(v):
            self.h.deny("SCRIPT_REFERENCE", "script mentions a protected path")

    def _visit_call(self, n: ast.Call) -> None:
        f = n.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        if name in DYNAMIC_FUNCS or (name == "import_module" and not (n.args and isinstance(n.args[0], ast.Constant))):
            if name in ("exec", "eval", "compile"):
                # exec("literal") is still analysable
                src = self.fold(n.args[0]) if n.args else None
                if src is not None and name != "compile":
                    PyScanner(self.h, self.home, self.cwd, self.script).scan(src, 1)
                    return
            self.h.incomplete("DYNAMIC_CODE")
            return
        if name == "chdir" and n.args:
            v = self.fold(n.args[0])
            if v:
                self.chdirs.append(os.path.normpath(v if v.startswith("/") else os.path.join(self.cwd, v)))
        if name in PATH_FUNCS:
            vals = [self.fold(a) for a in n.args] + [self.fold(k.value) for k in n.keywords]
            if isinstance(f, ast.Attribute) and name in ("read_text", "read_bytes", "iterdir", "rglob", "write_text", "write_bytes", "touch", "exists"):
                vals.append(self.fold(f.value))
            for v in vals:
                if v:
                    self._check_value(v, absolute_only=False)
        if name in SHELL_FUNCS and n.args:
            a0 = n.args[0]
            argv = None
            cmd = self.fold(a0)
            if cmd is None:
                try:
                    argv = self._fold_seq(a0, 0)
                except Unfoldable:
                    argv = None
            if argv:
                if self.h.elevation(argv[0]):
                    self.h.deny("ELEVATION", "privilege escalation command")
                self.h.shell(" ".join(_shq(x) for x in argv), self.cwd)
            elif cmd is not None:
                self.h.shell(cmd, self.cwd)

    def _visit_import(self, n: ast.AST, depth: int) -> None:
        names: list[tuple[str, int]] = []
        if isinstance(n, ast.Import):
            names = [(a.name, 0) for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            if n.module:
                # `from pkg import sub` may name a submodule as well as the package itself
                names = [(n.module, n.level)] + [(f"{n.module}.{a.name}", n.level) for a in n.names if a.name != "*"]
            else:
                names = [(a.name, n.level) for a in n.names]
        for mod, level in names:
            path = self._find_local(mod, level)
            if path:
                if depth >= 2:
                    self.h.incomplete("IMPORT_DEPTH_LIMIT")
                else:
                    self.h.follow(path, depth + 1)

    def _find_local(self, mod: str, level: int) -> str | None:
        parts = mod.split(".")
        bases = [self.script_dir, self.cwd]
        if level:
            bases = [self.script_dir]
            for _ in range(level - 1):
                bases = [os.path.dirname(bases[0])]
        for b in bases:
            cand = os.path.join(b, *parts)
            for p in (cand + ".py", os.path.join(cand, "__init__.py")):
                if os.path.isfile(p):
                    return p
        return None


def _shq(s: str) -> str:
    import shlex
    return shlex.quote(s)
