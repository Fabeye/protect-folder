"""A small, conservative shell lexer/parser: enough to find commands, words, cd, variables,
heredocs and command substitutions. It never executes anything. Anything it cannot model is
reported through `incomplete` codes rather than guessed."""

from __future__ import annotations

from dataclasses import dataclass, field

DYN = "\x00"          # placeholder for an unresolved expansion inside a word
MAX_TEXT = 512 * 1024
GLOB_CHARS = set("*?[")
RESERVED = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "in", "case",
            "esac", "function", "select", "time", "!", "{", "}", "coproc"}
OPS = ("&&", "||", "|&", ";;", "|", ";", "&", "(", ")", "\n")


@dataclass
class Word:
    text: str
    dynamic: bool = False
    glob: bool = False
    subs: list[str] = field(default_factory=list)
    quoted: bool = False


@dataclass
class Heredoc:
    delim: str
    body: str = ""
    quoted: bool = False
    strip_tabs: bool = False


@dataclass
class Simple:
    words: list[Word]
    redirs: list[tuple[str, Word]]
    heredocs: list[Heredoc]
    cwd: str | None
    assigns: dict[str, Word] = field(default_factory=dict)


@dataclass
class Parsed:
    commands: list[Simple]
    incomplete: list[str]


class _Lexer:
    def __init__(self, text: str, env: dict[str, str]):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.env = env
        self.vars: dict[str, Word] = {}
        self.incomplete: list[str] = []
        self.pending_heredocs: list[Heredoc] = []

    # -- helpers -----------------------------------------------------------------------------
    def _balanced(self, open_ch: str, close_ch: str) -> str:
        """Return the body of a balanced (...) / `...` group starting just after the opener."""
        depth = 1
        start = self.i
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c in "'\"":
                q = c
                self.i += 1
                while self.i < self.n and self.s[self.i] != q:
                    self.i += 2 if (q == '"' and self.s[self.i] == "\\") else 1
            elif c == open_ch and open_ch != close_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    body = self.s[start:self.i]
                    self.i += 1
                    return body
            self.i += 1
        self.incomplete.append("UNTERMINATED_SUBSTITUTION")
        return self.s[start:]

    def _fold(self, body: str) -> str | None:
        """Statically fold the trivially deterministic substitutions  $(echo LITERAL...)  /  $(printf %s LITERAL).
        Anything else (pipelines, variables, other commands) stays dynamic: never guessed."""
        if len(body) > 4096 or any(ch in body for ch in "|&;<>()$`\n"):
            return None
        sub = _Lexer(body, self.env)
        sub.vars = dict(self.vars)
        words: list[str] = []
        while sub.i < sub.n:
            if sub.s[sub.i] in " \t":
                sub.i += 1
                continue
            before = sub.i
            wd = sub.read_word()
            if sub.i == before or wd.dynamic or wd.glob or wd.subs or sub.incomplete:
                return None
            words.append(wd.text)
        if not words:
            return None
        if words[0] == "echo":
            rest = words[1:]
            while rest and rest[0] in ("-n", "-e", "-E"):
                rest.pop(0)
            return " ".join(rest)
        if words[0] == "printf" and len(words) == 3 and words[1] in ("%s", "%s\\n"):
            return words[2]
        return None

    def _sub(self, w: Word, body: str) -> None:
        w.subs.append(body)
        folded = self._fold(body)
        if folded is not None:
            w.text += folded
        else:
            w.text += DYN
            w.dynamic = True

    def _expand_var(self, w: Word, in_dq: bool) -> None:
        """At self.i pointing just after '$' for a name/brace form."""
        s = self.s
        if self.i < self.n and s[self.i] == "{":
            self.i += 1
            j = s.find("}", self.i)
            if j < 0:
                self.incomplete.append("UNTERMINATED_BRACE")
                j = self.n
            name = s[self.i:j]
            self.i = min(j + 1, self.n)
            simple = name.isidentifier()
            self._emit_var(w, name if simple else None)
            return
        j = self.i
        while j < self.n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        name = s[self.i:j]
        if name:
            self.i = j
            self._emit_var(w, name)
        elif self.i < self.n and s[self.i] in "@*#?$!-0123456789":
            self.i += 1
            w.text += DYN
            w.dynamic = True
        else:
            w.text += "$"

    def _emit_var(self, w: Word, name: str | None) -> None:
        if name is not None:
            if name in self.vars and not self.vars[name].dynamic:
                w.text += self.vars[name].text
                return
            if name in self.env:
                w.text += self.env[name]
                return
        w.text += DYN
        w.dynamic = True

    # -- word reader -------------------------------------------------------------------------
    def read_word(self) -> Word:
        w = Word("")
        s = self.s
        any_unquoted = False
        while self.i < self.n:
            c = s[self.i]
            if c in " \t\r\n" or (c in "|&;()<>" ):
                break
            if c == "\\":
                if self.i + 1 < self.n:
                    nxt = s[self.i + 1]
                    if nxt != "\n":
                        w.text += nxt
                    self.i += 2
                else:
                    self.i += 1
                any_unquoted = True
                continue
            if c == "'":
                self.i += 1
                j = s.find("'", self.i)
                if j < 0:
                    self.incomplete.append("UNTERMINATED_QUOTE")
                    j = self.n
                w.text += s[self.i:j]
                self.i = min(j + 1, self.n)
                w.quoted = True
                continue
            if c == '"':
                self.i += 1
                while self.i < self.n and s[self.i] != '"':
                    d = s[self.i]
                    if d == "\\" and self.i + 1 < self.n:
                        nx = s[self.i + 1]
                        w.text += nx if nx in '$`"\\' else "\\" + nx
                        self.i += 2
                    elif d == "$" and s.startswith("$(", self.i):
                        self.i += 2
                        self._sub(w, self._balanced("(", ")"))
                    elif d == "$":
                        self.i += 1
                        self._expand_var(w, True)
                    elif d == "`":
                        self.i += 1
                        self._sub(w, self._balanced("`", "`"))
                    else:
                        w.text += d
                        self.i += 1
                if self.i >= self.n:
                    self.incomplete.append("UNTERMINATED_QUOTE")
                self.i += 1
                w.quoted = True
                continue
            if c == "$" and s.startswith("$'", self.i):
                self.i += 2
                j = self.i
                while j < self.n and s[j] != "'":
                    j += 2 if s[j] == "\\" else 1
                w.text += s[self.i:j].encode("utf-8", "surrogateescape").decode("unicode_escape", "ignore") if "\\" in s[self.i:j] else s[self.i:j]
                self.i = min(j + 1, self.n)
                w.quoted = True
                continue
            if c == "$" and s.startswith("$((", self.i):
                self.i += 3
                self._balanced("(", ")")
                w.text += DYN
                w.dynamic = True
                continue
            if c == "$" and s.startswith("$(", self.i):
                self.i += 2
                self._sub(w, self._balanced("(", ")"))
                any_unquoted = True
                continue
            if c == "$":
                self.i += 1
                self._expand_var(w, False)
                any_unquoted = True
                continue
            if c == "`":
                self.i += 1
                self._sub(w, self._balanced("`", "`"))
                continue
            if c == "~" and not w.text and (self.i + 1 >= self.n or s[self.i + 1] in "/ \t\n;|&)"):
                w.text += self.env.get("HOME", DYN)
                if "HOME" not in self.env:
                    w.dynamic = True
                self.i += 1
                continue
            if c in GLOB_CHARS:
                w.glob = True
            w.text += c
            any_unquoted = True
            self.i += 1
        return w

    # -- heredoc bodies ----------------------------------------------------------------------
    def read_heredoc_bodies(self) -> None:
        """Called right after a newline was consumed."""
        for hd in self.pending_heredocs:
            lines = []
            while self.i < self.n:
                j = self.s.find("\n", self.i)
                line = self.s[self.i:] if j < 0 else self.s[self.i:j]
                self.i = self.n if j < 0 else j + 1
                check = line.lstrip("\t") if hd.strip_tabs else line
                if check == hd.delim:
                    break
                lines.append(line)
            hd.body = "\n".join(lines)
        self.pending_heredocs = []


def parse(text: str, env: dict[str, str] | None = None, cwd: str | None = None) -> Parsed:
    if len(text) > MAX_TEXT:
        return Parsed([], ["TEXT_TOO_LARGE"])
    return _assemble(text, dict(env or {}), cwd)


def _assemble(text: str, env: dict[str, str], cwd: str | None) -> Parsed:
    import os
    # Tokenise incrementally, registering Heredoc objects when '<<' DELIM is met so that
    # read_heredoc_bodies can fill them in at the next newline.
    lx2 = _Lexer(text, dict(env))
    commands: list[Simple] = []
    words: list[Word] = []
    redirs: list[tuple[str, Word]] = []
    hds: list[Heredoc] = []
    assigns: dict[str, Word] = {}
    cur_cwd = cwd
    s = lx2.s
    expecting: str | None = None

    def flush() -> None:
        nonlocal words, redirs, hds, assigns, cur_cwd
        if words or hds or redirs or assigns:
            commands.append(Simple(list(words), list(redirs), list(hds), cur_cwd, dict(assigns)))
            if words and words[0].text == "cd" and len(words) >= 2:
                tgt = words[1]
                if tgt.dynamic or tgt.glob or tgt.text in ("-",):
                    cur_cwd = None
                    lx2.incomplete.append("DYNAMIC_CWD")
                elif tgt.text.startswith("/"):
                    cur_cwd = os.path.normpath(tgt.text)
                elif cur_cwd:
                    cur_cwd = os.path.normpath(os.path.join(cur_cwd, tgt.text))
                else:
                    lx2.incomplete.append("DYNAMIC_CWD")
            elif words and words[0].text == "eval" and any(w.dynamic for w in words[1:]):
                lx2.incomplete.append("EVAL")
        words, redirs, hds, assigns = [], [], [], {}

    while lx2.i < lx2.n:
        c = s[lx2.i]
        if c in " \t\r":
            lx2.i += 1
            continue
        if c == "\n":
            lx2.i += 1
            flush()
            expecting = None
            lx2.read_heredoc_bodies()
            continue
        if c == "#":
            j = s.find("\n", lx2.i)
            lx2.i = lx2.n if j < 0 else j
            continue
        if (c == "<" and s.startswith("<(", lx2.i)) or (c == ">" and s.startswith(">(", lx2.i)):
            lx2.incomplete.append("PROCESS_SUBSTITUTION")
            lx2.i += 2
            body = lx2._balanced("(", ")")
            words.append(Word(DYN, True, subs=[body]))
            continue
        if c in "<>":
            op = c
            for cand in ("<<<", "<<-", "<<", ">>", "&>>"):
                if s.startswith(cand, lx2.i):
                    op = cand
                    break
            lx2.i += len(op)
            if lx2.i < lx2.n and s[lx2.i] == "&" and op in (">", "<"):
                op += "&"
                lx2.i += 1
            if lx2.i < lx2.n and s[lx2.i] == "|" and op == ">":
                lx2.i += 1
            expecting = op
            continue
        op = next((o for o in OPS if s.startswith(o, lx2.i)), None)
        if op:
            lx2.i += len(op)
            flush()
            expecting = None
            continue
        before = lx2.i
        w = lx2.read_word()
        if lx2.i == before:
            lx2.i += 1
            continue
        if w.text.isdigit() and not w.quoted and lx2.i < lx2.n and s[lx2.i] in "<>":
            continue                      # fd number of a redirection such as 2>
        if expecting in ("<<", "<<-"):
            hd = Heredoc(delim=w.text, quoted=w.quoted, strip_tabs=(expecting == "<<-"))
            hds.append(hd)
            lx2.pending_heredocs.append(hd)
            expecting = None
            continue
        if expecting:
            redirs.append((expecting, w))
            expecting = None
            continue
        # assignment prefix NAME=value (only before the command word)
        eq = w.text.find("=")
        if not words and eq > 0 and w.text[:eq].replace("_", "a").isalnum() and not w.text[0].isdigit():
            val = Word(w.text[eq + 1:], w.dynamic, w.glob, w.subs, w.quoted)
            assigns[w.text[:eq]] = val
            lx2.vars[w.text[:eq]] = val
            continue
        if not words and w.text in ("export", "local", "declare", "readonly"):
            words.append(w)
            continue
        if words and words[0].text in ("export", "local", "declare", "readonly") and "=" in w.text \
                and w.text.split("=", 1)[0].isidentifier():
            k, v = w.text.split("=", 1)
            val = Word(v, w.dynamic, w.glob, w.subs, w.quoted)
            assigns[k] = val
            lx2.vars[k] = val
        words.append(w)
    flush()
    return Parsed(commands, lx2.incomplete)


def command_word_index(words: list[Word]) -> int:
    """Index of the real command word, skipping reserved words and `!`."""
    i = 0
    while i < len(words) and words[i].text in RESERVED and not words[i].quoted:
        i += 1
    return i
