import os
import time

import pytest

from protect_folder.inspect.engine import (ALLOW, DENY, INCOMPLETE, Inspector, InspectPolicy,
                                           ProtectedPath, ScanCache)


@pytest.fixture
def world(tmp_path):
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    tgt = tmp_path / "disk" / "Forbidden folder"
    tgt.mkdir(parents=True)
    (tgt / "secret.txt").write_text("S")
    w = type("W", (), {})()
    w.home, w.proj, w.tgt, w.tmp = home, proj, tgt, tmp_path
    w.sentinel = tmp_path / "EXECUTED"

    def make(mode="balanced", **kw):
        pol = InspectPolicy((ProtectedPath("tid1", str(tgt)),), mode, home=str(home), policy_revision="r1", **kw)
        return Inspector(pol)
    w.make = make
    w.ins = make()

    def bash(cmd, cwd=None, ins=None):
        return (ins or w.ins).inspect("Bash", {"command": cmd}, str(cwd or proj))
    w.bash = bash

    def script(name, body, cwd=None):
        p = (cwd or proj) / name
        p.write_text(body)
        return p
    w.script = script
    return w


def verdict(d):
    return d.verdict


# ---- direct calls ------------------------------------------------------------------------------
@pytest.mark.parametrize("tmpl", [
    "cat '{t}/secret.txt'", 'cat "{t}/secret.txt"', "ls {tq}", "find '{t}' -name '*.txt'", "head -n1 {tq}/secret.txt",
    "grep -r x '{t}'", "cp '{t}/secret.txt' /tmp/x", "tar czf /tmp/a.tgz -C '{t}' .", "rsync -a '{t}/' /tmp/o/",
    "cat < '{t}/secret.txt'", "echo hi > '{t}/new.txt'", "tee '{t}/x' < /dev/null", "ls -la -- '{t}'",
    "wc -l --files0-from='{t}/list'", "cat 'file:///{tr}/secret.txt'", "ls '{t}/'", "ls '{t}/../Forbidden folder'",
    "ls '{t}/./sub/..'", "cat '{t}//secret.txt'", "du -sh '{t}'", "stat '{t}'", "cd '{t}' && ls",
    "cd '{t}'; cat secret.txt",
])
def test_direct_commands_blocked(world, tmpl):
    t = str(world.tgt)
    d = world.bash(tmpl.format(t=t, tq=repr(t).replace("'", '"'), tr=t.lstrip("/")))
    assert d.verdict == DENY and d.target_id == "tid1", tmpl
    assert "Protected directory" in d.reason and "secret" not in d.reason.lower().replace("secret.txt", "")


def test_relative_paths_resolve_against_cwd(world):
    d = world.bash("cat secret.txt", cwd=world.tgt)
    assert d.verdict == DENY
    d = world.bash("cat 'Forbidden folder/secret.txt'", cwd=world.tgt.parent)
    assert d.verdict == DENY
    d = world.bash("cat ../../disk/'Forbidden folder'/secret.txt")
    assert d.verdict == DENY


def test_tilde_and_home_expansion(world):
    sec = world.home / "vault"
    sec.mkdir()
    ins = world.make()
    ins.p.targets = (ProtectedPath("v", str(sec)),)
    ins.__init__(ins.p)
    assert ins.inspect("Bash", {"command": "cat ~/vault/k"}, str(world.proj)).verdict == DENY
    assert ins.inspect("Bash", {"command": "cat $HOME/vault/k"}, str(world.proj)).verdict == DENY
    assert ins.inspect("Bash", {"command": "cat ~/other/k"}, str(world.proj)).verdict == ALLOW


def test_symlink_alias_resolved(world):
    os.symlink(world.tgt, world.proj / "alias")
    assert world.bash("cat alias/secret.txt").verdict == DENY
    assert world.bash("ls alias").verdict == DENY


def test_parent_and_unrelated_paths_are_allowed(world):
    for cmd in ["ls " + str(world.tgt.parent), "find " + str(world.tgt.parent) + " -maxdepth 1",
                "cat " + str(world.tgt) + "-sibling/x", "ls " + str(world.tgt) + ".bak", "git status", "ls -la",
                "python3 -m pytest -q", "npm test", "make -j4", "cat README.md", "pip install requests",
                "git commit -m 'fix the Forbidden folder bug'", "echo " + str(world.tgt), "printf '%s' " + str(world.tgt)]:
        assert world.bash(cmd).verdict == ALLOW, cmd


# ---- privilege escalation -----------------------------------------------------------------------
@pytest.mark.parametrize("cmd", ["sudo ls", "su -", "pkexec id", "doas ls", "env X=1 sudo ls", "command sudo ls",
                                 "timeout 5 sudo ls", "nohup sudo ls &", "ls && sudo rm x", "ls | sudo tee f",
                                 "xargs -n1 sudo rm", "bash -c 'sudo ls'", "sh -c \"echo a; pkexec bash\"",
                                 "exec sudo -i", "time sudo ls", "echo $(sudo cat /etc/shadow)", "sudo -u root id",
                                 "FOO=1 sudo ls"])
def test_elevation_blocked(world, cmd):
    d = world.bash(cmd)
    assert d.verdict == DENY and "ELEVATION" in d.codes and "Privilege escalation" in d.reason, cmd


@pytest.mark.parametrize("cmd", ["echo sudo", "grep sudo README.md", "git commit -m 'no sudo needed'",
                                 "man sudo", "pip install sudo-tools", "ls sudoers.d", "echo 'su -'"])
def test_textual_mentions_of_elevation_are_not_invocations(world, cmd):
    assert world.bash(cmd).verdict == ALLOW, cmd


# ---- interpreters, source inspected before execution, never executed -----------------------------
EVIL_PY = "import os\nopen({s!r}, 'w').write('x')\nprint(open({t!r} + '/secret.txt').read())\n"


def test_python_script_with_absolute_reference_is_blocked_and_never_run(world):
    world.script("evil.py", EVIL_PY.format(s=str(world.sentinel), t=str(world.tgt)))
    for cmd in ["python3 evil.py", "python evil.py", "python3 ./evil.py", "python3.10 -u evil.py arg",
                "python3 -B -W ignore evil.py", f"python3 {world.proj}/evil.py", "cd .. && python3 proj/evil.py",
                "python3 evil.py | tee out", "timeout 5 python3 evil.py"]:
        d = world.bash(cmd)
        assert d.verdict == DENY and "SCRIPT_REFERENCE" in d.codes, cmd
    assert not world.sentinel.exists()                  # inspection NEVER executes the inspected source


def test_safe_scripts_still_run(world):
    world.script("ok.py", "import os, json\nprint(json.dumps(os.listdir('.')))\nopen('out.txt','w').write('x')\n")
    world.script("ok.sh", "#!/bin/sh\necho hello\nls -la\ngit status\n")
    world.script("ok.js", "const fs=require('fs'); console.log(fs.readdirSync('.'));\n")
    for cmd in ["python3 ok.py", "bash ok.sh", "sh ok.sh", "node ok.js", "source ok.sh", ". ./ok.sh"]:
        assert world.bash(cmd).verdict == ALLOW, cmd


def test_shell_script_reference(world):
    world.script("bad.sh", f"#!/bin/bash\nset -e\ncat '{world.tgt}/secret.txt'\n")
    world.script("bad2.sh", f"D='{world.tgt}'\ncat \"$D/secret.txt\"\n")
    for cmd in ["bash bad.sh", "sh bad.sh", "bash ./bad2.sh", "source bad.sh", ". bad2.sh"]:
        d = world.bash(cmd)
        assert d.verdict == DENY, cmd
    p = world.script("exec.sh", f"#!/bin/sh\nls '{world.tgt}'\n")
    os.chmod(p, 0o755)
    assert world.bash("./exec.sh").verdict == DENY                       # executed directly
    assert world.bash(f"{p}").verdict == DENY


def test_node_and_other_interpreters(world):
    t = str(world.tgt)
    world.script("bad.js", f"const fs=require('fs'); fs.readFileSync('{t}/secret.txt');\n")
    world.script("split.js", "const fs=require('fs'); fs.readFileSync('" + str(world.tgt.parent) + "/' + 'Forbidden' + ' folder' + '/secret.txt');\n")
    world.script("join.js", "const path=require('path'); path.join('" + str(world.tgt.parent) + "', 'Forbidden folder', 'secret.txt');\n")
    world.script("bad.rb", f"File.read('{t}/secret.txt')\n")
    world.script("bad.pl", f"open(F, '{t}/secret.txt');\n")
    for cmd in ["node bad.js", "node split.js", "node join.js", "ruby bad.rb", "perl bad.pl"]:
        assert world.bash(cmd).verdict == DENY, cmd


def test_inline_code(world):
    t = str(world.tgt)
    for cmd in [f"python3 -c \"print(open('{t}/secret.txt').read())\"", f"python -c 'import os; os.listdir(\"{t}\")'",
                f"bash -c 'cat \"{t}/secret.txt\"'", f"sh -c \"ls '{t}'\"", f"node -e \"require('fs').readdirSync('{t}')\"",
                f"perl -e 'open(F,\"{t}/secret.txt\")'", f"ruby -e 'File.read(\"{t}/secret.txt\")'"]:
        assert world.bash(cmd).verdict == DENY, cmd
    assert world.bash("python3 -c 'print(1+1)'").verdict == ALLOW
    assert world.bash("bash -c 'echo hi'").verdict == ALLOW


def test_heredocs(world):
    t = str(world.tgt)
    bad = f"python3 - <<'EOF'\nimport os\nprint(os.listdir('{t}'))\nEOF\n"
    assert world.bash(bad).verdict == DENY
    assert world.bash("python3 - <<EOF\nprint('hi')\nEOF\n").verdict == ALLOW
    assert world.bash(f"bash <<'EOF'\ncat '{t}/secret.txt'\nEOF").verdict == DENY
    assert world.bash("bash <<'EOF'\necho fine\nEOF").verdict == ALLOW
    # data heredoc that is only written, not executed, is not code
    assert world.bash(f"cat > notes.txt <<'EOF'\nsee {t}\nEOF").verdict == ALLOW


def test_script_created_and_run_in_the_same_command(world):
    t = str(world.tgt)
    cmd = f"cat > gen.py <<'EOF'\nprint(open('{t}/secret.txt').read())\nEOF\npython3 gen.py"
    assert world.bash(cmd).verdict == DENY
    cmd = f"echo \"open('{t}/secret.txt')\" > gen2.py && python3 gen2.py"
    assert world.bash(cmd).verdict == DENY
    cmd = "cat > ok.py <<'EOF'\nprint(2)\nEOF\npython3 ok.py"
    assert world.bash(cmd).verdict == ALLOW


# ---- obfuscation the spec asks us to catch --------------------------------------------------------
@pytest.mark.parametrize("src", [
    "open('{p}/' + 'Forbidden' + ' folder' + '/secret.txt')",
    "d = '{p}'\nn = 'Forbidden'\nopen(d + '/' + n + ' folder/secret.txt')",
    "import os\nopen(os.path.join('{p}', 'Forbidden folder', 'secret.txt'))",
    "from pathlib import Path\nPath('{p}') / 'Forbidden folder' / 'secret.txt'\n",
    "from pathlib import Path\nPath('{p}', 'Forbidden folder').read_text()",
    "open(f'{{\"{p}\"}}/Forbidden folder/secret.txt')" ,
    "base = '{p}'\nopen(f'{{base}}/Forbidden folder/s')",
    "open('%s/%s/secret.txt' % ('{p}', 'Forbidden folder'))",
    "open('{{}}/{{}}/secret.txt'.format('{p}', 'Forbidden folder'))",
    "import os\nos.listdir('/'.join(['{pp}', 'disk', 'Forbidden folder']))",
    "import os\nos.chdir('{p}')\nopen('Forbidden folder/secret.txt')",
    "import os\nos.listdir(os.path.normpath('{p}/x/../Forbidden folder'))",
    "p = '{p}/Forbidden folder'\nq = p\nimport shutil\nshutil.copytree(q, '/tmp/zzz')",
    "import subprocess\nsubprocess.run(['cat', '{p}/Forbidden folder/secret.txt'])",
    "import subprocess\nsubprocess.run('cat \"{p}/Forbidden folder/secret.txt\"', shell=True)",
    "import os\nos.system('ls ' + '{p}' + '/Forbidden folder')",
])
def test_python_obfuscation_variants_blocked(world, src):
    p = str(world.tgt.parent)
    body = src.replace("{p}", p).replace("{pp}", str(world.tmp)).replace("{{", "{").replace("}}", "}")
    world.script("v.py", body + "\n")
    d = world.bash("python3 v.py")
    assert d.verdict == DENY, body


def test_relative_path_in_python_resolved_against_script_cwd(world):
    world.script("rel.py", "open('../../disk/Forbidden folder/secret.txt')\n")
    assert world.bash("python3 rel.py").verdict == DENY
    world.script("rel2.py", "open('secret.txt')\n", cwd=world.tgt.parent)   # cwd is not the target: fine
    assert world.bash("python3 rel2.py", cwd=world.tgt.parent).verdict == ALLOW


def test_shell_variable_and_quoting_tricks(world):
    t = str(world.tgt)
    parent = str(world.tgt.parent)
    for cmd in [f"A='Forbidden'; B='folder'; cat '{parent}'/\"$A $B\"/secret.txt",
                f"cat '{parent}/Forb'\"idden fo\"lder/secret.txt", f"cat {parent}/Forbidden\\ folder/secret.txt",
                f"X={parent}; cat \"$X/Forbidden folder/s\"", f"export X='{t}'; ls \"$X\"", f"ls {parent}/Forb*",
                f"ls {parent}/?orbidden*", f"cat {parent}/*/secret.txt", f"cd {parent} && cat Forbidden*/x",
                f"cat $'{t}/secret.txt'"]:
        assert world.bash(cmd).verdict == DENY, cmd


def test_glob_that_cannot_reach_target_is_allowed(world):
    assert world.bash(f"ls {world.tgt.parent}/Other*").verdict == ALLOW
    assert world.bash("ls *.py").verdict == ALLOW


# ---- incomplete inspection ------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", ["eval \"$CMD\"", "cat /mnt/$X" , "bash <(curl -s x)", "cd \"$D\" && cat file"])
def test_unsupported_shell_constructs_are_reported_incomplete(world, cmd):
    ins = world.make()
    # make the dynamic prefix plausible: use a target under /mnt for the DYNAMIC_PATH case
    ins.p.targets = (ProtectedPath("tid1", "/mnt/secretdisk/x"),)
    ins.__init__(ins.p)
    d = ins.inspect("Bash", {"command": cmd}, str(world.proj))
    assert d.verdict == INCOMPLETE and d.incomplete, cmd


@pytest.mark.parametrize("src,code", [
    ("exec(input())", "DYNAMIC_CODE"), ("eval(some_var)", "DYNAMIC_CODE"),
    ("m = __import__(name)", "DYNAMIC_CODE"), ("import importlib\nimportlib.import_module(x)", "DYNAMIC_CODE"),
    ("def broken(:\n", "PYTHON_PARSE_FAILED"), ("print 'py2 syntax'\n", "PYTHON_PARSE_FAILED"),
])
def test_python_dynamic_or_unparseable_is_incomplete(world, src, code):
    world.script("dyn.py", src + "\n")
    d = world.bash("python3 dyn.py")
    assert d.verdict == INCOMPLETE and code in d.incomplete, d


def test_strict_mode_refuses_what_balanced_defers(world):
    world.script("dyn.py", "exec(input())\n")
    assert world.bash("python3 dyn.py").verdict == INCOMPLETE
    strict = world.make("strict")
    d = world.bash("python3 dyn.py", ins=strict)
    assert d.verdict == DENY and "strict" in d.reason.lower()
    assert world.bash("python3 -c 'print(1)'", ins=strict).verdict == ALLOW


def test_local_imports_are_followed(world):
    world.script("helper.py", f"def leak():\n    return open('{world.tgt}/secret.txt').read()\n")
    world.script("main.py", "import helper\nhelper.leak()\n")
    assert world.bash("python3 main.py").verdict == DENY
    (world.proj / "pkg").mkdir()
    (world.proj / "pkg" / "__init__.py").write_text("")
    (world.proj / "pkg" / "deep.py").write_text(f"X = open('{world.tgt}/secret.txt')\n")
    world.script("main2.py", "from pkg import deep\nimport os, sys, json\n")
    assert world.bash("python3 main2.py").verdict == DENY
    world.script("main3.py", "import os, sys, json, collections\n")
    assert world.bash("python3 main3.py").verdict == ALLOW


def test_unfollowed_js_import_is_incomplete(world):
    world.script("a.js", "const b = require('./b');\nb.go();\n")
    d = world.bash("node a.js")
    assert d.verdict == INCOMPLETE and "UNFOLLOWED_IMPORT" in d.incomplete


def test_missing_oversized_and_special_scripts(world):
    assert world.bash("python3 nonexistent.py").verdict == INCOMPLETE
    big = world.script("big.py", "x = 1\n" * 400_000)
    ins = world.make(max_source_bytes=1024)
    d = world.bash("python3 big.py", ins=ins)
    assert d.verdict == INCOMPLETE and "SOURCE_TOO_LARGE" in d.incomplete
    assert world.bash("python3 big.py", ins=world.make("strict", max_source_bytes=1024)).verdict == DENY
    os.mkfifo(world.proj / "pipe.py")
    t0 = time.monotonic()
    d = world.bash("python3 pipe.py")
    assert time.monotonic() - t0 < 2 and d.verdict == INCOMPLETE          # must not hang on a FIFO
    d = world.bash("python3 /dev/stdin")
    assert d.verdict in (INCOMPLETE, ALLOW)


def test_binary_is_not_claimed_inspected(world):
    p = world.proj / "a.out"
    p.write_bytes(b"\x7fELF\x00\x00" + b"\x00" * 100)
    os.chmod(p, 0o755)
    assert world.bash("./a.out").verdict == ALLOW        # compiled code is out of scope (OS layers apply)


# ---- non-bash tools --------------------------------------------------------------------------------
def test_file_tools(world):
    t = str(world.tgt)
    I = world.ins
    for tool, ti in [("Read", {"file_path": t + "/secret.txt"}), ("Edit", {"file_path": t + "/x", "old_string": "a"}),
                     ("Write", {"file_path": t + "/new", "content": "x"}), ("MultiEdit", {"file_path": t + "/x"}),
                     ("NotebookEdit", {"notebook_path": t + "/n.ipynb"}), ("Glob", {"pattern": t + "/**/*"}),
                     ("Grep", {"pattern": "x", "path": t}), ("read", {"filePath": t + "/secret.txt"}),
                     ("list", {"path": t}), ("glob", {"pattern": t + "/*.txt"}), ("write", {"filePath": t + "/q"}),
                     ("edit", {"filePath": "Forbidden folder/secret.txt"})]:
        cwd = str(world.tgt.parent) if "Forbidden folder/" in str(ti) and not str(ti).startswith("{'filePath': '/") else str(world.proj)
        assert I.inspect(tool, ti, cwd).verdict == DENY, (tool, ti)
    for tool, ti in [("Read", {"file_path": str(world.proj / "README.md")}), ("Grep", {"pattern": "x", "path": str(world.tgt.parent)}),
                     ("Glob", {"pattern": "**/*.py"}), ("Write", {"file_path": str(world.proj / "n.py"), "content": "x"}),
                     ("WebFetch", {"url": "https://example.com", "prompt": "hi"})]:
        assert I.inspect(tool, ti, str(world.proj)).verdict == ALLOW, (tool, ti)


def test_unknown_tool_with_path_in_any_string_argument(world):
    d = world.ins.inspect("mcp__fs__read_text_file", {"anything": {"x": 1}, "target": str(world.tgt) + "/a"}, str(world.proj))
    assert d.verdict == DENY
    d = world.ins.inspect("mcp__x__tool", {"query": "weather in Paris"}, str(world.proj))
    assert d.verdict == ALLOW


def test_patch_text_mentioning_target_is_blocked(world):
    patch = f"*** Begin Patch\n*** Update File: {world.tgt}/secret.txt\n@@\n-a\n+b\n*** End Patch"
    assert world.ins.inspect("apply_patch", {"patchText": patch}, str(world.proj)).verdict == DENY


def test_bash_workdir_argument(world):
    d = world.ins.inspect("bash", {"command": "cat secret.txt", "workdir": str(world.tgt)}, str(world.proj))
    assert d.verdict == DENY


# ---- names with spaces / unicode / glob characters -------------------------------------------------
@pytest.mark.parametrize("name", ["Ünï data", "[WIP] data*", "a b  c", "semi;colon", "dollar$name", "quote'name", "日本語 フォルダ"])
def test_awkward_target_names(world, name):
    t = world.tmp / "weird" / name
    t.mkdir(parents=True)
    ins = Inspector(InspectPolicy((ProtectedPath("w", str(t)),), home=str(world.home)))
    import shlex
    assert ins.inspect("Bash", {"command": f"cat {shlex.quote(str(t))}/f"}, str(world.proj)).verdict == DENY
    assert ins.inspect("Read", {"file_path": str(t) + "/f"}, str(world.proj)).verdict == DENY
    world.script("w.py", f"open({str(t)!r} + '/f')\n")
    assert ins.inspect("Bash", {"command": "python3 w.py"}, str(world.proj)).verdict == DENY
    assert ins.inspect("Bash", {"command": f"ls {shlex.quote(str(t.parent))}"}, str(world.proj)).verdict == ALLOW


# ---- cache -------------------------------------------------------------------------------------------
def test_cache_hits_and_never_trusts_stale_entries(world):
    cache = ScanCache()
    ins = Inspector(InspectPolicy((ProtectedPath("t", str(world.tgt)),), home=str(world.home), policy_revision="r1"), cache)
    s = world.script("c.py", "print(1)\n")
    assert ins.inspect("Bash", {"command": "python3 c.py"}, str(world.proj)).verdict == ALLOW
    assert ins.inspect("Bash", {"command": "python3 c.py"}, str(world.proj)).verdict == ALLOW
    assert cache.hits >= 1
    s.write_text(f"open('{world.tgt}/secret.txt')\n")            # file changes -> size/mtime change
    assert ins.inspect("Bash", {"command": "python3 c.py"}, str(world.proj)).verdict == DENY
    # same size, same mtime_ns but different inode content is covered by (ino,size,mtime_ns): force identical stat
    st = s.stat()
    s.write_text("A" * st.st_size)
    os.utime(s, ns=(st.st_atime_ns, st.st_mtime_ns + 1))
    assert ins.inspect("Bash", {"command": "python3 c.py"}, str(world.proj)).verdict != DENY
    # policy revision participates in the key
    ins2 = Inspector(InspectPolicy((ProtectedPath("t", str(world.tgt)),), home=str(world.home), policy_revision="r2"), cache)
    h = cache.hits
    ins2.inspect("Bash", {"command": "python3 c.py"}, str(world.proj))
    assert cache.hits == h


# ---- performance / limits ------------------------------------------------------------------------------
def test_performance_with_500_targets_and_a_1mib_script(world):
    targets = tuple(ProtectedPath(f"t{i}", f"/mnt/d{i % 7}/dir {i}") for i in range(500))
    ins = Inspector(InspectPolicy(targets, home=str(world.home), policy_revision="p"))
    body = "\n".join(f"x{i} = {i}  # line {i} padding padding padding" for i in range(20_000))
    s = world.script("large.py", body[: (1 << 20) - 100] + "\n")
    assert s.stat().st_size < 1 << 20
    t0 = time.monotonic()
    d = ins.inspect("Bash", {"command": "python3 large.py"}, str(world.proj))
    dt = time.monotonic() - t0
    assert d.verdict == ALLOW and dt < 2.0, dt
    t0 = time.monotonic()
    ins.inspect("Bash", {"command": "ls -la && git status | head && cat /mnt/d3/x"}, str(world.proj))
    assert time.monotonic() - t0 < 0.5


def test_time_limit_is_enforced_and_reported(world):
    ins = world.make(max_seconds=0.0)
    world.script("t.py", "x = 1\n")
    d = ins.inspect("Bash", {"command": "python3 t.py; python3 t.py; ls"}, str(world.proj))
    assert d.verdict == INCOMPLETE and "TIME_LIMIT" in d.incomplete
    assert world.make("strict", max_seconds=0.0).inspect("Bash", {"command": "ls; ls"}, str(world.proj)).verdict == DENY


def test_pathological_inputs_do_not_hang_or_crash(world):
    for cmd in ["(" * 5000, "$(" * 3000, "'" * 4001, "a" * 2_000_000, "cat " + "'x' " * 50000, "<<EOF\n" * 200,
                "`" * 999, "echo " + "\\" * 10001, ";" * 100000]:
        t0 = time.monotonic()
        d = world.bash(cmd)
        assert time.monotonic() - t0 < 5
        assert d.verdict in (ALLOW, INCOMPLETE, DENY)
    deep = "x = " + "(" * 500 + "1" + ")" * 500
    world.script("deep.py", deep + "\n")
    assert world.bash("python3 deep.py").verdict in (ALLOW, INCOMPLETE)


def test_decision_never_contains_source_or_secret_text(world):
    world.script("s.py", f"SECRET_SNIPPET_XYZ = open('{world.tgt}/secret.txt').read()\n")
    d = world.bash("python3 s.py")
    blob = repr(d.to_dict())
    assert d.verdict == DENY and "SECRET_SNIPPET_XYZ" not in blob and "secret.txt" not in blob


# ---- regression tests for gaps found by tests/security/test_hook_bypass.py ------------------------------------
def test_backtick_substitution_is_terminated_and_folded():
    from protect_folder.inspect import shell
    p = shell.parse("cat `echo /a/b`/c.txt")
    assert "UNTERMINATED_SUBSTITUTION" not in p.incomplete
    assert p.commands[0].words[1].text == "/a/b/c.txt" and not p.commands[0].words[1].dynamic


@pytest.mark.parametrize("src,want,dynamic", [
    ("cat $(echo /x/y)/z", "/x/y/z", False),
    ("cat \"$(echo -n /x y)\"", "/x y", False),
    ("cat $(printf %s /x/y)", "/x/y", False),
    ("cat $(echo $HOME2)", None, True),                 # variables are never guessed
    ("cat $(echo a | tr a b)", None, True),             # pipelines are never folded
    ("cat $(ls /x)", None, True),                       # other commands are never folded
])
def test_only_trivially_deterministic_substitutions_are_folded(src, want, dynamic):
    from protect_folder.inspect import shell
    w = shell.parse(src).commands[0].words[1]
    assert w.dynamic is dynamic
    if want is not None:
        assert w.text == want


def test_literal_eval_is_inspected_dynamic_eval_is_incomplete(tmp_path):
    from protect_folder.inspect.engine import Inspector, InspectPolicy, ProtectedPath, ScanCache
    pol = InspectPolicy((ProtectedPath("t", "/prot/dir"),), "balanced", 1 << 20, 2.0, "r", "/home/u")
    ins = Inspector(pol, ScanCache())
    assert ins.inspect("Bash", {"command": "eval 'cat /prot/dir/x'"}, str(tmp_path)).blocked
    d = ins.inspect("Bash", {"command": "eval \"$X\""}, str(tmp_path))
    assert "EVAL" in d.incomplete and not d.blocked           # balanced mode defers to L3/L4


def test_here_string_words_are_checked_and_dynamic_shell_code_is_incomplete(tmp_path):
    from protect_folder.inspect.engine import Inspector, InspectPolicy, ProtectedPath, ScanCache
    pol = InspectPolicy((ProtectedPath("t", "/prot/dir"),), "strict", 1 << 20, 2.0, "r", "/home/u")
    ins = Inspector(pol, ScanCache())
    assert ins.inspect("Bash", {"command": "xargs cat <<< /prot/dir/x"}, str(tmp_path)).blocked
    d = ins.inspect("Bash", {"command": "bash -c \"$(echo aGk= | base64 -d)\""}, str(tmp_path))
    assert d.blocked and "DYNAMIC_INLINE_CODE" in d.incomplete    # strict mode refuses what it cannot read
