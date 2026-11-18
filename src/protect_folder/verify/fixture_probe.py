"""Program run INSIDE the sandbox against a synthetic fixture. It only reports observations."""

PROBE_SRC = r'''
import errno, json, os, subprocess, sys

cfg = json.loads(sys.argv[1])
T, W, MARK, OUT = cfg["T"], cfg["W"], cfg["marker"], cfg["outside"]
results = []

def classify_exc(e):
    if isinstance(e, FileNotFoundError):
        return "masked_absent"
    if isinstance(e, PermissionError):
        return "eacces" if e.errno == errno.EACCES else "eperm"
    if isinstance(e, OSError):
        return {errno.EROFS: "erofs", errno.EBUSY: "ebusy", errno.EXDEV: "exdev",
                errno.ENOTDIR: "enotdir"}.get(e.errno, "other_err:%s" % errno.errorcode.get(e.errno, e.errno))
    return "other_err:" + type(e).__name__

def rec(name, outcome, detail=""):
    results.append({"name": name, "outcome": outcome, "detail": detail})

def read_check(name, path):
    try:
        data = open(path, "rb").read().decode("utf-8", "replace")
    except Exception as e:
        rec(name, classify_exc(e)); return
    rec(name, "leak" if MARK in data else "ok_no_marker")

def sub_check(name, argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except Exception as e:
        rec(name, "other_err:" + type(e).__name__); return
    if MARK in p.stdout or MARK in p.stderr:
        rec(name, "leak")
    elif p.returncode == 0:
        rec(name, "ok_no_marker")
    else:
        err = p.stderr
        rec(name, "masked_absent" if "No such file" in err else
            "eacces" if "Permission denied" in err else "eperm" if "not permitted" in err else
            "other_err:rc%d" % p.returncode)

read_check("read_direct", T + "/marker.txt")
read_check("read_deep_file", T + "/sub/deep.txt")
read_check("read_dotdot_spelling", T + "/../" + os.path.basename(T) + "/marker.txt")
read_check("read_proc_root_spelling", "/proc/self/root" + T + "/marker.txt")
read_check("read_via_preexisting_symlink", W + "/alias/marker.txt")
try:
    os.symlink(T, W + "/runtime_link")
    read_check("read_via_runtime_created_symlink", W + "/runtime_link/marker.txt")
except Exception as e:
    rec("read_via_runtime_created_symlink", classify_exc(e))
try:
    names = os.listdir(T)
    rec("list_directory", "leak" if "marker.txt" in names else "empty_masked")
except Exception as e:
    rec("list_directory", classify_exc(e))
sub_check("read_via_cat_child", ["cat", T + "/marker.txt"])
sub_check("read_via_python_child", [sys.executable, "-I", "-c",
          "import sys; print(open(sys.argv[1]).read())", T + "/marker.txt"])
sub_check("read_via_shell_glob_child", ["sh", "-c", "cat " + T.replace(" ", "\\ ") + "/*"])
sub_check("find_child", ["find", T, "-name", "*.txt"])
try:
    os.link(T + "/marker.txt", W + "/hardlink")
    rec("hardlink_out_of_target", "leak" if MARK in open(W + "/hardlink").read() else "ok_no_marker")
except Exception as e:
    rec("hardlink_out_of_target", classify_exc(e))
try:
    open(T + "/created_by_agent.txt", "w").write("x")
    rec("write_into_target", "ok_ephemeral")     # judged host-side: must not persist
except Exception as e:
    rec("write_into_target", classify_exc(e))
try:
    os.rename(T, OUT + "/renamed")
    rec("rename_target_away", "ok_renamed")
except Exception as e:
    rec("rename_target_away", classify_exc(e))
try:
    open(OUT + "/x", "w").write("x")
    rec("write_outside_workspace", "ok_written")
except Exception as e:
    rec("write_outside_workspace", classify_exc(e))
# controls: prove the sandbox is working normally, so blocks above are not a broken environment
try:
    open(W + "/control_write.txt", "w").write("ok")
    rec("control_write_workspace", "ok")
except Exception as e:
    rec("control_write_workspace", classify_exc(e))
try:
    rec("control_read_workspace", "ok" if open(W + "/control.txt").read() == "control-ok" else "bad")
except Exception as e:
    rec("control_read_workspace", classify_exc(e))
sub_check("control_python_child", [sys.executable, "-I", "-c", "print('hello')"])
print(json.dumps(results))
'''
