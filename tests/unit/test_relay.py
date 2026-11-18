"""The in-sandbox relay, against a fake SRT proxy (HTTP CONNECT with Basic auth)."""

import base64
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from protect_folder import launcher
from protect_folder.errors import ProtectError
from protect_folder.policy import profiles

RELAY = str(Path(launcher.relay_script()))


class FakeProxy:
    """Accepts CONNECT host:port, checks credentials, and tunnels only to `allowed` targets."""

    def __init__(self, allowed, user="srt.X", pw="s3cret"):
        self.allowed, self.user, self.pw = set(allowed), user, pw
        self.seen = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def env(self):
        return {"http_proxy": f"http://{self.user}:{self.pw}@127.0.0.1:{self.port}"}

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                return
            buf += d
        head = buf.split(b"\r\n\r\n")[0].decode()
        first, *hdrs = head.split("\r\n")
        _, target, _ = first.split(" ")
        auth = next((h.split(": ", 1)[1] for h in hdrs if h.lower().startswith("proxy-authorization")), "")
        self.seen.append((target, auth))
        want = "Basic " + base64.b64encode(f"{self.user}:{self.pw}".encode()).decode()
        if auth != want:
            c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            c.close()
            return
        if target not in self.allowed:
            c.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            c.close()
            return
        host, port = target.rsplit(":", 1)
        up = socket.create_connection((host, int(port)))
        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        t = threading.Thread(target=_pipe, args=(up, c), daemon=True)
        t.start()
        _pipe(c, up)


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def echo_server():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=lambda c=c: (c.sendall(b"hello:" + c.recv(100)), c.close()), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run_relay(args, cmd, env, **kw):
    full_env = {"PATH": os.environ["PATH"], **env}
    return subprocess.Popen([sys.executable, "-I", "-S", RELAY, *args, "--", *cmd], env=full_env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def client_cmd(port, payload="x"):
    code = ("import socket,sys;s=socket.create_connection(('127.0.0.1',%d),timeout=10);s.sendall(b'%s');"
            "print(s.recv(100).decode())" % (port, payload))
    return [sys.executable, "-c", code]


def test_relay_forwards_through_proxy_and_returns_child_status():
    up = echo_server()
    proxy = FakeProxy({f"127.0.0.1:{up}"})
    lp = free_port()
    p = run_relay(["--relay", f"127.0.0.1:{lp}=127.0.0.1:{up}"], client_cmd(lp, "ping"), proxy.env())
    out, err = p.communicate(timeout=30)
    assert p.returncode == 0, err
    assert out.decode().strip() == "hello:ping"
    assert proxy.seen and proxy.seen[0][0] == f"127.0.0.1:{up}" and proxy.seen[0][1].startswith("Basic ")


def test_proxy_denial_is_not_bypassed():
    up = echo_server()
    proxy = FakeProxy(set())                         # nothing allowlisted
    lp = free_port()
    p = run_relay(["--relay", f"127.0.0.1:{lp}=127.0.0.1:{up}"], client_cmd(lp), proxy.env())
    out, err = p.communicate(timeout=30)
    assert "hello:" not in out.decode()              # the relay has no path around the proxy
    assert proxy.seen


def test_wrong_proxy_credentials_get_nothing():
    up = echo_server()
    proxy = FakeProxy({f"127.0.0.1:{up}"})
    env = {"http_proxy": f"http://srt.X:WRONG@127.0.0.1:{proxy.port}"}
    lp = free_port()
    p = run_relay(["--relay", f"127.0.0.1:{lp}=127.0.0.1:{up}"], client_cmd(lp), env)
    out, _ = p.communicate(timeout=30)
    assert "hello:" not in out.decode()


def test_exit_code_propagates():
    p = run_relay([], [sys.executable, "-c", "raise SystemExit(7)"], {"http_proxy": "http://u:p@127.0.0.1:9"})
    p.communicate(timeout=30)
    assert p.returncode == 7


def test_fails_closed_when_listener_cannot_bind_and_child_never_starts(tmp_path):
    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    port = held.getsockname()[1]
    sentinel = tmp_path / "STARTED"
    p = run_relay(["--relay", f"127.0.0.1:{port}=127.0.0.1:1"],
                  [sys.executable, "-c", f"open({str(sentinel)!r},'w')"], {"http_proxy": "http://u:p@127.0.0.1:9"})
    p.communicate(timeout=30)
    assert p.returncode == 70 and not sentinel.exists()


@pytest.mark.parametrize("env", [{}, {"http_proxy": "ftp://x"}, {"http_proxy": "http://nohost"}])
def test_fails_closed_without_a_usable_proxy(tmp_path, env):
    sentinel = tmp_path / "STARTED"
    p = run_relay(["--relay", "127.0.0.1:%d=127.0.0.1:1" % free_port()],
                  [sys.executable, "-c", f"open({str(sentinel)!r},'w')"], env)
    p.communicate(timeout=30)
    assert p.returncode == 70 and not sentinel.exists()


@pytest.mark.parametrize("args", [["--relay", "0.0.0.0:9=127.0.0.1:1"], ["--relay", "10.0.0.5:9=127.0.0.1:1"],
                                  ["--relay", "127.0.0.1:0=127.0.0.1:1"], ["--relay", "nocolon=127.0.0.1:1"],
                                  ["--relay", "127.0.0.1:9"], ["--bogus"]])
def test_refuses_non_loopback_or_malformed_listeners(args):
    p = run_relay(args, [sys.executable, "-c", "pass"], {"http_proxy": "http://u:p@127.0.0.1:9"})
    p.communicate(timeout=30)
    assert p.returncode == 70


def test_sigterm_is_forwarded_to_the_child(tmp_path):
    ready = tmp_path / "ready"
    code = (f"import signal,time,sys;signal.signal(signal.SIGTERM, lambda *a: sys.exit(42));"
            f"open({str(ready)!r},'w');time.sleep(30)")
    p = run_relay([], [sys.executable, "-c", code], {"http_proxy": "http://u:p@127.0.0.1:9"})
    for _ in range(100):
        if ready.exists():
            break
        time.sleep(0.1)
    assert ready.exists()
    os.kill(p.pid, signal.SIGTERM)
    p.communicate(timeout=30)
    assert p.returncode == 42


# ---- launcher wrapping and profile validation ------------------------------------------------------------------
def test_wrap_relays():
    assert launcher.wrap_relays([], ["opencode", "run"]) == ["opencode", "run"]
    w = launcher.wrap_relays([("127.0.0.1:11434", "127.0.0.1:11434")], ["opencode", "--", "x"])
    assert w[:4] == ["/usr/bin/python3", "-I", "-S", launcher.relay_script()]
    assert w[4:6] == ["--relay", "127.0.0.1:11434=127.0.0.1:11434"] and w[6:] == ["--", "opencode", "--", "x"]


def test_builtin_ollama_profile_is_exactly_one_literal_and_one_relay():
    doms = profiles.resolve_profile("opencode-local-ollama", {})
    assert doms == ["127.0.0.1:11434"]
    assert profiles.resolve_relays("opencode-local-ollama", {}, doms) == [("127.0.0.1:11434", "127.0.0.1:11434")]
    assert profiles.resolve_relays("offline", {}, []) == []


@pytest.mark.parametrize("relay", [{"listen": "0.0.0.0:1", "upstream": "127.0.0.1:2"},
                                   {"listen": "127.0.0.1:1", "upstream": "evil.example:443"},
                                   {"listen": "127.0.0.1:1"}, "junk"])
def test_custom_profile_relays_are_validated(relay):
    pol = {"profiles": {"p": {"allowedDomains": ["127.0.0.1:2"], "relays": [relay]}}}
    with pytest.raises(ProtectError):
        profiles.resolve_relays("p", pol, profiles.resolve_profile("p", pol))
