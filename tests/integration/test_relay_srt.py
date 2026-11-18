"""The relay + network profile through a REAL SRT sandbox: a host-loopback service is reachable only at the
single allowlisted literal, and only via the relay (the sandbox's own loopback is not the host's)."""

import json
import os
import socket
import sys
import threading

import pytest

from protect_folder import admin, jsonio, launcher
from protect_folder.hostops import MetaState

pytestmark = pytest.mark.srt


def host_server(reply: bytes):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            try:
                c.recv(100)
                c.sendall(reply)
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()
    return s, s.getsockname()[1]


@pytest.fixture
def world(senv):
    e = senv
    e.ws = e.tmp / "project"
    e.ws.mkdir()
    e.install()
    d = e.mkdir("Forbidden folder")
    st = os.stat(d)
    e.host.meta[(st.st_dev, st.st_ino)] = MetaState(1000, 1000, 0o750)
    assert admin.add(e.ctx, str(d), yes=True, accept_no_fs_enforcement=True).ok
    e.is_root = False
    return e


def set_profile(e, name, prof):
    lo = e.layout
    jsonio.atomic_write(lo.policy_file, json.dumps({"schema_version": 1, "profiles": {name: prof}}).encode(),
                        0o644, lo.trusted_uid, lo.trusted_gid)


CLIENT = ("import socket,sys;p=int(sys.argv[1]);s=socket.socket();s.settimeout(8)\n"
          "try:\n s.connect(('127.0.0.1',p));s.sendall(b'hi');print('GOT',s.recv(50).decode())\n"
          "except Exception as e:\n print('FAIL',type(e).__name__)\n")


def go(e, argv, capfd, **kw):
    code = launcher.run(e.ctx, argv, cwd=str(e.ws), quiet=True, **kw)
    c = capfd.readouterr()
    return code, c.out, c.err


def test_host_service_reachable_through_relay_and_only_that_port(world, capfd):
    e = world
    srv, port = host_server(b"HOST-SERVICE")
    other, other_port = host_server(b"OTHER-SERVICE")
    lit = f"127.0.0.1:{port}"
    set_profile(e, "p", {"allowedDomains": [lit], "relays": [{"listen": lit, "upstream": lit}]})
    # allowlisted literal: reachable at the sandbox's loopback because the relay forwards it
    code, out, err = go(e, [sys.executable, "-c", CLIENT, str(port)], capfd, profile="p")
    assert code == 0 and "GOT HOST-SERVICE" in out, (out, err)
    # a different host port is NOT reachable (nothing listens on the sandbox's loopback there)
    code, out, err = go(e, [sys.executable, "-c", CLIENT, str(other_port)], capfd, profile="p")
    assert "OTHER-SERVICE" not in out and "FAIL" in out


def test_without_relay_the_literal_is_not_reachable_from_a_plain_client(world, capfd):
    """Documents WHY the relay exists: the allowlist alone does not make host loopback visible."""
    e = world
    srv, port = host_server(b"HOST-SERVICE")
    lit = f"127.0.0.1:{port}"
    set_profile(e, "norelay", {"allowedDomains": [lit]})
    code, out, err = go(e, [sys.executable, "-c", CLIENT, str(port)], capfd, profile="norelay")
    assert "HOST-SERVICE" not in out


def test_relay_cannot_exceed_the_allowlist_even_if_misconfigured(world, capfd):
    e = world
    srv, port = host_server(b"HOST-SERVICE")
    lit = f"127.0.0.1:{port}"
    set_profile(e, "bad", {"allowedDomains": ["127.0.0.1:9"], "relays": [{"listen": lit, "upstream": lit}]})
    from protect_folder.errors import ProtectError
    with pytest.raises(ProtectError):
        launcher.run(e.ctx, [sys.executable, "-c", "pass"], cwd=str(e.ws), quiet=True, profile="bad")
