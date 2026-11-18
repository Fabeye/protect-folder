"""In-sandbox TCP relay. Standalone script: run as  python3 -I -S sandbox_relay.py --relay L=U ... -- CMD...

Why it exists: inside SRT the sandbox has its own loopback, so a client that dials 127.0.0.1:PORT (OpenCode
discovering Ollama) never reaches a service on the HOST. The only way out is SRT's authenticated HTTP proxy,
which enforces the network allowlist. This relay listens on a fixed loopback address INSIDE the sandbox and
forwards each connection to a fixed upstream with HTTP CONNECT through that proxy. It therefore grants nothing
the allowlist does not already grant: an upstream that is not in `allowedDomains` gets a 403 from the proxy.

Fail closed: if any listener cannot be bound, or the proxy environment is missing, the command is NOT started.
Stdlib only, no protect_folder imports (it runs with -I -S)."""

from __future__ import annotations

import base64
import os
import signal
import socket
import subprocess
import sys
import threading
from urllib.parse import unquote, urlsplit

EX_UNAVAILABLE = 70
SI_USER = 0
FORWARD = (signal.SIGTERM, signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2)
IGNORE_FROM_TTY = (signal.SIGINT, signal.SIGQUIT)        # the child gets these from the terminal itself


def die(msg: str) -> "None":
    sys.stderr.write("protect-folder relay: " + msg + "\n")
    sys.exit(EX_UNAVAILABLE)


def parse_addr(spec: str, *, loopback_only: bool = False) -> tuple[str, int]:
    host, sep, port = spec.rpartition(":")
    if not sep or not host or not port.isdigit() or not (0 < int(port) < 65536):
        die(f"bad address {spec!r} (want HOST:PORT)")
    if loopback_only and host not in ("127.0.0.1", "::1"):
        die(f"refusing to listen on {host!r}: only loopback inside the sandbox is allowed")
    return host, int(port)


def proxy_from_env(env: dict[str, str]) -> tuple[str, int, str | None]:
    raw = env.get("http_proxy") or env.get("HTTP_PROXY")
    if not raw:
        die("no http_proxy in the environment: not running inside the sandbox runtime")
    u = urlsplit(raw)
    if u.scheme != "http" or not u.hostname or not u.port:
        die("unusable http_proxy value")
    auth = None
    if u.username is not None:
        cred = f"{unquote(u.username)}:{unquote(u.password or '')}"
        auth = "Basic " + base64.b64encode(cred.encode()).decode()
    return u.hostname, u.port, auth


def open_tunnel(proxy: tuple[str, int, str | None], upstream: tuple[str, int]) -> tuple[socket.socket, bytes] | None:
    host, port, auth = proxy
    s = socket.create_connection((host, port), timeout=15)
    target = f"{upstream[0]}:{upstream[1]}"
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        req += f"Proxy-Authorization: {auth}\r\n"
    s.sendall((req + "\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    parts = head.split(b" ", 2)
    if len(parts) < 2 or parts[1] != b"200":
        s.close()
        return None
    s.settimeout(None)
    return s, rest


def pump(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client: socket.socket, proxy: tuple[str, int, str | None], upstream: tuple[str, int]) -> None:
    try:
        tunnel = open_tunnel(proxy, upstream)
    except OSError:
        tunnel = None
    if tunnel is None:
        client.close()
        return
    tunnel, left = tunnel
    if left:
        try:
            client.sendall(left)
        except OSError:
            client.close()
            tunnel.close()
            return
    threading.Thread(target=pump, args=(client, tunnel), daemon=True).start()
    pump(tunnel, client)
    client.close()
    tunnel.close()


def serve(listener: socket.socket, proxy: tuple[str, int, str | None], upstream: tuple[str, int]) -> None:
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn, proxy, upstream), daemon=True).start()


def bind(listen: tuple[str, int]) -> socket.socket:
    fam = socket.AF_INET6 if ":" in listen[0] else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(listen)
        s.listen(64)
    except OSError as exc:
        die(f"cannot listen on {listen[0]}:{listen[1]}: {exc}")
    return s


def parse_args(argv: list[str]) -> tuple[list[tuple[tuple[str, int], tuple[str, int]]], list[str]]:
    relays: list[tuple[tuple[str, int], tuple[str, int]]] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--relay" and i + 1 < len(argv):
            listen, sep, upstream = argv[i + 1].partition("=")
            if not sep:
                die(f"bad --relay {argv[i + 1]!r} (want LISTEN=UPSTREAM)")
            relays.append((parse_addr(listen, loopback_only=True), parse_addr(upstream)))
            i += 2
        elif argv[i] == "--":
            return relays, argv[i + 1:]
        else:
            die(f"unknown argument {argv[i]!r}")
    die("missing '-- COMMAND'")
    return relays, []


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    relays, cmd = parse_args(argv)
    if not cmd:
        die("no command given")
    proxy = proxy_from_env(dict(os.environ))
    listeners = [(bind(l), u) for l, u in relays]                 # every listener must exist BEFORE the child
    for lst, up in listeners:
        threading.Thread(target=serve, args=(lst, proxy, up), daemon=True).start()

    watch = set(FORWARD) | {signal.SIGCHLD, *IGNORE_FROM_TTY}
    old = signal.pthread_sigmask(signal.SIG_BLOCK, watch)
    try:
        proc = subprocess.Popen(cmd, close_fds=True, preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, []))
    except OSError as exc:
        die(f"cannot start {cmd[0]!r}: {exc}")
    signal.signal(signal.SIGCHLD, lambda *_: None)
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            info = signal.sigtimedwait(watch, 0.2)
            if info is not None and info.si_signo != signal.SIGCHLD and info.si_code == SI_USER:
                try:
                    proc.send_signal(info.si_signo)
                except ProcessLookupError:
                    pass
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
    return 128 - rc if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main())
