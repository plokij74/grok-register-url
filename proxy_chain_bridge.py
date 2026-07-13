"""Local HTTP proxy bridge: client → local_proxy → residential → target.

Use case (Kookeey etc.):
  Chromium / requests cannot natively chain proxies.
  gate.kookeey.info is only reachable via local Clash (127.0.0.1:7890).

  Browser  →  127.0.0.1:bridge_port  (no auth)
           →  127.0.0.1:7890         (local VPN/proxy)
           →  user:pass@gate...:1000 (residential)
           →  internet

This module starts one bridge per residential URL (reused process-wide).
"""

from __future__ import annotations

import base64
import select
import socket
import threading
import time
from typing import Callable
from urllib.parse import unquote, urlparse

LogFn = Callable[[str], None]

_lock = threading.Lock()
# key = f"{local}|{residential}" -> {"port": int, "thread": Thread, "stop": Event}
_bridges: dict[str, dict] = {}


def _noop_log(_: str) -> None:
    return None


def _parse(proxy_url: str) -> dict:
    p = (proxy_url or "").strip()
    if not p:
        return {}
    u = urlparse(p if "://" in p else f"http://{p}")
    host = u.hostname or ""
    if not host:
        return {}
    port = u.port or (443 if (u.scheme or "http") == "https" else 80)
    return {
        "scheme": (u.scheme or "http").lower(),
        "host": host,
        "port": int(port),
        "username": unquote(u.username) if u.username else "",
        "password": unquote(u.password) if u.password else "",
    }


def _basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _recv_until(sock: socket.socket, marker: bytes = b"\r\n\r\n", limit: int = 65536) -> bytes:
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection")
        data += chunk
    return data


def _connect_via_socks5(
    transport: socket.socket,
    proxy: dict,
    target_host: str,
    target_port: int,
) -> socket.socket:
    """Complete an authenticated SOCKS5 CONNECT over an open transport."""
    username = str(proxy.get("username") or "").encode("utf-8")
    password = str(proxy.get("password") or "").encode("utf-8")
    methods = b"\x00\x02" if username else b"\x00"
    transport.sendall(b"\x05" + bytes((len(methods),)) + methods)
    version, method = _recv_exact(transport, 2)
    if version != 5 or method == 0xFF:
        raise OSError("SOCKS5 proxy rejected authentication methods")
    if method == 0x02:
        if len(username) > 255 or len(password) > 255:
            raise OSError("SOCKS5 username/password is too long")
        transport.sendall(
            b"\x01" + bytes((len(username),)) + username
            + bytes((len(password),)) + password
        )
        auth_version, auth_status = _recv_exact(transport, 2)
        if auth_version != 1 or auth_status != 0:
            raise OSError("SOCKS5 username/password authentication failed")
    elif method != 0x00:
        raise OSError(f"unsupported SOCKS5 auth method: {method}")

    host_bytes = target_host.encode("idna")
    if len(host_bytes) > 255:
        raise OSError("SOCKS5 target hostname is too long")
    request = (
        b"\x05\x01\x00\x03" + bytes((len(host_bytes),)) + host_bytes
        + int(target_port).to_bytes(2, "big")
    )
    transport.sendall(request)
    version, reply, _reserved, address_type = _recv_exact(transport, 4)
    if version != 5 or reply != 0:
        raise OSError(f"SOCKS5 CONNECT rejected (reply={reply})")
    if address_type == 1:
        _recv_exact(transport, 4)
    elif address_type == 3:
        _recv_exact(transport, _recv_exact(transport, 1)[0])
    elif address_type == 4:
        _recv_exact(transport, 16)
    else:
        raise OSError(f"invalid SOCKS5 address type: {address_type}")
    _recv_exact(transport, 2)
    return transport


def _connect_via_http_proxy(
    hop: dict,
    target_host: str,
    target_port: int,
    *,
    timeout: float = 30.0,
) -> socket.socket:
    """TCP connect to target_host:target_port through an HTTP proxy hop."""
    s = socket.create_connection((hop["host"], hop["port"]), timeout=timeout)
    s.settimeout(timeout)
    req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Proxy-Connection: keep-alive\r\n"
    )
    if hop.get("username"):
        req += f"Proxy-Authorization: {_basic_auth_header(hop['username'], hop['password'])}\r\n"
    req += "\r\n"
    s.sendall(req.encode("utf-8"))
    resp = _recv_until(s)
    first = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if b" 200 " not in resp.split(b"\r\n", 1)[0] and not first.startswith("HTTP/1.1 200") and not first.startswith("HTTP/1.0 200"):
        s.close()
        raise OSError(f"proxy CONNECT failed via {hop['host']}:{hop['port']} → {target_host}:{target_port}: {first}")
    return s


def _open_exit_socket(
    local: dict,
    residential: dict,
    target_host: str,
    target_port: int,
    *,
    timeout: float = 45.0,
) -> socket.socket:
    """client wants target; open tunnel: local → residential → target."""
    # 1) through local proxy, reach residential gateway
    if local:
        if local.get("scheme") in ("socks5", "socks5h"):
            to_resi = socket.create_connection(
                (local["host"], local["port"]), timeout=timeout
            )
            to_resi.settimeout(timeout)
            try:
                to_resi = _connect_via_socks5(
                    to_resi,
                    local,
                    residential["host"],
                    residential["port"],
                )
            except Exception:
                to_resi.close()
                raise
        else:
            to_resi = _connect_via_http_proxy(
                local, residential["host"], residential["port"], timeout=timeout
            )
    else:
        to_resi = socket.create_connection(
            (residential["host"], residential["port"]), timeout=timeout
        )
        to_resi.settimeout(timeout)

    # 2) through residential, CONNECT to real target
    if residential.get("scheme") in ("socks5", "socks5h"):
        try:
            return _connect_via_socks5(
                to_resi, residential, target_host, target_port
            )
        except Exception:
            to_resi.close()
            raise

    req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Proxy-Connection: keep-alive\r\n"
    )
    if residential.get("username"):
        req += (
            f"Proxy-Authorization: "
            f"{_basic_auth_header(residential['username'], residential['password'])}\r\n"
        )
    req += "\r\n"
    to_resi.sendall(req.encode("utf-8"))
    resp = _recv_until(to_resi)
    first = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if not (first.startswith("HTTP/1.1 200") or first.startswith("HTTP/1.0 200") or b" 200 " in resp.split(b"\r\n", 1)[0]):
        to_resi.close()
        raise OSError(f"residential CONNECT failed → {target_host}:{target_port}: {first}")
    return to_resi


def _pipe(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            r, _, x = select.select(sockets, [], sockets, 300)
            if x:
                break
            if not r:
                break
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _handle_client(
    client: socket.socket,
    local: dict,
    residential: dict,
    log: LogFn,
) -> None:
    client.settimeout(60)
    try:
        head = _recv_until(client)
        if not head:
            client.close()
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = line.split()
        if len(parts) < 2:
            client.close()
            return
        method, target = parts[0].upper(), parts[1]

        if method == "CONNECT":
            # CONNECT host:port HTTP/1.1
            if ":" in target:
                host, port_s = target.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = target, 443
            try:
                remote = _open_exit_socket(local, residential, host, port)
            except Exception as exc:
                try:
                    client.sendall(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                    )
                except OSError:
                    pass
                client.close()
                log(f"[bridge] CONNECT {host}:{port} failed: {exc}")
                return
            try:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except OSError:
                remote.close()
                client.close()
                return
            _pipe(client, remote)
            return

        # Absolute-form HTTP request: GET http://host/path HTTP/1.1
        # Relative form is rare for proxy clients we care about.
        host = ""
        port = 80
        if target.startswith("http://") or target.startswith("https://"):
            u = urlparse(target)
            host = u.hostname or ""
            port = u.port or (443 if u.scheme == "https" else 80)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            # rebuild request line as origin-form for upstream after CONNECT...
            # Simpler path: open tunnel then re-send rewritten request over tunnel.
            new_first = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
            rest = head.split(b"\r\n", 1)[1] if b"\r\n" in head else b"\r\n"
            # strip Proxy-Authorization / absolute Host issues: keep as-is mostly
            rebuilt = new_first + rest
        else:
            # origin-form: need Host header
            rebuilt = head
            for hl in head.split(b"\r\n")[1:]:
                if hl.lower().startswith(b"host:"):
                    hv = hl.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
                    if ":" in hv:
                        host, port_s = hv.rsplit(":", 1)
                        try:
                            port = int(port_s)
                        except ValueError:
                            host, port = hv, 80
                    else:
                        host, port = hv, 80
                    break

        if not host:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            client.close()
            return

        try:
            remote = _open_exit_socket(local, residential, host, port)
        except Exception as exc:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            client.close()
            log(f"[bridge] {method} {host}:{port} failed: {exc}")
            return

        try:
            remote.sendall(rebuilt)
        except OSError as exc:
            remote.close()
            client.close()
            log(f"[bridge] send to exit failed: {exc}")
            return
        _pipe(client, remote)
    except Exception as exc:
        log(f"[bridge] client error: {exc}")
        try:
            client.close()
        except OSError:
            pass


def _serve(
    listen_sock: socket.socket,
    local: dict,
    residential: dict,
    stop: threading.Event,
    log: LogFn,
) -> None:
    listen_sock.settimeout(1.0)
    while not stop.is_set():
        try:
            client, _addr = listen_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        t = threading.Thread(
            target=_handle_client,
            args=(client, local, residential, log),
            daemon=True,
        )
        t.start()
    try:
        listen_sock.close()
    except OSError:
        pass


def ensure_bridge(
    residential_proxy: str,
    local_proxy: str,
    *,
    log: LogFn | None = None,
    listen_host: str = "127.0.0.1",
    preferred_port: int = 0,
) -> str:
    """Start (or reuse) chain bridge. Returns http://127.0.0.1:PORT for clients.

    preferred_port=0 → ephemeral free port.
    """
    log = log or _noop_log
    residential = _parse(residential_proxy)
    local = _parse(local_proxy) if local_proxy else {}
    if not residential:
        raise ValueError("invalid residential proxy")

    key = f"{local_proxy or ''}|{residential_proxy}"
    with _lock:
        existing = _bridges.get(key)
        if existing and existing.get("thread") and existing["thread"].is_alive():
            port = existing["port"]
            return f"http://{listen_host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_host, int(preferred_port or 0)))
        sock.listen(128)
        port = sock.getsockname()[1]
        stop = threading.Event()
        th = threading.Thread(
            target=_serve,
            args=(sock, local, residential, stop, log),
            name=f"proxy-bridge-{port}",
            daemon=True,
        )
        th.start()
        _bridges[key] = {
            "port": port,
            "thread": th,
            "stop": stop,
            "sock": sock,
            "started": time.time(),
            "residential": residential_proxy,
            "local": local_proxy,
        }
        log(
            f"[bridge] up http://{listen_host}:{port}  "
            f"chain local={local_proxy or '(direct)'} → "
            f"resi={residential['host']}:{residential['port']}"
        )
        return f"http://{listen_host}:{port}"


def stop_all_bridges() -> None:
    with _lock:
        items = list(_bridges.values())
        _bridges.clear()
    for item in items:
        try:
            item["stop"].set()
        except Exception:
            pass
        try:
            item["sock"].close()
        except Exception:
            pass
