#!/usr/bin/env python3
from __future__ import annotations

import base64
import hmac
import os
import select
import socket
import threading
import urllib.parse
import time
from typing import Any

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {
        "1",
        "true",
        "yes",
        "on"
    }


PROXY_AUTH_ENABLED = env_flag("PROXY_AUTH_ENABLED", "0")
PROXY_USERNAME = os.environ.get("PROXY_USERNAME", "")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "")




def proxy_auth_ready() -> bool:
    return bool(PROXY_USERNAME and PROXY_PASSWORD)


def proxy_auth_match(username: str, password: str) -> bool:
    if not proxy_auth_ready():
        return False

    return hmac.compare_digest(username, PROXY_USERNAME) and hmac.compare_digest(password, PROXY_PASSWORD)


def parse_basic_proxy_auth(value: str) -> tuple[str, str] | None:
    value = value.strip()

    if not value.lower().startswith("basic "):
        return None

    token = value[6:].strip()

    try:
        raw = base64.b64decode(token).decode("utf-8", errors="replace")
    except Exception:
        return None

    username, sep, password = raw.partition(":")
    if not sep:
        return None

    return username, password


def http_proxy_auth_ok(lines: list[str]) -> bool:
    if not PROXY_AUTH_ENABLED:
        return True

    for line in lines[1:]:
        if not line.lower().startswith("proxy-authorization:"):
            continue

        value = line.split(":", 1)[1].strip()
        parsed = parse_basic_proxy_auth(value)
        if not parsed:
            return False

        username, password = parsed
        return proxy_auth_match(username, password)

    return False


def send_http_auth_required(client: socket.socket) -> None:
    client.sendall(
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b"Proxy-Authenticate: Basic realm=\"AimiliVPN Proxy\"\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


def socks5_auth(client: socket.socket, methods: bytes) -> bool:
    if not PROXY_AUTH_ENABLED:
        if 0x00 not in methods:
            client.sendall(b"\x05\xff")
            return False

        client.sendall(b"\x05\x00")
        return True

    # 认证开启后，只接受 username/password 认证方式
    if 0x02 not in methods:
        client.sendall(b"\x05\xff")
        return False

    client.sendall(b"\x05\x02")

    try:
        auth_version = recv_exact(client, 1)[0]
        if auth_version != 1:
            client.sendall(b"\x01\x01")
            return False

        username_len = recv_exact(client, 1)[0]
        username = recv_exact(client, username_len).decode("utf-8", errors="replace")

        password_len = recv_exact(client, 1)[0]
        password = recv_exact(client, password_len).decode("utf-8", errors="replace")

        if proxy_auth_match(username, password):
            client.sendall(b"\x01\x00")
            return True

        client.sendall(b"\x01\x01")
        return False
    except Exception:
        try:
            client.sendall(b"\x01\x01")
        except OSError:
            pass
        return False

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def resolve_dns_over_tun0(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    import random
    tx_id = random.getrandbits(16).to_bytes(2, "big")
    flags = b"\x01\x00"
    questions = b"\x00\x01"
    rrs = b"\x00\x00\x00\x00\x00\x00"

    qname = b""
    for part in host.split("."):
        if not part:
            continue
        part_bytes = part.encode("idna")
        qname += len(part_bytes).to_bytes(1, "big") + part_bytes
    qname += b"\x00"

    qtype_qclass = b"\x00\x01\x00\x01"
    packet = tx_id + flags + questions + rrs + qname + qtype_qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError:
            return None
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()

    if len(resp) < 12:
        return None
    if resp[:2] != tx_id:
        return None

    rcode = resp[3] & 0x0F
    if rcode != 0:
        return None

    offset = 12
    while offset < len(resp):
        length = resp[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + length

    offset += 4
    answers_count = int.from_bytes(resp[6:8], "big")
    if answers_count == 0:
        return None

    for _ in range(answers_count):
        if offset >= len(resp):
            break
        while offset < len(resp):
            length = resp[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                offset += 2
                break
            else:
                offset += 1 + length
        if offset + 10 > len(resp):
            break
        atype = int.from_bytes(resp[offset : offset + 2], "big")
        aclass = int.from_bytes(resp[offset + 2 : offset + 4], "big")
        rdlength = int.from_bytes(resp[offset + 8 : offset + 10], "big")
        offset += 10
        if offset + rdlength > len(resp):
            break
        if atype == 1 and aclass == 1 and rdlength == 4:
            ip_bytes = resp[offset : offset + 4]
            return socket.inet_ntoa(ip_bytes)
        offset += rdlength
    return None

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    host, port = address
    resolved_ip = resolve_dns_over_tun0(host)
    if resolved_ip:
        host = resolved_ip

    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)

        if not socks5_auth(client, methods):
            return
        version, command, _, address_type = recv_exact(client, 4)

        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            upstream = create_connection((host, port), timeout=20)
        except Exception:
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    finally:
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        method, target, version = lines[0].split(" ", 2)

        if not http_proxy_auth_ok(lines):
            send_http_auth_required(client)
            return
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            port = parse_int(port_text) or 443
            upstream = create_connection((host, port), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [
            line
            for line in lines[1:]
            if not line.lower().startswith((
                "proxy-connection:",
                "connection:",
                "proxy-authorization:",
            ))
        ]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first)
        else:
            http_client(client, first)
    except Exception:
        try:
            client.close()
        except OSError:
            pass

def start_proxy_server(host: str, port: int) -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
        if PROXY_AUTH_ENABLED and not proxy_auth_ready():
            print(
                "[WARN] PROXY_AUTH_ENABLED=1, but PROXY_USERNAME or PROXY_PASSWORD is empty. "
                "All proxy requests will be rejected.",
                flush=True
            )
        auth_status = "auth enabled" if PROXY_AUTH_ENABLED else "no auth"
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port} ({auth_status})", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {e}", flush=True)
        return

    while True:
        try:
            client, address = server.accept()
            threading.Thread(
                target=proxy_client,
                args=(client, address),
                daemon=True,
            ).start()

        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)