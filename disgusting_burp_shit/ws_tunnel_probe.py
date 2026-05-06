#!/usr/bin/env python3
import base64
import os
import socket
import ssl

HOST = "10.81.131.108"
PORT = 80

PATHS = [
    "/",
    "/websockify",
    "/ws",
    "/vnc",
    "/novnc/websockify",
]


def ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def build_handshake(path: str) -> bytes:
    key = ws_key()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: http://localhost\r\n"
        "\r\n"
    )
    return req.encode("ascii")


def make_ws_frame(payload: bytes, opcode: int = 2) -> bytes:
    # Client->server frames must be masked.
    first = 0x80 | (opcode & 0x0F)
    n = len(payload)
    mask_key = os.urandom(4)

    if n < 126:
        header = bytes([first, 0x80 | n])
    elif n < 65536:
        header = bytes([first, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        header = bytes([first, 0x80 | 127]) + n.to_bytes(8, "big")

    masked = bytes(payload[i] ^ mask_key[i % 4] for i in range(n))
    return header + mask_key + masked


def recv_ws_frame(sock: socket.socket):
    h = sock.recv(2)
    if len(h) < 2:
        return None, None
    b1, b2 = h[0], h[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    ln = b2 & 0x7F

    if ln == 126:
        ext = sock.recv(2)
        if len(ext) < 2:
            return None, None
        ln = int.from_bytes(ext, "big")
    elif ln == 127:
        ext = sock.recv(8)
        if len(ext) < 8:
            return None, None
        ln = int.from_bytes(ext, "big")

    mask = b""
    if masked:
        mask = sock.recv(4)
        if len(mask) < 4:
            return None, None

    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data))
        if not chunk:
            break
        data += chunk

    if masked:
        data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))

    return opcode, data


def probe_path(path: str):
    print(f"\n[*] Probing path: {path}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((HOST, PORT))
    s.sendall(build_handshake(path))

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(1024)
        if not chunk:
            break
        resp += chunk
        if len(resp) > 8192:
            break

    head = resp.decode("utf-8", errors="ignore")
    first_line = head.splitlines()[0] if head.splitlines() else "<no status>"
    print(f"    Handshake: {first_line}")

    if "101" not in first_line:
        s.close()
        return

    # Try to elicit backend behavior with both text and binary payloads.
    probes = [
        (1, b"HELLO"),
        (2, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        (2, b"RFB 003.008\n"),
    ]

    for op, payload in probes:
        try:
            s.sendall(make_ws_frame(payload, opcode=op))
            opcode, data = recv_ws_frame(s)
            if opcode is None:
                print(f"    Probe op={op}: no frame returned")
                continue
            preview = data[:120]
            txt = preview.decode("utf-8", errors="ignore")
            print(f"    Probe op={op}: frame opcode={opcode}, {len(data)} bytes, preview={txt!r}")
        except Exception as exc:
            print(f"    Probe op={op}: error: {exc}")

    s.close()


if __name__ == "__main__":
    for p in PATHS:
        try:
            probe_path(p)
        except Exception as exc:
            print(f"\n[*] Probing path {p} failed: {exc}")
