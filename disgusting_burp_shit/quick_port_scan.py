#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "10.81.131.108"
PORTS = [
    22, 80, 81, 88, 443, 444, 445, 8080, 8081, 8000, 8443, 8888, 9000, 9001, 9090,
    3000, 3001, 5000, 5001, 7000, 7001, 1337, 31337
]


def check_port(port: int):
    s = socket.socket()
    s.settimeout(1.2)
    try:
        rc = s.connect_ex((HOST, port))
        if rc == 0:
            return port, True
        return port, False
    except Exception:
        return port, False
    finally:
        s.close()


def grab_banner(port: int):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((HOST, port))
        # Try HTTP probe first
        s.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        data = s.recv(512)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return "<no banner>"
    finally:
        s.close()


if __name__ == "__main__":
    open_ports = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(check_port, p) for p in PORTS]
        for f in as_completed(futs):
            port, ok = f.result()
            if ok:
                open_ports.append(port)

    open_ports.sort()
    print("Open ports:", open_ports)
    for p in open_ports:
        banner = grab_banner(p)
        first = banner.splitlines()[0] if banner else ""
        print(f"[{p}] {first[:220]}")
