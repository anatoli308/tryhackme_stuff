#!/usr/bin/env python3
"""
Voyage stage-2 enumeration helper
- Confirms baseline
- Bruteforces Host-header vhosts by content-length delta
- Enumerates interesting paths

Run on AttackBox:
  python3 voyage_next_enum.py --target 10.82.166.188
"""

import argparse
import requests

COMMON_VHOSTS = [
    "tourism.thm", "www.tourism.thm", "admin.tourism.thm", "api.tourism.thm",
    "dev.tourism.thm", "staging.tourism.thm", "internal.tourism.thm",
    "voyage.thm", "app.tourism.thm", "portal.tourism.thm", "dashboard.tourism.thm",
    "intranet.tourism.thm", "cms.tourism.thm", "backend.tourism.thm"
]

COMMON_PATHS = [
    "/", "/README.txt", "/robots.txt", "/administrator/", "/api/",
    "/api/index.php/v1/config/application?public=true",
    "/api/index.php/v1/users?public=true",
    "/index.php?option=com_users&view=login",
    "/index.php/component/users/remind?Itemid=101",
    "/index.php/component/users/reset?Itemid=101",
    "/dashboard", "/portal", "/app", "/internal", "/dev", "/test",
    "/finance", "/revenue", "/reports", "/pickle", "/serialize", "/preview",
    "/upload", "/admin", "/api/v1", "/graphql"
]


def req(session: requests.Session, url: str, host: str = None):
    headers = {}
    if host:
        headers["Host"] = host
    r = session.get(url, headers=headers, timeout=10, allow_redirects=False)
    return r.status_code, len(r.text), r.headers.get("Location", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="10.82.166.188")
    args = ap.parse_args()

    base = f"http://{args.target}"
    s = requests.Session()

    print("\n=== Baseline ===")
    code, blen, _ = req(s, base)
    print(f"[+] {base} -> {code}, len={blen}")

    print("\n=== VHost Host-header delta scan ===")
    found = []
    for host in COMMON_VHOSTS:
        try:
            code, l, loc = req(s, base, host=host)
            delta = abs(l - blen)
            if code in (200, 301, 302, 401, 403) and delta > 40:
                found.append((host, code, l, delta, loc))
                print(f"[+] {host:24} code={code} len={l} delta={delta} loc={loc}")
        except Exception:
            pass

    if not found:
        print("[-] No obvious vhost delta found with built-in list")

    print("\n=== Path scan (direct target) ===")
    for p in COMMON_PATHS:
        try:
            code, l, loc = req(s, base + p)
            if code in (200, 301, 302, 401, 403):
                print(f"[+] {p:65} code={code} len={l} loc={loc}")
        except Exception:
            pass

    print("\n=== Recommendations ===")
    print("1) If any vhost shows large delta, add it to /etc/hosts and browse it directly.")
    print("2) If only Joomla paths appear, current host is likely only stage-1 (CVE leak).")
    print("3) Next foothold usually requires discovering custom/internal service endpoint.")


if __name__ == "__main__":
    main()
