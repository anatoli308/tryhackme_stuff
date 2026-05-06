#!/usr/bin/env python3
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGETS = [
    ("http://10.81.188.92:80", True),
    ("https://10.81.188.92:8443", False),
]

CANDIDATE_PATHS = [
    "/authenticate",
    "/login",
    "/api/authenticate",
    "/api/login",
    "/register",
    "/process",
    "/flag",
    "/api/flag",
]


def extract_paths(html: str):
    links = sorted(set(re.findall(r"href=[\"']([^\"']+)", html, flags=re.IGNORECASE)))
    forms = sorted(set(re.findall(r"action=[\"']([^\"']+)", html, flags=re.IGNORECASE)))
    return links, forms


for base, verify in TARGETS:
    print(f"\n=== {base} ===")
    try:
        r = requests.get(base + "/", timeout=3, verify=verify)
    except Exception as exc:
        print(f"GET / -> error: {exc}")
        continue

    print(f"GET / -> HTTP {r.status_code} | Server: {r.headers.get('Server', '?')}")
    html = r.text
    links, forms = extract_paths(html)
    print(f"links: {links[:20]}")
    print(f"forms: {forms[:20]}")

    for path in CANDIDATE_PATHS:
        url = base + path
        try:
            rg = requests.get(url, timeout=2, verify=verify)
            rp = requests.post(url, data={"a": "1"}, timeout=2, verify=verify)
            print(f"{path:30} GET {rg.status_code:3} | POST {rp.status_code:3}")
        except Exception as exc:
            print(f"{path:30} ERR {str(exc)[:70]}")
