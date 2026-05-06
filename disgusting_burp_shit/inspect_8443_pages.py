#!/usr/bin/env python3
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base = "https://10.81.188.92:8443"
paths = ["/", "/authenticate", "/login"]

for p in paths:
    print(f"\n=== {p} ===")
    try:
        r = requests.get(base + p, timeout=5, verify=False)
        print(f"HTTP {r.status_code}")
        print(r.text[:1200])
        scripts = re.findall(r"<script[^>]*src=[\"']([^\"']+)", r.text, flags=re.IGNORECASE)
        print("scripts:", scripts[:10])
    except Exception as exc:
        print("ERR", exc)
