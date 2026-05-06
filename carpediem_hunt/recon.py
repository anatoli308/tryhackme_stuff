"""Fast async recon for Carpe Diem ransomware challenge.

Goals:
- Enumerate hidden routes / common files
- Test /proof for GraphQL injection in `proof` field
- Test the user's hypothesis: real wallet is checked against backend GraphQL
"""
from __future__ import annotations

import asyncio
import re

import httpx

BASE = "http://10.113.168.120"
HOST = "c4rp3d13m.net"
HEADERS = {"Host": HOST, "Content-Type": "application/json"}


WORDLIST = [
    # Static / typical
    "robots.txt", "sitemap.xml", "favicon.ico",
    "stylesheets/style.css", "stylesheets/", "javascripts/", "images/",
    # API / app
    "api", "api/", "api/proof", "api/key", "api/decrypt", "api/payments",
    "decrypt", "key", "keys", "flag", "flags", "admin", "admin/",
    "proof", "proofs", "wallet", "wallets", "payment", "payments",
    "status", "health", "version",
    # Source leak
    ".git/config", ".env", ".env.local", "package.json", "package-lock.json",
    "server.js", "app.js", "index.js", "routes.js", "config.js",
    "src/", "src/index.js", "src/server.js", "src/routes/",
    # Hasura passthrough attempts
    "v1/graphql", "v1/graphql/", "graphql", "graphiql", "console",
    "v1/version", "v1/metadata", "healthz",
]


async def probe_route(client: httpx.AsyncClient, path: str) -> tuple[str, int, int, str]:
    try:
        r = await client.get(f"/{path}", timeout=10)
        return path, r.status_code, len(r.content), r.headers.get("content-type", "")
    except Exception as e:
        return path, -1, 0, str(e)[:40]


async def main() -> None:
    async with httpx.AsyncClient(base_url=BASE, headers=HEADERS, follow_redirects=False) as client:
        print("=== route enumeration ===")
        results = await asyncio.gather(*(probe_route(client, p) for p in WORDLIST))
        for path, sc, sz, ct in sorted(results, key=lambda x: (x[1], x[0])):
            if sc == 404 and sz == 152:
                continue  # standard 404 noise
            print(f"  {sc:>4} {sz:>7}  /{path}  ({ct})")


if __name__ == "__main__":
    asyncio.run(main())
