#!/usr/bin/env python3
"""
Phase 4: RSA - Public Key finden + Algorithm Confusion Angriff
"""
import re, requests

TARGET = "http://10.113.167.230:5000"
s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

# 1. Mögliche Key/API Endpoints scannen
print("--- Endpoint Scan ---")
endpoints = [
    "/public_key", "/key", "/keys", "/.well-known/jwks.json",
    "/api/key", "/api/public_key", "/static/key.pem", "/static/public.pem",
    "/admin", "/admin/key", "/debug", "/source", "/config",
    "/api", "/api/v1", "/health", "/info", "/status",
    "/.env", "/app.py", "/main.py", "/server.py",
    "/robots.txt", "/sitemap.xml",
]
for ep in endpoints:
    r = s.get(f"{TARGET}{ep}")
    if r.status_code != 404:
        print(f"  {ep} → HTTP {r.status_code} | {r.text[:150]}")

# 2. /compose mit allen möglichen Feldern
print("\n--- POST /compose (alle Felder) ---")
r = s.post(f"{TARGET}/compose", data={
    "subject": "Test", "message": "hello", "recipient": "admin",
    "to": "admin", "from": "admin", "content": "hello"
})
print(f"HTTP {r.status_code}")
flashes = re.findall(r'class="flash[^"]*"[^>]*>\s*(.+?)\s*</div>', r.text, re.DOTALL)
for f in flashes:
    clean = re.sub(r'<[^>]+>', '', f).strip()
    print(f"Flash: {clean[:200]}")

# Signatur in Response suchen
sigs = re.findall(r'[0-9a-f]{64,}', r.text)
print(f"Hex sigs gefunden: {len(sigs)}")
for sig in sigs[:3]:
    print(f"  {sig[:80]}")

# PEM blocks suchen
pem = re.findall(r'-----BEGIN[^-]+-----[^-]+-----END[^-]+-----', r.text)
print(f"PEM blocks: {pem}")

print("\n--- Response (4000-7000) ---")
print(r.text[4000:7000])
