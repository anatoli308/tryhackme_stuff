import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# 1) The secret vault from robots.txt
print("=== /cupids_secret_vault/ ===")
r = s.get(f"{BASE}/cupids_secret_vault/", timeout=10)
print(f"Status: {r.status_code}, Length: {len(r.text)}")
print(r.text[:2000])
for f in FLAG_RE.findall(r.text):
    print(f"[FLAG] {f}")

# Sub-paths in the vault
print("\n=== Vault sub-paths ===")
vault_paths = [
    "/cupids_secret_vault",
    "/cupids_secret_vault/flag",
    "/cupids_secret_vault/flag.txt",
    "/cupids_secret_vault/admin",
    "/cupids_secret_vault/login",
    "/cupids_secret_vault/secret",
    "/cupids_secret_vault/letters",
    "/cupids_secret_vault/messages",
    "/cupids_secret_vault/dashboard",
    "/cupids_secret_vault/config",
    "/cupids_secret_vault/api",
    "/cupids_secret_vault/key",
    "/cupids_secret_vault/cupid",
    "/cupids_secret_vault/index",
    "/cupids_secret_vault/index.html",
]
for p in vault_paths:
    try:
        r = s.get(f"{BASE}{p}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            loc = r.headers.get("Location", "")
            body = r.text[:150].replace("\n", " ")
            print(f"  {p} -> {r.status_code} loc={loc} | {body}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass

# 2) Try vault with the password from robots.txt as auth
print("\n=== Vault with auth ===")
password = "cupid_arrow_2026!!!"
for p in ["/cupids_secret_vault/", "/cupids_secret_vault/login"]:
    # Basic auth
    r = requests.get(f"{BASE}{p}", auth=("cupid", password), timeout=5)
    if r.status_code != 404:
        print(f"  BasicAuth {p} -> {r.status_code} ({len(r.text)} bytes)")
    # POST with password
    r = s.post(f"{BASE}{p}", data={"password": password, "key": password, "secret": password}, timeout=5)
    if r.status_code != 404:
        print(f"  POST {p} -> {r.status_code} ({len(r.text)} bytes) | {r.text[:200]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")
    # Header auth
    r = s.get(f"{BASE}{p}", headers={"Authorization": f"Bearer {password}", "X-API-Key": password}, timeout=5)
    if r.status_code != 404:
        print(f"  Header {p} -> {r.status_code} ({len(r.text)} bytes)")

# 3) Check all links/forms on vault page
print("\n=== Vault page analysis ===")
r = s.get(f"{BASE}/cupids_secret_vault/", timeout=10)
for m in re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  HREF: {m}")
for m in re.findall(r'action=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  ACTION: {m}")
for m in re.finditer(r"<form[^>]*>", r.text, re.I):
    print(f"  FORM: {m.group(0)[:200]}")
for m in re.finditer(r"<input[^>]*>", r.text, re.I):
    print(f"  INPUT: {m.group(0)[:200]}")
for m in re.finditer(r"<script[^>]*>.*?</script>", r.text, re.I | re.S):
    print(f"  SCRIPT: {m.group(0)[:500]}")
text = re.sub(r"<[^>]+>", " ", r.text)
text = re.sub(r"\s+", " ", text).strip()
print(f"  TEXT: {text[:800]}")

# 4) Werkzeug console - try with PIN from robots.txt hint
print("\n=== Werkzeug Console ===")
r = s.get(f"{BASE}/console", timeout=5)
print(f"  GET /console -> {r.status_code} ({len(r.text)} bytes)")
print(f"  {r.text[:300]}")

# 5) More endpoint enum based on "Love Letters" theme
print("\n=== Theme-based endpoints ===")
more = [
    "/letter", "/letters", "/love", "/message", "/messages",
    "/send", "/write", "/compose", "/read", "/inbox",
    "/post", "/submit", "/api/letters", "/api/messages",
    "/api/love", "/board", "/wall", "/anonymous",
    "/valentine", "/cupid", "/arrow",
]
for ep in more:
    try:
        r = s.get(f"{BASE}{ep}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            body = r.text[:100].replace("\n", " ")
            print(f"  {ep} -> {r.status_code} ({len(r.text)} bytes) | {body}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass
