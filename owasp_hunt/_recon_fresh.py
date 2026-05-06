import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# Fresh eyes - dump EVERYTHING raw
print("=== RAW BYTES of /cupids_secret_vault/ ===")
r = s.get(f"{BASE}/cupids_secret_vault/", timeout=10)
raw = r.content
print(f"Content-Length header: {r.headers.get('Content-Length')}")
print(f"Actual bytes: {len(raw)}")
print(f"Hex dump (first 200 bytes):")
for i in range(0, min(200, len(raw)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in raw[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[i:i+16])
    print(f"  {i:04x}: {hex_part:<48} {ascii_part}")

print(f"\nHex dump (last 200 bytes):")
start = max(0, len(raw) - 200)
for i in range(start, len(raw), 16):
    hex_part = ' '.join(f'{b:02x}' for b in raw[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[i:i+16])
    print(f"  {i:04x}: {hex_part:<48} {ascii_part}")

# Check for zero-width chars, hidden unicode
print(f"\n=== Hidden Unicode check ===")
text = r.text
special_chars = []
for i, c in enumerate(text):
    if ord(c) > 127 or (ord(c) < 32 and c not in '\r\n\t'):
        special_chars.append((i, c, hex(ord(c))))
if special_chars:
    print(f"  Found {len(special_chars)} special chars:")
    for pos, ch, hexval in special_chars[:20]:
        context = text[max(0,pos-10):pos+10]
        print(f"    pos={pos} char={hexval} context=...{repr(context)}...")
else:
    print("  No special/hidden Unicode characters found")

# Check for CSS hidden content
print(f"\n=== CSS analysis ===")
# Look for display:none, visibility:hidden, opacity:0, color matching background
css_hidden = re.findall(r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:white|#fff)', text, re.IGNORECASE)
if css_hidden:
    print(f"  Hidden CSS found: {css_hidden}")
else:
    print("  No hidden CSS patterns")

# Full clean text dump
print(f"\n=== FULL TEXT of vault ===")
print(text)
print("=== END ===")

# Now check / (homepage) the same way
print(f"\n=== FULL TEXT of / ===")
r2 = s.get(f"{BASE}/", timeout=10)
print(r2.text)
print("=== END ===")

# Check for response headers we might have missed
print(f"\n=== ALL HEADERS from all endpoints ===")
for path in ["/", "/cupids_secret_vault/", "/robots.txt", "/console"]:
    r = s.get(f"{BASE}{path}", timeout=5)
    print(f"\n{path} ({r.status_code}):")
    for k, v in r.headers.items():
        print(f"  {k}: {v}")

# Maybe the challenge name gives a hint - check the TryHackMe room
# The robots.txt line: Disallow: /cupids_secret_vault/*  # cupid_arrow_2026!!!
# The * is a wildcard - maybe there's a specific file UNDER vault?

# Try common file names that would be in a "vault"
print(f"\n=== Vault file discovery ===")
vault_files = [
    "flag.txt", "secret.txt", "love_letter.txt", "letter.txt",
    "message.txt", "note.txt", "password.txt", "key.txt",
    "index.html", "index.htm", "default.html", "vault.html",
    "treasure.txt", "answer.txt", "hint.txt", "clue.txt",
    "README.md", "readme.txt", "README.txt",
    "data.json", "config.json", "secrets.json",
    "arrow.txt", "cupid.txt", "love.txt", "heart.txt",
    "flag", "secret", "key", "token",
    ".env", ".secret", ".flag", ".hidden",
    "admin.html", "login.html", "auth.html",
    "shell.php", "cmd.php", "backdoor.php",  # just in case
    "1", "2", "3",  # numeric
    "a", "b", "c",
    "test", "debug", "dev",
    "backup", "dump", "export",
    "anonymous", "valentine", "cupid_arrow",
    "cupid_arrow_2026", "arrow_2026",
]
for f in vault_files:
    try:
        r = s.get(f"{BASE}/cupids_secret_vault/{f}", timeout=3, allow_redirects=False)
        if r.status_code != 404:
            print(f"  /cupids_secret_vault/{f} -> {r.status_code} ({len(r.text)} bytes)")
            print(f"    {r.text[:200]}")
            for fl in FLAG_RE.findall(r.text):
                print(f"    [FLAG] {fl}")
    except:
        pass

# Maybe we need to use gobuster-style with .txt .html .py extensions
print(f"\n=== Extension fuzzing on common words ===")
words = ["flag", "secret", "love", "letter", "cupid", "arrow", "vault", 
         "key", "admin", "console", "debug", "hidden", "index", "main",
         "app", "config", "data", "message", "note", "anonymous",
         "valentine", "heart", "treasure", "password", "token"]
exts = ["", ".txt", ".html", ".json", ".py", ".php", ".xml", ".md", ".log", ".bak"]

for word in words:
    for ext in exts:
        path = f"/cupids_secret_vault/{word}{ext}"
        try:
            r = s.get(f"{BASE}{path}", timeout=2, allow_redirects=False)
            if r.status_code != 404:
                print(f"  {path} -> {r.status_code} ({len(r.text)} bytes)")
                for fl in FLAG_RE.findall(r.text):
                    print(f"    [FLAG] {fl}")
        except:
            pass

# Also try at root level
for word in words:
    for ext in exts:
        path = f"/{word}{ext}"
        try:
            r = s.get(f"{BASE}{path}", timeout=2, allow_redirects=False)
            if r.status_code != 404:
                if path not in ["/console"]:
                    print(f"  {path} -> {r.status_code} ({len(r.text)} bytes)")
        except:
            pass

print("\nDone.")
