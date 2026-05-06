import requests
import re

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# /console is a custom app route (400 = needs specific params)
# When __debugger__=yes is added, Werkzeug middleware intercepts -> 404
# So /console is the APP's route. Let's figure out what it needs.

print("=== /console parameter discovery ===")

# Try various common console parameters
params = [
    {"cmd": "ls"},
    {"command": "ls"},
    {"code": "print('test')"},
    {"exec": "print('test')"},
    {"input": "test"},
    {"query": "test"},
    {"q": "test"},
    {"script": "test"},
    {"expression": "1+1"},
    {"eval": "1+1"},
    {"run": "test"},
    {"password": "cupid_arrow_2026!!!"},
    {"pin": "cupid_arrow_2026!!!"},
    {"key": "cupid_arrow_2026!!!"},
    {"secret": "cupid_arrow_2026!!!"},
    {"token": "cupid_arrow_2026!!!"},
    {"auth": "cupid_arrow_2026!!!"},
    {"access": "cupid_arrow_2026!!!"},
    {"unlock": "cupid_arrow_2026!!!"},
    {"passphrase": "cupid_arrow_2026!!!"},
]

for p in params:
    r = s.get(f"{BASE}/console", params=p, timeout=5)
    if r.status_code != 400 and r.status_code != 404:
        print(f"  GET /console?{p} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")
    else:
        # Check if body changed from default 400
        if r.status_code == 400 and len(r.text) != 167:
            print(f"  GET /console?{p} -> 400 but different body ({len(r.text)} bytes)")
            print(f"    {r.text[:300]}")

# Try POST with various params
print("\n=== POST /console ===")
for p in params:
    r = s.post(f"{BASE}/console", data=p, timeout=5)
    if r.status_code != 400 and r.status_code != 404 and r.status_code != 405:
        print(f"  POST /console {p} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# Try JSON POST
print("\n=== JSON POST /console ===")
for p in params:
    r = s.post(f"{BASE}/console", json=p, timeout=5)
    if r.status_code != 400 and r.status_code != 404 and r.status_code != 405:
        print(f"  JSON POST /console {p} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
        for f in FLAG_RE.findall(r.text):
            print(f"    [FLAG] {f}")

# Try with Authorization header
print("\n=== /console with auth headers ===")
auth_headers = [
    {"Authorization": f"Bearer cupid_arrow_2026!!!"},
    {"Authorization": f"Basic Y3VwaWQ6Y3VwaWRfYXJyb3dfMjAyNiEhIQ=="},  # cupid:cupid_arrow_2026!!!
    {"X-Api-Key": "cupid_arrow_2026!!!"},
    {"X-Token": "cupid_arrow_2026!!!"},
    {"X-Secret": "cupid_arrow_2026!!!"},
    {"X-Access-Key": "cupid_arrow_2026!!!"},
    {"Cookie": "session=cupid_arrow_2026!!!"},
    {"Cookie": "token=cupid_arrow_2026!!!"},
    {"Cookie": "auth=cupid_arrow_2026!!!"},
]
for h in auth_headers:
    r = s.get(f"{BASE}/console", headers=h, timeout=5)
    if r.status_code != 400:
        print(f"  {h} -> {r.status_code} ({len(r.text)} bytes)")
        print(f"    {r.text[:300]}")
    elif len(r.text) != 167:
        print(f"  {h} -> 400 but different body ({len(r.text)} bytes)")

# Maybe /console needs a specific content type
print("\n=== /console with content types ===")
cts = [
    "application/json",
    "application/x-www-form-urlencoded", 
    "text/plain",
    "text/html",
    "application/xml",
    "multipart/form-data",
]
for ct in cts:
    r = s.get(f"{BASE}/console", headers={"Content-Type": ct}, timeout=5)
    if r.status_code != 400:
        print(f"  Content-Type: {ct} -> {r.status_code}")
    elif len(r.text) != 167:
        print(f"  Content-Type: {ct} -> 400 but different ({len(r.text)} bytes)")

# Try raw connection to /console to see if it's about request format
print("\n=== Raw HTTP to /console ===")
import socket

def raw_request(method, path, headers=None, body=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("10.114.139.59", 5000))
    
    req = f"{method} {path} HTTP/1.1\r\nHost: 10.114.139.59:5000\r\n"
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    if body:
        req += f"Content-Length: {len(body)}\r\n"
    req += "\r\n"
    if body:
        req += body
    
    sock.send(req.encode())
    response = b""
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
    except:
        pass
    sock.close()
    return response.decode('utf-8', errors='replace')

# HTTP/1.0
print("  HTTP/1.0 GET /console:")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("10.114.139.59", 5000))
sock.send(b"GET /console HTTP/1.0\r\nHost: 10.114.139.59:5000\r\n\r\n")
resp = b""
try:
    while True:
        data = sock.recv(4096)
        if not data:
            break
        resp += data
except:
    pass
sock.close()
print(f"    {resp[:500].decode('utf-8', errors='replace')}")

# Maybe it needs a specific Host header
print("\n  With Host: localhost:")
resp = raw_request("GET", "/console", {"Host": "localhost:5000"})
print(f"    {resp[:500]}")

# Maybe accept header matters
print("\n  With Accept: application/json:")
resp = raw_request("GET", "/console", {
    "Host": "10.114.139.59:5000",
    "Accept": "application/json"
})
print(f"    {resp[:500]}")

# Maybe the route is /console/<something>
print("\n=== /console/ subpaths ===")
subpaths = [
    "/console/", "/console/exec", "/console/run", "/console/eval",
    "/console/shell", "/console/cmd", "/console/command",
    "/console/login", "/console/auth", "/console/unlock",
    "/console/python", "/console/interactive",
    "/console/cupid_arrow_2026!!!",
    "/console/api", "/console/v1",
]
for p in subpaths:
    try:
        r = s.get(f"{BASE}{p}", timeout=5)
        if r.status_code != 404:
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes)")
            if r.status_code != 400 or len(r.text) != 167:
                print(f"    {r.text[:200]}")
    except:
        pass

# Now let's try a different approach entirely
# Maybe there are routes we haven't tried - API routes, webhook-style
print("\n=== API-style endpoints ===")
api_paths = [
    "/api", "/api/", "/api/v1", "/api/v1/",
    "/api/letters", "/api/messages", "/api/notes",
    "/api/vault", "/api/secret", "/api/console",
    "/api/admin", "/api/user", "/api/auth",
    "/api/flag", "/api/love", "/api/cupid",
    "/api/fetch_layout", "/api/render",
    "/api/export", "/api/import", "/api/backup",
    "/v1/", "/v2/",
    "/graphql", "/graphql/",
    "/webhook", "/callback",
    "/internal", "/internal/",
    "/private", "/private/",
    "/hidden", "/hidden/",
    "/secret", "/secret/",
    "/love", "/love/",
    "/valentine", "/valentine/",
    "/arrow", "/arrow/",
    "/cupid", "/cupid/",
    "/heart", "/heart/",
    "/letter", "/letter/",
    "/letters", "/letters/",
    "/message", "/message/",
    "/messages", "/messages/",
    "/note", "/note/",
    "/notes", "/notes/",
    "/board", "/board/",
    "/wall", "/wall/",
    "/post", "/post/",
    "/submit", "/submit/",
    "/send", "/send/",
    "/anonymous", "/anonymous/",
]
for p in api_paths:
    try:
        r = s.get(f"{BASE}{p}", timeout=3, allow_redirects=False)
        if r.status_code not in [404]:
            print(f"  {p} -> {r.status_code} ({len(r.text)} bytes)")
            if r.status_code not in [301, 308] and len(r.text) < 500:
                print(f"    {r.text[:200]}")
    except:
        pass

print("\nDone.")
