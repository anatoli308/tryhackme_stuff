import requests, re

BASE = "http://10.112.165.127:5000"

# Register fresh
import random, string
uname = "test_" + "".join(random.choices(string.ascii_lowercase, k=4))
s = requests.Session()
s.post(f"{BASE}/register", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)
s.post(f"{BASE}/login", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)

# Seed with unique markers to find rendering context
s.post(f"{BASE}/complete_profile", data={
    "real_name": "MARKER_NAME_<b>bold</b>_END",
    "email": "test@test.com",
    "phone": "123",
    "address": "MARKER_ADDR_<b>bold</b>_END",
    "bio": "MARKER_BIO_<b>bold</b>_END",
}, allow_redirects=False)

# Check how markers appear in /profile/{uname}
print(f"=== /profile/{uname} raw HTML ===")
r = s.get(f"{BASE}/profile/{uname}")
# Find each marker and show surrounding context
for field in ["NAME", "ADDR", "BIO"]:
    marker = f"MARKER_{field}_"
    idx = r.text.find(marker)
    if idx >= 0:
        snippet = r.text[max(0,idx-80):idx+120]
        has_raw_b = f"MARKER_{field}_<b>bold</b>_END" in r.text
        has_escaped = f"MARKER_{field}_&lt;b&gt;bold&lt;/b&gt;_END" in r.text
        print(f"\n  [{field}] raw_html={has_raw_b}, escaped={has_escaped}")
        print(f"  context: ...{snippet}...")
    else:
        print(f"\n  [{field}] NOT FOUND in profile page")

# Also check /my_profile
print(f"\n=== /my_profile raw HTML ===")
r2 = s.get(f"{BASE}/my_profile")
for field in ["NAME", "ADDR", "BIO"]:
    marker = f"MARKER_{field}_"
    idx = r2.text.find(marker)
    if idx >= 0:
        snippet = r2.text[max(0,idx-80):idx+120]
        has_raw = f"MARKER_{field}_<b>bold</b>_END" in r2.text
        has_escaped = f"MARKER_{field}_&lt;b&gt;" in r2.text
        print(f"\n  [{field}] raw_html={has_raw}, escaped={has_escaped}")
        print(f"  context: ...{snippet}...")
    else:
        print(f"\n  [{field}] NOT FOUND")

# Try /my_profile POST instead of /complete_profile
print(f"\n=== Try seeding via /my_profile POST ===")
s.post(f"{BASE}/my_profile", data={
    "real_name": "MARKER2_NAME_<b>bold2</b>_END",
    "email": "test@test.com",
    "phone": "123",
    "address": "MARKER2_ADDR_<b>bold2</b>_END",
    "bio": "MARKER2_BIO_<b>bold2</b>_END",
}, allow_redirects=False)

r3 = s.get(f"{BASE}/profile/{uname}")
for field in ["NAME", "ADDR", "BIO"]:
    marker = f"MARKER2_{field}_"
    idx = r3.text.find(marker)
    if idx >= 0:
        snippet = r3.text[max(0,idx-80):idx+120]
        has_raw = f"MARKER2_{field}_<b>bold2</b>_END" in r3.text
        has_escaped = f"MARKER2_{field}_&lt;b&gt;" in r3.text
        print(f"\n  [{field}] raw_html={has_raw}, escaped={has_escaped}")
        print(f"  context: ...{snippet}...")
    else:
        print(f"\n  [{field}] NOT FOUND")

print(f"\nUsername: {uname}")
