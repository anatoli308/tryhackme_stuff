import requests, re

BASE = "http://10.112.165.127:5000"
COOKIE = "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw"

s = requests.Session()
s.cookies.set("session", COOKIE)

for page in ["/dashboard", "/profile/cupid", "/my_profile"]:
    print(f"\n=== {page} ===")
    r = s.get(f"{BASE}{page}", timeout=10, allow_redirects=True)
    print(f"Status: {r.status_code}, Length: {len(r.text)}, URL: {r.url}")
    for m in re.finditer(r"<form[^>]*>", r.text, re.I):
        print(f"  FORM: {m.group(0)[:200]}")
    for m in re.finditer(r"<button[^>]*>.*?</button>", r.text, re.I | re.S):
        print(f"  BUTTON: {m.group(0)[:200]}")
    for m in re.finditer(r"<input[^>]*>", r.text, re.I):
        print(f"  INPUT: {m.group(0)[:200]}")
    for m in re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I):
        print(f"  HREF: {m}")
    for m in re.findall(r'action=["\']([^"\']+)["\']', r.text, re.I):
        print(f"  ACTION: {m}")
    text = re.sub(r"<[^>]+>", " ", r.text)
    text = re.sub(r"\s+", " ", text).strip()
    print(f"  TEXT: {text[:800]}")

# Try register to see the form
print("\n=== /register GET ===")
r = s.get(f"{BASE}/register", timeout=10)
print(f"Status: {r.status_code}")
for m in re.finditer(r"<input[^>]*>", r.text, re.I):
    print(f"  INPUT: {m.group(0)[:200]}")
for m in re.findall(r'action=["\']([^"\']+)["\']', r.text, re.I):
    print(f"  ACTION: {m}")

# Try different like formats
print("\n=== Like attempts ===")
for path in ["/like/cupid", "/like/8", "/swipe/8", "/swipe/cupid",
             "/match/cupid", "/send_like/cupid", "/heart/cupid",
             "/api/like/8", "/api/like/cupid"]:
    try:
        r = s.post(f"{BASE}{path}", timeout=5)
        print(f"  POST {path} -> {r.status_code}")
    except:
        print(f"  POST {path} -> error")
    try:
        r = s.get(f"{BASE}{path}", timeout=5)
        if r.status_code != 404:
            print(f"  GET  {path} -> {r.status_code}")
    except:
        pass
