import pathlib
import re

path = pathlib.Path("artifacts/leak_0_96_60000.bin")
text = path.read_bytes().decode("latin1", "ignore")

patterns = [
    r"x-hasura-admin-secret.{0,120}",
    r"http://[^\s\"']+/v1/graphql/?",
    r"key.{0,120}",
    r"wallet.{0,120}",
    r"[A-Za-z0-9+/]{20,120}={0,2}",
]

for pat in patterns:
    print("\n===", pat, "===")
    seen = 0
    for m in re.finditer(pat, text, re.IGNORECASE):
        s = max(0, m.start() - 80)
        e = min(len(text), m.end() + 80)
        print(text[s:e].replace("\r", " ").replace("\n", " "))
        seen += 1
        if seen >= 8:
            break
    if seen == 0:
        print("(none)")
