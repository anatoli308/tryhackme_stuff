import glob
import pathlib
import re

for p in sorted(glob.glob("artifacts/leak_*.bin")):
    text = pathlib.Path(p).read_bytes().decode("latin1", "ignore")
    if '"key"' not in text:
        continue

    print("\n###", pathlib.Path(p).name)

    # Try a strict JSON-ish capture first
    for m in re.finditer(r'"key"\s*:\s*"([^"]{6,200})"', text, re.IGNORECASE):
        print("strict:", m.group(1))

    # Then a fuzzy local window around key
    for m in re.finditer(r'"key"\s*:\s*"', text, re.IGNORECASE):
        s = m.end()
        window = text[s:s+180]
        print("fuzzy-window:", window.replace("\r", " ").replace("\n", " "))
        # keep only b64 chars and punctuation to inspect corruption
        cleaned = re.sub(r'[^A-Za-z0-9+/=,._-]', '', window)
        print("cleaned:", cleaned)
        break
