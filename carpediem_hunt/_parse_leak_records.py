import glob
import pathlib
import re

key_pat = re.compile(r'"key"\s*:\s*"([^"]{20,240})"', re.I)
name_pat = re.compile(r'"name"\s*:\s*"([^"]{1,120})"', re.I)
file_pat = re.compile(r'"filename"\s*:\s*"([^"]{1,120})"', re.I)

for p in sorted(glob.glob("artifacts/leak_*.bin")):
    t = pathlib.Path(p).read_bytes().decode("latin1", "ignore")
    if '"key"' not in t:
        continue

    print("\n##", pathlib.Path(p).name)
    keys = key_pat.findall(t)
    names = name_pat.findall(t)
    files = file_pat.findall(t)

    if files:
        print("files:", files[:10])
    if names:
        print("names:", names[:10])
    print("keys:", len(keys))
    for k in keys[:10]:
        print("  ", k, "len", len(k))

# global search for database hints
print("\n=== database hints ===")
for p in sorted(glob.glob("artifacts/leak_*.bin")):
    t = pathlib.Path(p).read_bytes().decode("latin1", "ignore")
    if re.search(r"database|kdbx|kbxd|carp", t, re.I):
        print(pathlib.Path(p).name)
        for m in re.finditer(r".{0,80}(database|kdbx|kbxd|carp).{0,120}", t, re.I):
            s = m.group(0).replace("\r", " ").replace("\n", " ")
            print(" ", s)
            break
