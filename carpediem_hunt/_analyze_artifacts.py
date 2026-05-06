import glob
import pathlib
import re

kws = ("key", "decrypt", "wallet", "proof", "THM{", "flag", "master", "keepass", "kdbx")

for p in sorted(glob.glob("artifacts/*")):
    data = pathlib.Path(p).read_bytes()
    text = data.decode("latin1", "ignore")
    hits = [k for k in kws if k.lower() in text.lower()]
    flags = re.findall(r"THM\{[^}]{1,200}\}", text, re.IGNORECASE)
    if hits or flags:
        print(pathlib.Path(p).name, "len", len(data), "hits", hits)
    if flags:
        print("  FLAGS:", flags)
