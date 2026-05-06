import base64
import glob
import pathlib
import re

from Crypto.Cipher import AES

files = ["Database.carp", "Database_live.carp"]
encs = {}
for f in files:
    b = pathlib.Path(f).read_bytes()
    encs[f] = (b[:12], b[12:-16], b[-16:])

cands = set()
for p in glob.glob("artifacts/leak_*.bin"):
    t = pathlib.Path(p).read_bytes().decode("latin1", "ignore")
    # key field preferred
    for m in re.finditer(r'"key"\s*:\s*"([^"]{8,240})"', t, re.I):
        raw = m.group(1)
        clean = "".join(ch for ch in raw if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        if len(clean) >= 16:
            cands.add(clean)

    # generic base64-ish runs
    for m in re.finditer(r"[A-Za-z0-9+/]{24,200}={0,2}", t):
        cands.add(m.group(0))

print("candidate strings", len(cands))

tried = 0
for s in sorted(cands):
    tried += 1
    key_forms = []
    key_forms.append(s.encode()[:16])
    for pad in ("", "=", "==", "==="):
        try:
            d = base64.b64decode(s + pad, validate=False)
        except Exception:
            continue
        if len(d) >= 16:
            key_forms.append(d[:16])

    for key in key_forms:
        for name, (nonce, ct, tag) in encs.items():
            try:
                pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
                print("SUCCESS", name, "cand", s[:80], "key", key)
                out = pathlib.Path("artifacts") / f"decrypted_{name}.bin"
                out.write_bytes(pt)
                txt = pt.decode("utf-8", "ignore")
                flags = re.findall(r"THM\{[^}]{1,200}\}", txt, re.I)
                print("flags", sorted(set(flags)))
                raise SystemExit(0)
            except Exception:
                pass

print("tried", tried, "no success")
