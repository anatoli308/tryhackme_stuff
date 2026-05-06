import base64
import itertools
import re
from pathlib import Path

from Crypto.Cipher import AES

raw_keys = [
    "bDRkNUliRGNpUFlZRmR6RE1VZXpOSkkxWFUxa3dSTkRlQVhIai45ZGlMVFhFSGJQN1U2c01GWlZscUVrY19jVw==",
    "OVB0Vy4ua3FBZnZoMThmM3g1dGFxOHVVdXFfanNCa1hLQ1pPUFZCTTJQUk9fWFN1ZlliRS5fZXBRSDU4aUVmZA==",
]

enc = Path("Database.carp").read_bytes()
nonce, ct, tag = enc[:12], enc[12:-16], enc[-16:]

replace_opts = {
    ".": ["+", "/"],
    "_": ["+", "/"],
    "-": ["+", "/"],
}


def generate(s: str):
    positions = []
    chars = list(s)
    for i, ch in enumerate(chars):
        if ch in replace_opts:
            positions.append(i)

    if not positions:
        yield s
        return

    options = [replace_opts[chars[i]] for i in positions]
    for combo in itertools.product(*options):
        out = chars[:]
        for pos, repl in zip(positions, combo):
            out[pos] = repl
        yield "".join(out)


def try_decrypt(k: str):
    try:
        raw = base64.b64decode(k, validate=True)
    except Exception:
        return False, b""
    if len(raw) < 16:
        return False, b""

    key16 = raw[:16]
    try:
        pt = AES.new(key16, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        return True, pt
    except Exception:
        return False, b""


tries = 0
for idx, rk in enumerate(raw_keys, 1):
    for cand in generate(rk):
        tries += 1
        ok, pt = try_decrypt(cand)
        if ok:
            out = Path(f"artifacts/recovered_decrypt_key{idx}.bin")
            out.write_bytes(pt)
            print("SUCCESS key", idx)
            print("candidate", cand)
            txt = pt.decode("utf-8", "ignore")
            flags = re.findall(r"THM\{[^}]{1,200}\}", txt, re.I)
            print("flags", sorted(set(flags)))
            raise SystemExit(0)

print("no success, tries", tries)
