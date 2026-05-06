import base64
import re
import subprocess
from pathlib import Path

from Crypto.Cipher import AES

keys = [
    "bDRkNUliRGNpUFlZRmR6RE1VZXpOSkkxWFUxa3dSTkRlQVhIai45ZGlMVFhFSGJQN1U2c01GWlZscUVrY19jVw==",
    "OVB0Vy4ua3FBZnZoMThmM3g1dGFxOHVVdXFfanNCa1hLQ1pPUFZCTTJQUk9fWFN1ZlliRS5fZXBRSDU4aUVmZA==",
]

enc = Path("Database.carp").read_bytes()
nonce, ct, tag = enc[:12], enc[12:-16], enc[-16:]

print("[+] AES direct tests")
for i, k in enumerate(keys, 1):
    raw = base64.b64decode(k)
    key16 = raw[:16]
    try:
        pt = AES.new(key16, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        out = Path(f"artifacts/aes_decrypted_{i}.bin")
        out.write_bytes(pt)
        print("SUCCESS", i, "len", len(pt), out)
        txt = pt.decode("utf-8", "ignore")
        print("flags", re.findall(r"THM\{[^}]{1,200}\}", txt, re.I))
    except Exception as e:
        print("FAIL", i, type(e).__name__)

print("\n[+] decrypt_win_amd64.exe tests")
exe = Path("decrypt_win_amd64.exe")
if exe.exists():
    for i, k in enumerate(keys, 1):
        outbase = f"outkey{i}.kdbx"
        # Based on RE: program expects 3 user args after binary
        # candidate order: <input> <outputBase> <base64key>
        cmd = [str(exe), "Database.carp", outbase, k]
        r = subprocess.run(cmd, capture_output=True, text=True)
        print("CMD", cmd)
        print("RC", r.returncode)
        if r.stdout.strip():
            print("STDOUT", r.stdout.strip())
        if r.stderr.strip():
            print("STDERR", r.stderr.strip())

        outp = Path(outbase + ".decrypt")
        if outp.exists():
            print("OUTPUT", outp, outp.stat().st_size)
else:
    print("decrypt_win_amd64.exe not found")
