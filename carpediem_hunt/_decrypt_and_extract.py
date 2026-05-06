import base64
import re
from pathlib import Path

from Crypto.Cipher import AES

KEY_B64 = "OVB0Vy4ua3FBZnZoMThmM3g1dGFxOHVVdXFfanNCa1hLQ1pPUFZCTTJQUk9fWFN1ZlliRS5fZXBRSDU4aUVmZA=="

enc = Path("Database.carp").read_bytes()
nonce, ct, tag = enc[:12], enc[12:-16], enc[-16:]
key = base64.b64decode(KEY_B64)[:16]

pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
Path("artifacts/database_decrypted.bin").write_bytes(pt)

text = pt.decode("utf-8", "ignore")
flags = sorted(set(re.findall(r"THM\{[^}]{1,200}\}", text, re.IGNORECASE)))

print("plaintext size", len(pt))
print("flags", flags)

# Print useful snippets if flags are not explicit.
if not flags:
    for pat in [r"flag\s*1[^\r\n]{0,120}", r"flag\s*2[^\r\n]{0,120}", r"password[^\r\n]{0,120}"]:
        print("\\nPATTERN", pat)
        for m in re.finditer(pat, text, re.IGNORECASE):
            s = max(0, m.start() - 80)
            e = min(len(text), m.end() + 80)
            print(text[s:e].replace("\n", " "))
