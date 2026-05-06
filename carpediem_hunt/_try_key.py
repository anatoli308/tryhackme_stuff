import base64

from Crypto.Cipher import AES

enc = open("Database.carp", "rb").read()
nonce, ct, tag = enc[:12], enc[12:-16], enc[-16:]

raw = "OVB0Vy4uaThmM3g1dGFxOHVVd,8,ï¿½]ï¿½TJQUlliRS5fZXBRSDU4a,"
candidate = "".join(ch for ch in raw if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

print("candidate:", candidate)
print("len:", len(candidate))

for pad in ("", "=", "==", "==="):
    s = candidate + pad
    try:
        decoded = base64.b64decode(s, validate=False)
    except Exception:
        continue
    print("decoded len", len(decoded), "pad", repr(pad))
    if len(decoded) < 16:
        continue
    try:
        pt = AES.new(decoded[:16], AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        print("SUCCESS")
        print(pt[:300])
        break
    except Exception as e:
        print("fail", type(e).__name__)
