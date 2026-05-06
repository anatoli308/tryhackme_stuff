import base64

keys = [
    "bDRkNUliRGNpUFlZRmR6RE1VZXpOSkkxWFUxa3dSTkRlQVhIai45ZGlMVFhFSGJQN1U2c01GWlZscUVrY19jVw==",
    "OVB0Vy4ua3FBZnZoMThmM3g1dGFxOHVVdXFfanNCa1hLQ1pPUFZCTTJQUk9fWFN1ZlliRS5fZXBRSDU4aUVmZA==",
]
A = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

for k in keys:
    bad = sorted(set(ch for ch in k if ch not in A))
    print(k)
    print("bad chars:", bad)
    try:
        d1 = base64.b64decode(k, validate=True)
        print("std decode len", len(d1))
    except Exception as e:
        print("std decode err", type(e).__name__, e)
    try:
        d2 = base64.b64decode(k, altchars=b"-_", validate=False)
        print("url decode len", len(d2))
    except Exception as e:
        print("url decode err", type(e).__name__, e)
    print()
