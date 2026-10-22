import torch
import numpy as np
import base64
import binascii
import itertools
import re

MODEL_PATH = "signal-classifier-1778659286018.pt"

FLAG_PATTERNS = [
    re.compile(rb"THM\{.*?\}", re.DOTALL),
    re.compile(rb"THM\[.*?\]", re.DOTALL),
]

# Decoders
CODECS = [
    ("ascii", lambda b: b.decode("ascii", errors="ignore")),
    ("utf-8", lambda b: b.decode("utf-8", errors="ignore")),
    ("base64", lambda b: base64.b64decode(b, validate=False)),
    ("hex", lambda b: binascii.unhexlify(b)),
    ("rot13", lambda b: b.decode("ascii", errors="ignore").translate(str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    )).encode("ascii", errors="ignore")),
    ("reverse", lambda b: b[::-1]),
]

# Try all combinations of decoders up to depth 2

def try_decoders(data):
    results = set()
    for depth in [1, 2]:
        for combo in itertools.product(CODECS, repeat=depth):
            try:
                val = data
                for name, fn in combo:
                    val = fn(val)
                results.add(val)
            except Exception:
                continue
    return results

def find_flags_bytes(data):
    found = set()
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(data):
            found.add(m.group().decode("ascii", errors="ignore"))
    return found

def scan_obj(obj, path=None, found=None):
    if found is None:
        found = set()
    if path is None:
        path = []
    # 1. Raw bytes
    if isinstance(obj, (bytes, bytearray)):
        # Direct
        found.update(find_flags_bytes(obj))
        # Decoders
        for decoded in try_decoders(obj):
            found.update(find_flags_bytes(decoded if isinstance(decoded, (bytes, bytearray)) else str(decoded).encode("utf-8", errors="ignore")))
    # 2. String
    elif isinstance(obj, str):
        found.update(find_flags_bytes(obj.encode("utf-8", errors="ignore")))
        for decoded in try_decoders(obj.encode("utf-8", errors="ignore")):
            found.update(find_flags_bytes(decoded if isinstance(decoded, (bytes, bytearray)) else str(decoded).encode("utf-8", errors="ignore")))
    # 3. Numpy array
    elif isinstance(obj, np.ndarray):
        try:
            flat = obj.tobytes()
            found.update(find_flags_bytes(flat))
            for decoded in try_decoders(flat):
                found.update(find_flags_bytes(decoded if isinstance(decoded, (bytes, bytearray)) else str(decoded).encode("utf-8", errors="ignore")))
        except Exception:
            pass
    # 4. Tensor
    elif hasattr(obj, "numpy"):
        try:
            arr = obj.numpy()
            flat = arr.tobytes()
            found.update(find_flags_bytes(flat))
            for decoded in try_decoders(flat):
                found.update(find_flags_bytes(decoded if isinstance(decoded, (bytes, bytearray)) else str(decoded).encode("utf-8", errors="ignore")))
        except Exception:
            pass
    # 5. Dict
    elif isinstance(obj, dict):
        for k, v in obj.items():
            scan_obj(k, path + ["key"], found)
            scan_obj(v, path + [str(k)], found)
    # 6. List/tuple
    elif isinstance(obj, (list, tuple, set)):
        for i, v in enumerate(obj):
            scan_obj(v, path + [str(i)], found)
    # 7. Object attributes
    elif hasattr(obj, "__dict__"):
        for k, v in vars(obj).items():
            scan_obj(k, path + ["attr"], found)
            scan_obj(v, path + [str(k)], found)
    return found

def main():
    print("[+] Loading model...")
    model = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
    print("[+] Scanning model recursively for flags...")
    found = scan_obj(model)
    print("[+] Flags found:")
    for f in sorted(found):
        print(f)

if __name__ == "__main__":
    main()
