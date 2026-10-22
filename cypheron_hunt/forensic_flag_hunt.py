import torch
import numpy as np
import os
import sys
import re
import base64
import binascii
import itertools
import zlib
import bz2
import lzma
import gzip
import codecs
import struct
from collections.abc import Mapping, Sequence

FLAG_PAT = re.compile(rb"THM\{[^}]{5,100}\}")
FLAG_FRAG_PAT = re.compile(rb"THM|\{|\}")

# --- Helper Decoders ---
def try_decoders(data):
    results = set()
    decoders = [
        lambda b: base64.b64decode(b, validate=True),
        binascii.unhexlify,
        zlib.decompress,
        bz2.decompress,
        lzma.decompress,
        gzip.decompress,
        codecs.decode,
        lambda b: codecs.decode(b, 'rot_13'),
        lambda b: base64.b32decode(b, casefold=True),
        lambda b: base64.b85decode(b),
        lambda b: codecs.decode(b, 'uu'),
    ]
    for dec in decoders:
        try:
            out = dec(data)
            if isinstance(out, str):
                out = out.encode()
            results.add(out)
        except Exception:
            continue
    return results

# --- Binary Extraction ---
def extract_strings_from_file(path, minlen=4):
    with open(path, 'rb') as f:
        data = f.read()
    result = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        result.add(match.group(0))
    return result, data

def find_flag_fragments(data):
    return [m.group(0) for m in FLAG_FRAG_PAT.finditer(data)]

# --- Model Analysis ---
def scan_obj(obj, found, path=None):
    if path is None:
        path = []
    # Direct bytes/str
    if isinstance(obj, (bytes, bytearray)):
        for flag in FLAG_PAT.findall(obj):
            found.add(flag)
        # Try decoders
        for dec in try_decoders(obj):
            for flag in FLAG_PAT.findall(dec):
                found.add(flag)
    elif isinstance(obj, str):
        for flag in FLAG_PAT.findall(obj.encode()):
            found.add(flag)
        for dec in try_decoders(obj.encode()):
            for flag in FLAG_PAT.findall(dec):
                found.add(flag)
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            scan_obj(k, found, path+['k'])
            scan_obj(v, found, path+['v'])
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        for i, v in enumerate(obj):
            scan_obj(v, found, path+[str(i)])
    elif hasattr(obj, '__dict__'):
        for k, v in vars(obj).items():
            scan_obj(k, found, path+['d'])
            scan_obj(v, found, path+['d'])
    # Numpy/tensor
    elif hasattr(obj, 'numpy'):
        arr = obj.numpy()
        scan_obj(arr, found, path+['tensor'])
    elif isinstance(obj, np.ndarray):
        scan_obj(obj.tobytes(), found, path+['ndarray'])

# --- Custom Code/Reduce/Setstate ---
def scan_custom_code(obj, found):
    attrs = ['__reduce__', '__setstate__', '__getstate__', '__call__', 'forward', '__dict__']
    for attr in attrs:
        if hasattr(obj, attr):
            val = getattr(obj, attr)
            if callable(val):
                try:
                    code = val.__code__
                    co_consts = getattr(code, 'co_consts', [])
                    for c in co_consts:
                        scan_obj(c, found)
                except Exception:
                    continue
            else:
                scan_obj(val, found)
    # Hooks
    for hook in ['_forward_hooks', '_backward_hooks', '_forward_pre_hooks']:
        if hasattr(obj, hook):
            scan_obj(getattr(obj, hook), found)

# --- Dynamic Execution ---
def try_dynamic(model, found):
    import random
    try:
        for _ in range(10):
            # Try random input shapes
            x = np.random.randn(random.randint(1, 8), random.randint(1, 8)).astype(np.float32)
            try:
                out = model(torch.from_numpy(x))
                scan_obj(out, found)
            except Exception:
                continue
    except Exception:
        pass

# --- Main ---
def main():
    model_path = sys.argv[1] if len(sys.argv) > 1 else 'model.pt'
    print(f"[i] Loading model: {model_path}")
    found = set()
    # Binary scan
    strings, data = extract_strings_from_file(model_path)
    print(f"[i] Extracted {len(strings)} ASCII strings from binary")
    for s in strings:
        for flag in FLAG_PAT.findall(s):
            found.add(flag)
        for dec in try_decoders(s):
            for flag in FLAG_PAT.findall(dec):
                found.add(flag)
    # Fragments
    frags = find_flag_fragments(data)
    if frags:
        print(f"[i] Found flag fragments in binary: {frags}")
    # Model load
    model = torch.load(model_path, map_location='cpu', weights_only=False)
    scan_obj(model, found)
    scan_custom_code(model, found)
    # Try dynamic execution if callable
    if callable(model):
        try_dynamic(model, found)
    print("[+] Flags found:")
    for f in found:
        print(f.decode(errors='replace'))
    if not found:
        print("[!] No flags found.")

if __name__ == "__main__":
    main()
