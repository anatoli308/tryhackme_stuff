import torch
import numpy as np
import base64
import re
import os
from itertools import product

def print_header(msg):
    print("\n" + "="*60)
    print(msg)
    print("="*60)

def xor_all_keys(data, flag_prefix=b'THM{'):
    # Try all 1-byte XOR keys
    for key in range(1, 256):
        xored = bytes([b ^ key for b in data])
        if flag_prefix in xored:
            idx = xored.find(flag_prefix)
            end = xored.find(b'}', idx)
            if end != -1:
                try:
                    print(f"[XOR key={key}] Found: {xored[idx:end+1].decode(errors='ignore')}")
                except Exception:
                    continue

def search_utf16(data):
    # Try to decode as UTF-16 and search for flag
    try:
        s = data.decode('utf-16', errors='ignore')
        m = re.search(r'THM\{.*?\}', s)
        if m:
            print(f"[UTF-16] Found: {m.group(0)}")
    except Exception:
        pass

def search_fragments_across_tensors(tensor_bytes_list, min_len=3):
    # Try to find flag fragments that could be joined
    fragments = []
    for idx, b in enumerate(tensor_bytes_list):
        ascii_str = ''.join([chr(x) if 32 <= x < 127 else '.' for x in b])
        for m in re.finditer(r'THM\{[A-Za-z0-9_]{%d,}' % min_len, ascii_str):
            fragments.append((idx, m.group(0)))
    if len(fragments) > 1:
        print("[FRAGMENTS ACROSS TENSORS]")
        for idx, frag in fragments:
            print(f"  Tensor {idx}: {frag}")
        # Try to join fragments
        joined = ''.join(f[1] for f in fragments)
        if 'THM{' in joined and '}' in joined:
            flag = joined[joined.find('THM{'):joined.find('}')+1]
            print(f"[JOINED FRAGMENTS] {flag}")

def search_model_metadata(model):
    print_header("Searching model metadata for flag-like strings")
    for k, v in model.items():
        if isinstance(v, str):
            if 'THM{' in v:
                print(f"[META] Key: {k} | Value: {v}")
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str) and 'THM{' in item:
                    print(f"[META] Key: {k} | Value: {item}")
        elif isinstance(v, dict):
            for subk, subv in v.items():
                if isinstance(subv, str) and 'THM{' in subv:
                    print(f"[META] Key: {k}.{subk} | Value: {subv}")

def main():
    pt_path = "signal-classifier-1778659286018.pt"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, pt_path)
    print_header(f"Brute flag hunt: {model_path}")
    try:
        model = torch.load(model_path, map_location="cpu", weights_only=False)
        state_dict = model.get('state_dict')
        tensor_bytes_list = []
        if state_dict:
            print_header("Brute tensor search in state_dict")
            for k, v in state_dict.items():
                arr = None
                if hasattr(v, 'tobytes'):
                    arr = v
                elif hasattr(v, 'cpu') and hasattr(v, 'numpy'):
                    arr = v.cpu().numpy()
                if arr is not None:
                    b = arr.tobytes()
                    tensor_bytes_list.append(b)
                    xor_all_keys(b)
                    search_utf16(b)
            search_fragments_across_tensors(tensor_bytes_list)
        else:
            print("[!] No state_dict found in model.")
        # Also check feature_mean and feature_std
        for arr_name in ['feature_mean', 'feature_std']:
            arr = model.get(arr_name)
            if arr is not None:
                b = arr.tobytes() if hasattr(arr, 'tobytes') else arr
                xor_all_keys(b)
                search_utf16(b)
        search_model_metadata(model)
    except Exception as e:
        print(f"[!] Error loading model: {e}")

if __name__ == "__main__":
    main()
