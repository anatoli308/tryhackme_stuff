import torch
import numpy as np
import base64
import re
import os

# Aggressive CTF flag fragment and encoding search

def print_header(msg):
    print("\n" + "="*60)
    print(msg)
    print("="*60)

def find_flag_fragments(data, min_len=6):
    # Find all substrings that look like THM{...} fragments
    ascii_str = ''.join([chr(x) if 32 <= x < 127 else '.' for x in data])
    for i in range(len(ascii_str)):
        for l in range(min_len, 32):
            frag = ascii_str[i:i+l]
            if 'THM{' in frag or 'THM' in frag:
                print(f"[FRAGMENT] Offset {i}: {repr(frag)}")

def rot_search(data, flag_prefix=b'THM{', max_rot=256):
    # Try all byte rotations (Caesar cipher)
    for rot in range(1, max_rot):
        rotated = bytes([(b + rot) % 256 for b in data])
        if flag_prefix in rotated:
            idx = rotated.find(flag_prefix)
            end = rotated.find(b'}', idx)
            if end != -1:
                try:
                    print(f"[ROT{rot}] Found: {rotated[idx:end+1].decode(errors='ignore')}")
                except Exception:
                    continue

def search_tensor_aggressive(k, v):
    arr = None
    if hasattr(v, 'tobytes'):
        arr = v
    elif hasattr(v, 'cpu') and hasattr(v, 'numpy'):
        arr = v.cpu().numpy()
    if arr is not None:
        b = arr.tobytes()
        print(f"\n  Key: {k!r:30} | Bytes: {len(b)}")
        # Fragment search
        find_flag_fragments(b)
        # ROT search
        rot_search(b)
        # Reverse search
        rev = b[::-1]
        if b'THM{' in rev:
            idx = rev.find(b'THM{')
            end = rev.find(b'}', idx)
            if end != -1:
                try:
                    print(f"[REVERSED] Found: {rev[idx:end+1][::-1].decode(errors='ignore')}")
                except Exception:
                    pass
        # Base64 decode all windows
        for i in range(0, len(b)-20):
            chunk = b[i:i+60]
            try:
                decoded = base64.b64decode(chunk, validate=True)
                if b'THM{' in decoded:
                    idx = decoded.find(b'THM{')
                    end = decoded.find(b'}', idx)
                    if end != -1:
                        print(f"[BASE64] Found: {decoded[idx:end+1].decode(errors='ignore')}")
            except Exception:
                continue

def main():
    pt_path = "signal-classifier-1778659286018.pt"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, pt_path)
    print_header(f"Aggressive flag hunt: {model_path}")
    try:
        model = torch.load(model_path, map_location="cpu", weights_only=False)
        state_dict = model.get('state_dict')
        if state_dict:
            print_header("Aggressive tensor search in state_dict")
            for k, v in state_dict.items():
                search_tensor_aggressive(k, v)
        else:
            print("[!] No state_dict found in model.")
        # Also check feature_mean and feature_std
        for arr_name in ['feature_mean', 'feature_std']:
            arr = model.get(arr_name)
            if arr is not None:
                search_tensor_aggressive(arr_name, arr)
    except Exception as e:
        print(f"[!] Error loading model: {e}")

if __name__ == "__main__":
    main()
