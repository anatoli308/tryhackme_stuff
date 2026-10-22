import torch
import numpy as np
import random
import string
import os
import sys
import time
import re
import base64
import subprocess

MODEL_PATH = "signal-classifier-1778659286018.pt"
LOG_FILE = "model_trigger_hunt.log"

# 1. Füttere das Modell mit zufälligen und ungewöhnlichen Inputs und logge die Ausgaben

def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_tensor(shape, dtype=torch.float32):
    if dtype == torch.float32:
        return torch.randn(*shape)
    elif dtype == torch.int64:
        return torch.randint(-1000, 1000, shape, dtype=dtype)
    else:
        return torch.randn(*shape).type(dtype)

def try_model_forward(model):
    # Try common input shapes
    shapes = [(1, 1), (1, 3), (1, 10), (1, 100), (10, 10), (1, 128), (1, 256)]
    results = []
    for shape in shapes:
        for dtype in [torch.float32, torch.int64]:
            try:
                x = random_tensor(shape, dtype)
                out = model(x)
                results.append((shape, dtype, str(out)))
            except Exception as e:
                results.append((shape, dtype, f"EXC: {e}"))
    return results

def try_model_with_strings(model):
    # Try passing strings if model supports it
    results = []
    for l in [4, 8, 16, 32, 64]:
        s = random_string(l)
        try:
            out = model(s)
            results.append((s, str(out)))
        except Exception as e:
            results.append((s, f"EXC: {e}"))
    return results

# 2. Überwache beim Laden des Modells alle Systemaktivitäten (Dateizugriffe, Netzwerk)
def monitor_model_load():
    # Windows: Use procmon or fallback to logging file/network access
    # Here: monkeypatch open/socket to log accesses
    import builtins
    import socket
    accesses = []
    orig_open = builtins.open
    orig_socket = socket.socket
    def open_hook(*args, **kwargs):
        accesses.append(f"open: {args}")
        return orig_open(*args, **kwargs)
    def socket_hook(*args, **kwargs):
        accesses.append(f"socket: {args}")
        return orig_socket(*args, **kwargs)
    builtins.open = open_hook
    socket.socket = socket_hook
    try:
        # WARNING: weights_only=False ist unsicher, aber nötig für CTF/Backdoor-Analyse!
        model = torch.load(MODEL_PATH, map_location='cpu', weights_only=False)
    except Exception as e:
        model = None
        accesses.append(f"torch.load EXC: {e}")
    builtins.open = orig_open
    socket.socket = orig_socket
    return model, accesses

# 3. Suche im Modell nach URLs, Domains, IPs
def search_for_urls(obj):
    url_regex = re.compile(r"(https?://[\w\.-]+|[\w\.-]+\.[a-z]{2,6}|\d+\.\d+\.\d+\.\d+)")
    found = set()
    def scan(val):
        if isinstance(val, str):
            for m in url_regex.findall(val):
                found.add(m)
        elif isinstance(val, (list, tuple)):
            for v in val:
                scan(v)
        elif isinstance(val, dict):
            for v in val.values():
                scan(v)
        elif hasattr(val, '__dict__'):
            scan(vars(val))
    scan(obj)
    return found

# 4. Prüfe, ob das Modell beim Laden/bei Inputs Dateien anlegt oder verändert
def check_file_changes(before_files):
    after_files = set(os.listdir('.'))
    new_files = after_files - before_files
    return new_files

# 5. Suche nach Pickle Exploits (__reduce__ Methoden)
def search_reduce_methods(obj):
    found = []
    def scan(val):
        if hasattr(val, '__reduce__'):
            found.append(str(type(val)))
        if isinstance(val, (list, tuple)):
            for v in val:
                scan(v)
        elif isinstance(val, dict):
            for v in val.values():
                scan(v)
        elif hasattr(val, '__dict__'):
            scan(vars(val))
    scan(obj)
    return found

def main():
    print("==== MODEL TRIGGER HUNT ====")
    # 2. Überwache Modell-Ladevorgang
    before_files = set(os.listdir('.'))
    model, accesses = monitor_model_load()
    print("[Monitor] File/Net accesses during load:")
    for acc in accesses:
        print("  ", acc)
    new_files = check_file_changes(before_files)
    if new_files:
        print(f"[Monitor] New files created: {new_files}")
    else:
        print("[Monitor] No new files created during load.")
    if not model:
        print("[Error] Model could not be loaded.")
        return
    # 1. Füttere Modell mit random Inputs
    print("[Trigger] Random tensor inputs:")
    for shape, dtype, out in try_model_forward(model):
        print(f"  shape={shape} dtype={dtype}: {out}")
    print("[Trigger] Random string inputs:")
    for s, out in try_model_with_strings(model):
        print(f"  input='{s}': {out}")
    # 3. Suche nach URLs
    urls = search_for_urls(model)
    if urls:
        print(f"[URL] Found URLs/domains/IPs: {urls}")
    else:
        print("[URL] No URLs/domains/IPs found.")
    # 5. Suche nach __reduce__ Methoden
    reduce_types = search_reduce_methods(model)
    if reduce_types:
        print(f"[Pickle] Objects with __reduce__: {reduce_types}")
    else:
        print("[Pickle] No suspicious __reduce__ methods found.")

if __name__ == "__main__":
    main()
