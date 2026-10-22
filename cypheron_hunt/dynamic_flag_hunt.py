import torch
import numpy as np
import base64
import re
import sys
import os

def print_header(msg):
	print("\n" + "="*60)
	print(msg)
	print("="*60)

def search_obj(obj, path=None):
	if path is None:
		path = []
	if isinstance(obj, dict):
		for k, v in obj.items():
			search_obj(k, path+['<key>'])
			search_obj(v, path+[str(k)])
	elif isinstance(obj, (list, tuple, set)):
		for idx, v in enumerate(obj):
			search_obj(v, path+[f'[{idx}]'])
	elif isinstance(obj, (str, bytes)):
		s = obj.decode() if isinstance(obj, bytes) else obj
		if 'THM{' in s:
			print(f"  [FLAG?] Path: {'/'.join(path)} | Value: {repr(s)[:120]}")

def search_bytes_for_flags(arr, arr_name):
	try:
		b = arr.tobytes()
		s = b.decode(errors='ignore')
		flags = re.findall(r'THM\{[^}]+\}', s)
		if flags:
			print(f"[FLAG in {arr_name}] Found: {flags}")
		# Try base64
		for i in range(0, len(b)-20):
			chunk = b[i:i+60]
			try:
				decoded = base64.b64decode(chunk, validate=True).decode(errors='ignore')
				b64_flags = re.findall(r'THM\{[^}]+\}', decoded)
				if b64_flags:
					print(f"[BASE64 FLAG in {arr_name}] Found: {b64_flags}")
			except Exception:
				continue
	except Exception as e:
		print(f"[!] Error analyzing {arr_name}: {e}")

def xor_search(data, flag_prefix=b'THM{', max_key=256):
	results = []
	for key in range(1, max_key):
		xored = bytes([b ^ key for b in data])
		if flag_prefix in xored:
			idx = xored.find(flag_prefix)
			end = xored.find(b'}', idx)
			if end != -1:
				try:
					results.append((key, xored[idx:end+1].decode(errors='ignore')))
				except Exception:
					continue
	return results

def byte_stats(data):
	arr = np.frombuffer(data, dtype=np.uint8)
	unique, counts = np.unique(arr, return_counts=True)
	stats = dict(zip(unique, counts))
	return stats

def analyze_tensor(k, v):
	arr = None
	if hasattr(v, 'tobytes'):
		arr = v
	elif hasattr(v, 'cpu') and hasattr(v, 'numpy'):
		arr = v.cpu().numpy()
	if arr is not None:
		b = arr.tobytes()
		print(f"\n  Key: {k!r:30} | Bytes: {len(b)}")
		# ASCII Dump (printable chars)
		ascii_str = ''.join([chr(x) if 32 <= x < 127 else '.' for x in b])
		print("    [ASCII]", ascii_str[:120] + ("..." if len(ascii_str) > 120 else ""))
		# HEX Dump (first 64 bytes)
		print("    [HEX]", b.hex()[:128] + ("..." if len(b) > 64 else ""))
		# BASE64 Dump (first 60 bytes)
		print("    [BASE64]", base64.b64encode(b[:60]).decode() + ("..." if len(b) > 60 else ""))
		# XOR-Flag search
		xor_flags = xor_search(b)
		if xor_flags:
			print(f"    [XOR-Flag found] Keys: {xor_flags}")
		# Stat analysis
		stats = byte_stats(b)
		print(f"    [Byte distribution] {dict(sorted(stats.items())[:8])} ... (total {len(stats)} unique bytes)")
		# Flag search
		search_bytes_for_flags(arr, k)

def main():
	pt_path = "signal-classifier-1778659286018.pt"
	# Robust: resolve path relative to script
	script_dir = os.path.dirname(os.path.abspath(__file__))
	model_path = os.path.join(script_dir, pt_path)
	print_header(f"Loading model: {model_path} (unsafe, for CTF analysis only)")
	try:
		model = torch.load(model_path, map_location="cpu", weights_only=False)
		print("[+] Model loaded. Type:", type(model))
		print("[+] Dir(model):", dir(model))
		if isinstance(model, dict):
			print("[+] Top-level keys and value types:")
			for k, v in model.items():
				print(f"  Key: {k!r:30} | Type: {type(v)}")

		print_header("All string/bytes values found in model (recursive)")
		search_obj(model)

		for arr_name in ['feature_mean', 'feature_std']:
			arr = model.get(arr_name)
			if arr is not None:
				search_bytes_for_flags(arr, arr_name)

		state_dict = model.get('state_dict')
		print("[DEBUG] state_dict keys:", list(state_dict.keys()) if state_dict else state_dict)
		if state_dict:
			print_header("Deep analysis of state_dict")
			for k, v in state_dict.items():
				print(f"  Key: {k!r:30} | Type: {type(v)} | Shape: {getattr(v, 'shape', None)}")
				analyze_tensor(k, v)

			cal = state_dict.get('_calibration_constants')
			if cal is not None:
				print_header("Dumping _calibration_constants")
				analyze_tensor('_calibration_constants', cal)

			print_header("Deep analysis of all tensors except _calibration_constants")
			for k, v in state_dict.items():
				if k == '_calibration_constants':
					continue
				analyze_tensor(k, v)
		else:
			print("[!] No state_dict found in model.")
	except Exception as e:
		print(f"[!] Error loading model: {e}")

if __name__ == "__main__":
	main()
