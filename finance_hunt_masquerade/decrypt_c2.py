#!/usr/bin/env python3
"""
Step 1: Re-extract and save decrypted payload from PCAP
Step 2: Extract strings from payload to find C2 encryption key/algo
Step 3: Decrypt C2 oldcss commands
"""
import hashlib, base64, sys, os, re, struct
from scapy.all import rdpcap, TCP, IP, Raw
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PCAP_FILE = r"C:\Users\anato\Downloads\dist\traffic.pcapng"
STAGE1_KEY = "X9vT3pL2QwE8xR6ZkYhC4s"

def rc4_crypt(key_bytes, data_bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

print("[+] Loading PCAP...")
packets = rdpcap(PCAP_FILE)

# Reassemble TCP streams
streams = {}
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        ip = pkt[IP]; tcp = pkt[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if key not in streams:
            streams[key] = []
        streams[key].append({'seq': tcp.seq, 'data': bytes(pkt[Raw].load), 'time': float(pkt.time)})

reassembled = {}
for key, pkts in streams.items():
    sorted_pkts = sorted(pkts, key=lambda p: p['seq'])
    data = b''.join(p['data'] for p in sorted_pkts)
    reassembled[key] = {'data': data, 'time': sorted_pkts[0]['time']}

# Extract HTTP sessions
http_sessions = []
for key, info in reassembled.items():
    text = info['data'].decode('ascii', errors='ignore')
    if text.startswith(('GET ', 'POST ')):
        src_ip, src_port, dst_ip, dst_port = key
        resp_key = (dst_ip, dst_port, src_ip, src_port)
        if resp_key in reassembled:
            resp = reassembled[resp_key]
            resp_text = resp['data'].decode('ascii', errors='ignore')
            if resp_text.startswith('HTTP/'):
                hdr_end = resp['data'].find(b'\r\n\r\n')
                if hdr_end > 0:
                    headers = resp['data'][:hdr_end].decode('ascii', errors='ignore')
                    body = resp['data'][hdr_end+4:]
                    http_sessions.append((key, info['data'], body, headers, info['time']))

# ================================================================
# STEP 1: Extract and save decrypted payload
# ================================================================
print("\n[+] STEP 1: Extracting amd.bin payload...")
hex_chars = set('0123456789abcdefABCDEF')
decrypted_payload = None

for key, req_data, body, headers, req_time in http_sessions:
    req_text = req_data.decode('ascii', errors='ignore')
    if '/amd.bin' in req_text:
        body_text = body.decode('ascii', errors='ignore').strip()
        cleaned = ''.join(c for c in body_text if c not in ' \r\n\t')
        is_hex = len(cleaned) > 0 and len(cleaned) % 2 == 0 and all(c in hex_chars for c in cleaned)
        
        if is_hex:
            payload_bytes = bytes.fromhex(cleaned)
            decrypted_payload = rc4_crypt(STAGE1_KEY.encode(), payload_bytes)
            sha256 = hashlib.sha256(decrypted_payload).hexdigest()
            print(f"    Decrypted payload: {len(decrypted_payload)} bytes, SHA-256: {sha256}")
            print(f"    Is PE: {decrypted_payload[:2] == b'MZ'}")
            
            out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_payload.bin")
            with open(out_path, 'wb') as f:
                f.write(decrypted_payload)
            print(f"    Saved: {out_path}")

if decrypted_payload is None:
    print("    ERROR: Could not find amd.bin payload!")
    sys.exit(1)

# ================================================================
# STEP 2: Extract strings from payload
# ================================================================
print("\n[+] STEP 2: Extracting strings from decrypted payload...")

strings = []
current = b""
for b in decrypted_payload:
    if 0x20 <= b < 0x7f:
        current += bytes([b])
    else:
        if len(current) >= 4:
            strings.append(current.decode('ascii'))
        current = b""
if len(current) >= 4:
    strings.append(current.decode('ascii'))

print(f"    Total strings: {len(strings)}")

# Crypto-related
print("\n  === CRYPTO STRINGS ===")
for s in strings:
    sl = s.lower()
    for kw in ['aes', 'rc4', 'encrypt', 'decrypt', 'cipher', 'cbc', 'ecb', 'gcm', 'key', 'chacha', 'pkcs']:
        if kw in sl:
            print(f"    {s}")
            break

# C2-related
print("\n  === C2 STRINGS ===")
for s in strings:
    sl = s.lower()
    for kw in ['http', 'url', 'cookie', 'session', 'oldcss', 'etag', 'command', 'exec', 'shell', 'cmd', 'powershell', 'guid', 'beacon', '/images', 'host']:
        if kw in sl:
            print(f"    {s}")
            break

# Potential keys
print("\n  === POTENTIAL KEYS ===")
for s in strings:
    if 8 <= len(s) <= 64 and re.match(r'^[A-Za-z0-9+/=_-]+$', s):
        skip_kw = ['function', 'return', 'windows', 'system', 'kernel', 'microsoft', 'GetProc', 'LoadLib', 'Virtual', 'Free', 'Heap', 'File', 'Write', 'Read', 'Module', 'Handle', 'Process', 'Thread', 'Event', 'Close', 'Open', 'Create', 'Delete', 'Query', 'Info', 'Status', 'Error', 'Exception', 'Address', 'Memory', 'Buffer', 'Alloc']
        if not any(kw.lower() in s.lower() for kw in skip_kw):
            print(f"    [{len(s):2d}] {s}")

# ALL strings sorted by uniqueness interest
print("\n  === ALL STRINGS (6+ chars) ===")
for s in sorted(set(s for s in strings if len(s) >= 6), key=lambda x: (-len(x), x)):
    print(f"    [{len(s):3d}] {s}")
    if len(s) > 300:
        break

# ================================================================
# STEP 3: Try decrypting oldcss values
# ================================================================
print("\n" + "=" * 70)
print("[+] STEP 3: Extracting and decrypting C2 commands (oldcss values)")
print("=" * 70)

# Collect unique oldcss values from C2 responses
oldcss_values = []
for key, req_data, body, headers, req_time in http_sessions:
    req_text = req_data.decode('ascii', errors='ignore')
    if 'Host: 34.174.57.99' in req_text and 'GET / ' in req_text and len(body) > 0:
        body_text = body.decode('ascii', errors='replace')
        # Extract oldcss comment
        m = re.search(r'oldcss=([A-Za-z0-9+/=]+)', body_text)
        if m:
            ts = datetime.fromtimestamp(req_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            etag = ''
            for hline in headers.split('\r\n'):
                if hline.lower().startswith('etag:'):
                    etag = hline.split(':', 1)[1].strip().strip('"')
            val = m.group(1)
            if val not in [v[1] for v in oldcss_values]:  # unique
                oldcss_values.append((ts, val, etag))

print(f"\n  Found {len(oldcss_values)} unique oldcss values:")
for ts, val, etag in oldcss_values:
    print(f"    [{ts}] Etag: {etag}")
    print(f"      oldcss({len(val)} chars): {val}")
    
    # Decode base64
    try:
        raw = base64.b64decode(val)
        print(f"      Decoded: {len(raw)} bytes -> {raw.hex()}")
    except Exception as e:
        print(f"      Base64 decode error: {e}")

# Now try various decryption approaches on oldcss values
print("\n  === TRYING DECRYPTION APPROACHES ===")

# Collect potential keys from the binary
potential_keys = []
for s in strings:
    if 8 <= len(s) <= 64 and re.match(r'^[A-Za-z0-9+/=_-]+$', s):
        skip_kw = ['function', 'return', 'windows', 'system', 'kernel', 'microsoft', 'GetProc', 'LoadLib', 'Virtual', 'Free', 'Heap', 'File', 'Write', 'Read', 'Module', 'Handle', 'Process', 'Thread', 'Event', 'Close', 'Open', 'Create', 'Delete', 'Query', 'Info', 'Status', 'Error', 'Exception', 'Address', 'Memory', 'Buffer', 'Alloc', 'Sleep', 'Crypt']
        if not any(kw.lower() in s.lower() for kw in skip_kw):
            potential_keys.append(s)

# Also try the stage1 key
potential_keys.insert(0, STAGE1_KEY)

for ts, val, etag in oldcss_values:
    try:
        raw = base64.b64decode(val)
    except:
        continue
    
    if len(raw) == 0:
        continue
    
    print(f"\n  --- oldcss at [{ts}] ({len(raw)} bytes) ---")
    
    # Try RC4 with each potential key
    for pk in potential_keys[:20]:
        dec = rc4_crypt(pk.encode(), raw)
        dec_text = dec.decode('ascii', errors='replace')
        printable = sum(1 for c in dec_text if c.isprintable())
        ratio = printable / len(dec_text) if len(dec_text) > 0 else 0
        if ratio > 0.7:
            print(f"    RC4 key='{pk}': {dec_text[:200]}")
    
    # Try AES-CBC with each potential key (first 16 bytes as IV)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        
        for pk in potential_keys[:20]:
            key_bytes = pk.encode()
            # Try different key derivation: raw, SHA256, MD5
            for key_hash_func, key_name in [(lambda k: hashlib.sha256(k).digest()[:32], "SHA256"), 
                                             (lambda k: hashlib.md5(k).digest(), "MD5"),
                                             (lambda k: k.ljust(32, b'\x00')[:32], "raw32"),
                                             (lambda k: k.ljust(16, b'\x00')[:16], "raw16")]:
                aes_key = key_hash_func(key_bytes)
                
                # If data is long enough to have IV
                if len(raw) > 16:
                    iv = raw[:16]
                    ct = raw[16:]
                    try:
                        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                        dec_obj = cipher.decryptor()
                        pt = dec_obj.update(ct) + dec_obj.finalize()
                        # Try to unpad
                        try:
                            unpadder = sym_padding.PKCS7(128).unpadder()
                            pt = unpadder.update(pt) + unpadder.finalize()
                        except:
                            pass
                        dec_text = pt.decode('ascii', errors='replace')
                        printable = sum(1 for c in dec_text if c.isprintable())
                        ratio = printable / len(dec_text) if len(dec_text) > 0 else 0
                        if ratio > 0.7:
                            print(f"    AES-CBC key='{pk}'({key_name}) IV=first16: {dec_text[:200]}")
                    except Exception:
                        pass
                
                # AES-ECB (no IV)
                if len(raw) % 16 == 0:
                    try:
                        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
                        dec_obj = cipher.decryptor()
                        pt = dec_obj.update(raw) + dec_obj.finalize()
                        try:
                            unpadder = sym_padding.PKCS7(128).unpadder()
                            pt = unpadder.update(pt) + unpadder.finalize()
                        except:
                            pass
                        dec_text = pt.decode('ascii', errors='replace')
                        printable = sum(1 for c in dec_text if c.isprintable())
                        ratio = printable / len(dec_text) if len(dec_text) > 0 else 0
                        if ratio > 0.7:
                            print(f"    AES-ECB key='{pk}'({key_name}): {dec_text[:200]}")
                    except Exception:
                        pass
    except ImportError:
        print("    [!] cryptography module not installed, skipping AES")
        break

# Also try XOR with simple keys
for ts, val, etag in oldcss_values[:3]:
    try:
        raw = base64.b64decode(val)
    except:
        continue
    if len(raw) == 0:
        continue
    print(f"\n  --- XOR attempts on [{ts}] ---")
    # Single-byte XOR
    for xor_byte in range(256):
        dec = bytes([b ^ xor_byte for b in raw])
        dec_text = dec.decode('ascii', errors='replace')
        printable = sum(1 for c in dec_text if c.isprintable())
        ratio = printable / len(dec_text) if len(dec_text) > 0 else 0
        if ratio > 0.85:
            print(f"    XOR 0x{xor_byte:02x}: {dec_text[:200]}")
