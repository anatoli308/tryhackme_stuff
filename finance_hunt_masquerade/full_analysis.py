#!/usr/bin/env python3
"""All-in-one: extract payload from PCAP, find strings, find AES key, decrypt commands."""
import sys, hashlib, base64, re, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP = r'C:\Users\anato\Downloads\dist\traffic.pcapng'
KEY = 'X9vT3pL2QwE8xR6ZkYhC4s'
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "analysis_output.txt")

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    r = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        r.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(r)

# === STEP 1: Extract payload from PCAP ===
from scapy.all import rdpcap, TCP, IP, Raw
print('Loading PCAP...')
pkts = rdpcap(PCAP)
streams = {}
for p in pkts:
    if p.haslayer(TCP) and p.haslayer(Raw):
        k = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
        streams.setdefault(k, []).append((p[TCP].seq, bytes(p[Raw].load)))
for k in streams:
    streams[k] = b''.join(d for _, d in sorted(streams[k], key=lambda x: x[0]))

hex_chars = set('0123456789abcdefABCDEF')
payload_data = None
for k, data in streams.items():
    t = data.decode('ascii', errors='ignore')
    if '/amd.bin' in t:
        rk = (k[2], k[3], k[0], k[1])
        if rk in streams:
            resp = streams[rk]
            hdr_end = resp.find(b'\r\n\r\n')
            body = resp[hdr_end+4:]
            cleaned = ''.join(c for c in body.decode('ascii', errors='ignore').strip() if c in hex_chars)
            payload_data = bytes.fromhex(cleaned)
            break

dec = rc4(KEY.encode(), payload_data)
print(f'Decrypted payload: {len(dec)} bytes, MZ={dec[:2] == b"MZ"}')
print(f'SHA-256: {hashlib.sha256(dec).hexdigest()}')

# Save it
payload_path = os.path.join(SCRIPT_DIR, 'decrypted_payload.bin')
with open(payload_path, 'wb') as f:
    f.write(dec)
print(f'Saved to {payload_path}')

# === STEP 2: Extract strings from payload ===
# ASCII strings (min 4 chars)
ascii_strings = []
current = b""
for b_val in dec:
    if 0x20 <= b_val < 0x7f:
        current += bytes([b_val])
    else:
        if len(current) >= 4:
            ascii_strings.append(current.decode('ascii'))
        current = b""
if len(current) >= 4:
    ascii_strings.append(current.decode('ascii'))

# UTF-16LE strings (min 4 chars)
unicode_strings = []
i = 0
current_u = b""
while i < len(dec) - 1:
    char = dec[i] | (dec[i+1] << 8)
    if 0x20 <= char < 0x7f:
        current_u += bytes([char])
    else:
        if len(current_u) >= 4:
            unicode_strings.append(current_u.decode('ascii'))
        current_u = b""
    i += 2
if len(current_u) >= 4:
    unicode_strings.append(current_u.decode('ascii'))

# Also try min 3 chars for both
short_ascii = []
current = b""
for b_val in dec:
    if 0x20 <= b_val < 0x7f:
        current += bytes([b_val])
    else:
        if len(current) >= 3:
            short_ascii.append(current.decode('ascii'))
        current = b""

all_strings = sorted(set(ascii_strings + unicode_strings), key=len, reverse=True)

# Write to output file
with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
    out.write(f"Payload: {len(dec)} bytes\n")
    out.write(f"SHA-256: {hashlib.sha256(dec).hexdigest()}\n\n")
    
    out.write("=== ALL UNIQUE STRINGS (sorted by length) ===\n")
    for s in all_strings:
        out.write(f"  [{len(s):3d}] {s}\n")
    
    out.write(f"\n=== CRYPTO-RELATED ===\n")
    for s in all_strings:
        sl = s.lower()
        if any(kw in sl for kw in ['aes', 'encrypt', 'decrypt', 'cipher', 'cbc', 'ecb', 
              'gcm', 'pkcs', 'padding', 'sha', 'key', 'iv', 'crypto', 'hmac', 'hash', 'mode']):
            out.write(f"  [{len(s):3d}] {s}\n")
    
    out.write(f"\n=== POTENTIAL KEYS ===\n")
    skip_words = ['function', 'return', 'windows', 'system', 'kernel', 'microsoft', 
                  'GetProc', 'LoadLib', 'Virtual', 'Attribute', 'Assembly', 'Runtime', 
                  'Compiler', 'Embedded', 'Debugg', 'Nullable', 'Disposable',
                  'String', 'Object', 'Boolean', 'Convert', 'Encoding', 'Managed',
                  'Security', 'Reflection', 'Interop', 'Collection', 'Diagnostic',
                  'Environment', 'Marshal', 'Console', 'Program', 'Module', 'Handle',
                  'Process', 'Thread', 'Exception', 'Memory', 'Version', 'Image',
                  'Resource', 'Token', 'Table', 'Debug', 'Reloc', 'Entry', 'Blob',
                  'Guid', 'mscorlib', 'netframework', 'corlib']
    for s in all_strings:
        if 6 <= len(s) <= 64 and re.match(r'^[A-Za-z0-9+/=_\-!@#$%^&*()]+$', s):
            if not any(kw.lower() in s.lower() for kw in skip_words):
                out.write(f"  [{len(s):3d}] {s}\n")
    
    # Look for #US heap
    out.write(f"\n=== .NET USER STRINGS HEAP ===\n")
    us_idx = dec.find(b'#US')
    if us_idx >= 0:
        out.write(f"  #US marker at offset: {us_idx}\n")
        # The #US heap pointer is in the stream headers
        # Let's parse the actual .NET metadata
    
    str_idx = dec.find(b'#Strings')
    if str_idx >= 0:
        out.write(f"  #Strings marker at offset: {str_idx}\n")
    
    blob_idx = dec.find(b'#Blob')
    if blob_idx >= 0:
        out.write(f"  #Blob marker at offset: {blob_idx}\n")
    
    guid_idx = dec.find(b'#GUID')
    if guid_idx >= 0:
        out.write(f"  #GUID marker at offset: {guid_idx}\n")
    
    # Parse .NET metadata to find User Strings heap
    # Look for the CLI header to find metadata
    out.write(f"\n=== .NET METADATA PARSING ===\n")
    # Find 'BSJB' signature (metadata root)
    bsjb = dec.find(b'BSJB')
    if bsjb >= 0:
        out.write(f"  BSJB metadata root at offset: {bsjb}\n")
        # Parse metadata root header
        # Skip signature(4), major(2), minor(2), reserved(4), version_length(4)
        ver_len = int.from_bytes(dec[bsjb+12:bsjb+16], 'little')
        version = dec[bsjb+16:bsjb+16+ver_len].decode('ascii', errors='replace').rstrip('\x00')
        out.write(f"  .NET version: {version}\n")
        
        # After version string: flags(2), streams(2)
        base = bsjb + 16 + ver_len
        flags = int.from_bytes(dec[base:base+2], 'little')
        num_streams = int.from_bytes(dec[base+2:base+4], 'little')
        out.write(f"  Number of streams: {num_streams}\n")
        
        # Parse stream headers
        offset = base + 4
        stream_info = {}
        for si in range(num_streams):
            s_offset = int.from_bytes(dec[offset:offset+4], 'little')
            s_size = int.from_bytes(dec[offset+4:offset+8], 'little')
            # Name is null-terminated, padded to 4 bytes
            name_start = offset + 8
            name_end = dec.find(b'\x00', name_start)
            name = dec[name_start:name_end].decode('ascii')
            # Pad to 4-byte boundary
            name_len = name_end - name_start + 1
            padded = (name_len + 3) & ~3
            offset = name_start + padded
            
            stream_info[name] = (s_offset, s_size)
            out.write(f"  Stream '{name}': offset={s_offset}, size={s_size}\n")
        
        # Extract #US (User Strings) heap
        if '#US' in stream_info:
            us_off, us_size = stream_info['#US']
            us_data = dec[bsjb + us_off:bsjb + us_off + us_size]
            out.write(f"\n  #US heap data ({us_size} bytes):\n")
            out.write(f"  Hex: {us_data.hex()}\n")
            
            # Parse user strings: each entry is a compressed length followed by UTF-16LE string + 1 byte
            pos = 1  # Skip first byte (usually 0)
            us_entries = []
            while pos < len(us_data):
                # Read compressed unsigned int
                b0 = us_data[pos]
                if b0 == 0:
                    pos += 1
                    continue
                if b0 < 0x80:
                    str_len = b0
                    pos += 1
                elif b0 < 0xC0:
                    if pos + 1 >= len(us_data):
                        break
                    str_len = ((b0 & 0x3F) << 8) | us_data[pos + 1]
                    pos += 2
                else:
                    if pos + 3 >= len(us_data):
                        break
                    str_len = ((b0 & 0x1F) << 24) | (us_data[pos+1] << 16) | (us_data[pos+2] << 8) | us_data[pos+3]
                    pos += 4
                
                if pos + str_len > len(us_data) or str_len <= 0:
                    break
                
                raw = us_data[pos:pos + str_len]
                # Last byte is a flag, string is the rest (UTF-16LE)
                if str_len > 1:
                    try:
                        s = raw[:-1].decode('utf-16-le')
                        us_entries.append(s)
                        out.write(f"    US[{len(us_entries)}]: [{len(s)}] {repr(s)}\n")
                    except:
                        out.write(f"    US[?]: raw={raw.hex()}\n")
                pos += str_len
            
            out.write(f"\n  Total user strings: {len(us_entries)}\n")
    
    # Also dump hex around crypto-related areas for manual inspection
    out.write(f"\n=== HEX CONTEXT AROUND 'AesManaged' ===\n")
    idx = dec.find(b'AesManaged')
    if idx >= 0:
        start = max(0, idx - 300)
        end = min(len(dec), idx + 300)
        for line_off in range(start, end, 16):
            chunk = dec[line_off:line_off+16]
            hexs = ' '.join(f'{b:02x}' for b in chunk)
            ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            marker = ' <-- HERE' if line_off <= idx < line_off + 16 else ''
            out.write(f"  {line_off:04x}: {hexs:<48s} {ascs}{marker}\n")

print(f"\nResults written to {OUTPUT_FILE}")
print("Now printing key sections to stdout:\n")

# Print to stdout for quick view
with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Print crypto and key sections
for section in ['CRYPTO-RELATED', 'POTENTIAL KEYS', '.NET USER STRINGS HEAP', '.NET METADATA PARSING']:
    marker = f'=== {section} ==='
    idx = content.find(marker)
    if idx >= 0:
        # Find next section or end
        next_section = content.find('\n===', idx + len(marker))
        if next_section < 0:
            next_section = len(content)
        print(content[idx:next_section])
        print()
