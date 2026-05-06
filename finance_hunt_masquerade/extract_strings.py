#!/usr/bin/env python3
"""Extract all strings from decrypted payload and find AES key, then decrypt oldcss."""
import sys, hashlib, base64, re, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PAYLOAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_payload.bin")

with open(PAYLOAD_PATH, "rb") as f:
    data = f.read()

print(f"Payload size: {len(data)} bytes")
print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")

# Extract ASCII strings (min length 4)
strings = []
current = b""
for b_val in data:
    if 0x20 <= b_val < 0x7f:
        current += bytes([b_val])
    else:
        if len(current) >= 4:
            strings.append(current.decode('ascii'))
        current = b""
if len(current) >= 4:
    strings.append(current.decode('ascii'))

# Also extract Unicode (UTF-16LE) strings
unicode_strings = []
i = 0
current_u = b""
while i < len(data) - 1:
    char = data[i] | (data[i+1] << 8)
    if 0x20 <= char < 0x7f:
        current_u += bytes([char])
    else:
        if len(current_u) >= 4:
            unicode_strings.append(current_u.decode('ascii'))
        current_u = b""
    i += 2
if len(current_u) >= 4:
    unicode_strings.append(current_u.decode('ascii'))

all_strings = list(set(strings + unicode_strings))
all_strings.sort(key=len, reverse=True)

# Write all strings to file
with open("payload_strings.txt", "w") as f:
    for s in all_strings:
        f.write(f"[{len(s):3d}] {s}\n")

print(f"\nTotal ASCII strings: {len(strings)}")
print(f"Total Unicode strings: {len(unicode_strings)}")
print(f"Total unique strings: {len(all_strings)}")
print("Saved to payload_strings.txt")

# Print crypto/key related
print("\n=== CRYPTO-RELATED STRINGS ===")
for s in all_strings:
    sl = s.lower()
    if any(kw in sl for kw in ['aes', 'encrypt', 'decrypt', 'cipher', 'cbc', 'ecb', 'gcm', 'pkcs', 'padding', 'sha256', 'key', 'iv', 'crypto', 'hmac', 'hash']):
        print(f"  [{len(s):3d}] {s}")

# Print strings that look like keys
print("\n=== POTENTIAL KEYS (alphanumeric, 8-64 chars) ===")
skip_words = ['function', 'return', 'windows', 'system', 'kernel', 'microsoft', 
              'GetProc', 'LoadLib', 'Virtual', 'Free', 'Heap', 'File', 'Write', 
              'Read', 'Module', 'Handle', 'Process', 'Thread', 'Event', 'Close', 
              'Open', 'Create', 'Delete', 'Query', 'Info', 'Status', 'Error',
              'Exception', 'Address', 'Memory', 'Buffer', 'Alloc', 'Sleep',
              'Crypt', 'Attribute', 'Assembly', 'Runtime', 'Version', 'Compiler',
              'Embedded', 'Debugg', 'Nullable', 'Disposable', 'IEnumer',
              'String', 'Object', 'Boolean', 'Convert', 'Encoding', 'Managed',
              'Security', 'Reflection', 'Interop', 'Collection', 'Diagnostic',
              'Environment', 'Marshal', 'Console', 'Program']
for s in all_strings:
    if 8 <= len(s) <= 64 and re.match(r'^[A-Za-z0-9+/=_-]+$', s):
        if not any(kw.lower() in s.lower() for kw in skip_words):
            print(f"  [{len(s):3d}] {s}")

# Print ALL strings for inspection
print("\n=== ALL UNIQUE STRINGS (showing all) ===")
for s in sorted(set(all_strings)):
    print(f"  [{len(s):3d}] {s}")

# Look for the key near known crypto strings in the binary
print("\n=== BINARY CONTEXT AROUND 'AesManaged' ===")
idx = data.find(b'AesManaged')
if idx >= 0:
    print(f"  Found at offset: {idx}")
    # Show surrounding bytes as hex and ascii
    start = max(0, idx - 200)
    end = min(len(data), idx + 200)
    context = data[start:end]
    # Extract strings from this context
    ctx_strings = []
    current = b""
    for b_val in context:
        if 0x20 <= b_val < 0x7f:
            current += bytes([b_val])
        else:
            if len(current) >= 3:
                ctx_strings.append(current.decode('ascii'))
            current = b""
    if len(current) >= 3:
        ctx_strings.append(current.decode('ascii'))
    for s in ctx_strings:
        print(f"    {s}")

# Look for context around CipherMode
print("\n=== BINARY CONTEXT AROUND 'CipherMode' ===")
idx = data.find(b'CipherMode')
if idx >= 0:
    start = max(0, idx - 200)
    end = min(len(data), idx + 200)
    context = data[start:end]
    ctx_strings = []
    current = b""
    for b_val in context:
        if 0x20 <= b_val < 0x7f:
            current += bytes([b_val])
        else:
            if len(current) >= 3:
                ctx_strings.append(current.decode('ascii'))
            current = b""
    if len(current) >= 3:
        ctx_strings.append(current.decode('ascii'))
    for s in ctx_strings:
        print(f"    {s}")

# Search for key-like patterns in the .NET metadata
# Look for user strings heap in .NET (#US)
print("\n=== SEARCHING FOR .NET USER STRINGS (#US heap) ===")
# .NET user strings are UTF-16LE prefixed with length
# Look for the #US signature
us_idx = data.find(b'#US')
if us_idx >= 0:
    print(f"  #US heap marker at offset: {us_idx}")
    # The actual heap starts after the stream headers
    # Let's look for string-like patterns after this
    # Scan ahead for readable strings
    scan_start = us_idx
    scan_end = min(len(data), us_idx + 2000)
    region = data[scan_start:scan_end]
    
    # Extract all UTF-16LE strings from this region
    i = 0
    while i < len(region) - 1:
        # Try to read a run of UTF-16LE printable chars
        chars = []
        j = i
        while j < len(region) - 1:
            char = region[j] | (region[j+1] << 8)
            if 0x20 <= char < 0x7f:
                chars.append(chr(char))
                j += 2
            else:
                break
        if len(chars) >= 4:
            s = ''.join(chars)
            print(f"  [{scan_start + i:5d}] [{len(s):3d}] {s}")
        i = j + 2 if j == i else j

# Also look for #Strings heap
print("\n=== .NET #Strings heap ===")
str_idx = data.find(b'#Strings')
if str_idx >= 0:
    print(f"  #Strings heap marker at offset: {str_idx}")

# Look for #Blob heap
blob_idx = data.find(b'#Blob')
if blob_idx >= 0:
    print(f"  #Blob heap marker at offset: {blob_idx}")
