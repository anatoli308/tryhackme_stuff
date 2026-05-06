#!/usr/bin/env python3
"""Extract strings from decrypted payload binary and try decrypting C2 oldcss commands."""
import sys, hashlib, base64, struct, re

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PAYLOAD_PATH = r"D:\projects\tryhackme\finance_hunt_masquerade\decrypted_payload.bin"

# Read binary
with open(PAYLOAD_PATH, "rb") as f:
    data = f.read()

print(f"Payload size: {len(data)} bytes")
print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
print()

# Extract ASCII strings (min length 4)
strings = []
current = b""
for b in data:
    if 0x20 <= b < 0x7f:
        current += bytes([b])
    else:
        if len(current) >= 4:
            strings.append(current.decode('ascii'))
        current = b""
if len(current) >= 4:
    strings.append(current.decode('ascii'))

print(f"Total strings found: {len(strings)}")
print()

# Look for crypto-related strings
crypto_keywords = ['aes', 'rc4', 'key', 'encrypt', 'decrypt', 'cipher', 'crypt', 'iv', 'hmac', 'sha', 'hash', 'secret', 'password', 'base64', 'xor', 'chacha', 'salsa', 'blowfish', 'des', 'rsa', 'cbc', 'ecb', 'gcm', 'ctr', 'cfb', 'ofb', 'pkcs', 'pad']
print("=== CRYPTO-RELATED STRINGS ===")
for s in strings:
    sl = s.lower()
    for kw in crypto_keywords:
        if kw in sl:
            print(f"  {s}")
            break

print()

# Look for URLs
print("=== URL-LIKE STRINGS ===")
for s in strings:
    if 'http' in s.lower() or '/' in s and '.' in s:
        if len(s) > 6:
            print(f"  {s}")

print()

# Look for strings that could be keys (base64-like, hex-like, specific length)
print("=== POTENTIAL KEYS (base64/hex-like, 16-64 chars) ===")
for s in strings:
    if 16 <= len(s) <= 64:
        # Check if it looks like a key (alphanumeric, base64, or hex)
        if re.match(r'^[A-Za-z0-9+/=_-]+$', s) and not s.startswith('0x') and not ' ' in s:
            # Skip common non-key strings
            if not any(kw in s.lower() for kw in ['function', 'return', 'windows', 'system', 'kernel', 'microsoft', 'GetProc', 'LoadLib', 'Virtual']):
                print(f"  [{len(s)}] {s}")

print()

# Print ALL strings for manual inspection (grouped by length)
print("=== ALL STRINGS (6+ chars, sorted by length) ===")
long_strings = [s for s in strings if len(s) >= 6]
long_strings.sort(key=len, reverse=True)
for s in long_strings[:200]:
    print(f"  [{len(s):3d}] {s}")

print()

# Now look for specific patterns in binary - AES key schedule related
# Look for 16, 24, or 32 byte sequences that could be AES keys
print("=== BINARY ANALYSIS ===")

# Look for "oldcss=" pattern references or C2 communication strings  
for s in strings:
    if 'oldcss' in s.lower() or 'cookie' in s.lower() or 'sessionid' in s.lower() or 'etag' in s.lower():
        print(f"  C2-related: {s}")

# Check for .NET or Go or Rust markers
if b".text" in data and b".rdata" in data:
    print("  PE sections found: .text, .rdata")
if b"Go build" in data or b"runtime.main" in data:
    print("  Detected: Go binary")
if b"_CorExeMain" in data or b"mscoree.dll" in data:
    print("  Detected: .NET binary")
if b"rust" in data.lower():
    print("  Possible Rust binary")

# Look for the stage1 key to see if it's reused
stage1_key = b"X9vT3pL2QwE8xR6ZkYhC4s"
if stage1_key in data:
    print(f"  Stage 1 key found in binary!")

# Look for any base64-encoded key patterns
print()
print("=== CHECKING FOR EMBEDDED BASE64 KEYS ===")
for s in strings:
    if 8 <= len(s) <= 100 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
        try:
            decoded = base64.b64decode(s)
            if len(decoded) in [16, 24, 32]:  # AES key sizes
                print(f"  Potential AES key (b64): {s} -> {decoded.hex()} ({len(decoded)} bytes)")
        except:
            pass
