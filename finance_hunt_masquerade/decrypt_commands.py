#!/usr/bin/env python3
"""Decrypt C2 commands from oldcss values using the AES key found in the payload."""
import sys, hashlib, base64, re, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

AES_KEY_STRING = "M4squ3r4d3Th3P4ck3tSt34lthM0d31337"

# The payload uses CreateAesKey with SHA256Managed - key is SHA256 of the string
key_hash = hashlib.sha256(AES_KEY_STRING.encode('utf-8')).digest()
print(f"AES Key string: {AES_KEY_STRING}")
print(f"SHA-256 of key: {key_hash.hex()}")
print(f"Key (32 bytes): {key_hash.hex()}")

# oldcss values extracted from the PCAP C2 responses
oldcss_values = [
    "LQPZY0C4ZPwZD8K0sFRzQKtP8l0NE35v/EzXkc0lU0Q=",
    "e/AWYx/120vW/t/o7Dgib7YjCVue1QYc43iF2irBVCkXBSfctKIDrBn3W3R79h9Y",
    "DjensviPUVe1TnQ6UNXTSZTJ3ECH6v4llUZ8GSbTtNM=",
    "wrRG31m5pAqBrTdKJH2MV/fmJh0vpuGnsoVmXJzp3GNTR35maQWTtwxGFA1+OKhj/gQpRdiAjjIItrlGio+iUA==",
    "Ot1LuXsbejCKTUgGHsOHdjI24igTv5FF/SIER1zMN7U=",
    "ewM6r2+zOT+sjlxdzqz0IZFonQfRisqJjwqJx8EtwBe1UDNeMLCFZbQF9ULp22A5kYU+gCJWLCBlDAVW/P9Z5G/Towi2ILsTUBNgwpnx1Nya9YBGdAbYoux5Hfoynsfb",
    "y9iDuwodl3alDXAtCAVkE1CBJ4QR7eRtT6TQYSL20hM=",
]

# From the .NET code: encryptedStringWithIV suggests IV is prepended to ciphertext
# AES-CBC with PKCS7 padding, first 16 bytes = IV, rest = ciphertext

print("\n=== DECRYPTING C2 COMMANDS ===\n")
for i, val in enumerate(oldcss_values):
    raw = base64.b64decode(val)
    iv = raw[:16]
    ct = raw[16:]
    
    print(f"[{i+1}] oldcss = {val}")
    print(f"    Raw length: {len(raw)} bytes")
    print(f"    IV:  {iv.hex()}")
    print(f"    CT:  {ct.hex()}")
    
    # Try AES-CBC with PKCS7 unpadding
    try:
        cipher = Cipher(algorithms.AES(key_hash), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        
        # Try to unpad PKCS7
        try:
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except:
            pass
        
        decoded = plaintext.decode('utf-8', errors='replace')
        print(f"    DECRYPTED: {decoded}")
    except Exception as e:
        print(f"    ERROR: {e}")
    print()

# Also try with raw key (first 16 or 32 bytes of the string itself)
print("\n=== TRYING WITH RAW KEY (first 32 bytes of string as key) ===\n")
raw_key = AES_KEY_STRING.encode('utf-8')[:32]
print(f"Raw key: {raw_key.hex()} ({raw_key.decode()})")

for i, val in enumerate(oldcss_values):
    raw = base64.b64decode(val)
    iv = raw[:16]
    ct = raw[16:]
    
    try:
        cipher = Cipher(algorithms.AES(raw_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        
        try:
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except:
            pass
        
        decoded = plaintext.decode('utf-8', errors='replace')
        print(f"  [{i+1}] {decoded}")
    except Exception as e:
        print(f"  [{i+1}] ERROR: {e}")

# Also try with 16-byte key (first 16 bytes of string)
print("\n=== TRYING WITH RAW KEY (first 16 bytes of string as key, AES-128) ===\n")
raw_key16 = AES_KEY_STRING.encode('utf-8')[:16]
print(f"Key16: {raw_key16.hex()} ({raw_key16.decode()})")

for i, val in enumerate(oldcss_values):
    raw = base64.b64decode(val)
    iv = raw[:16]
    ct = raw[16:]
    
    try:
        cipher = Cipher(algorithms.AES(raw_key16), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        
        try:
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except:
            pass
        
        decoded = plaintext.decode('utf-8', errors='replace')
        print(f"  [{i+1}] {decoded}")
    except Exception as e:
        print(f"  [{i+1}] ERROR: {e}")
