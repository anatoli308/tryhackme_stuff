#!/usr/bin/env python3
"""
Prüfe ob 500 = 'falsche Sig' oder 'Server-Bug', und teste alle Key-Varianten
"""
import hashlib, re, requests
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as CryptoSHA256

TARGET = "http://10.113.167.230:5000"
SEED   = b"admin_lovenote_2026_valentine"

s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

# ── 1. Server-Verhalten bei ungültigen Inputs testen ─────────────────────────
print("--- Server-Verhalten bei verschiedenen Inputs ---")
test_cases = [
    ("leere Sig",   {"message": "test", "signature": ""}),
    ("keine Felder",{}),
    ("nur message", {"message": "test"}),
    ("hex 128c",    {"message": "test", "signature": "a" * 128}),
    ("hex 256c",    {"message": "test", "signature": "a" * 256}),
    ("hex 512c",    {"message": "test", "signature": "a" * 512}),
    ("junk b64",    {"message": "test", "signature": "aGVsbG8=" * 10}),
]
for label, data in test_cases:
    r = s.post(f"{TARGET}/verify", data=data)
    clean = re.sub(r'<[^>]+>', ' ', r.text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    relevant = [x.strip() for x in clean.split('.') if any(w in x.lower() for w in ['valid','invalid','error','fail','sign','flag'])]
    print(f"  [{label}] {r.status_code} | {relevant[:2] if relevant else clean[200:300]}")

# ── 2. Alle Key-Varianten ausprobieren ───────────────────────────────────────
print("\n--- Key-Varianten ---")

def make_key_and_sign(p_val, q_val, msg="test"):
    e = 65537
    n = p_val * q_val
    d = pow(e, -1, (p_val-1)*(q_val-1))
    k = RSA.construct((n, e, d, p_val, q_val))
    h = CryptoSHA256.new(msg.encode())
    sig_hex = pkcs1_15.new(k).sign(h).hex()
    return k, sig_hex

def try_verify(msg, sig_hex, label):
    r = s.post(f"{TARGET}/verify", data={"message": msg, "signature": sig_hex})
    flags = re.findall(r'THM\{[^}]+\}|[A-Z0-9_]{3,}\{[^}]+\}', r.text)
    clean = re.sub(r'<[^>]+>', ' ', r.text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    relevant = [x.strip() for x in clean.split('.') if any(w in x.lower() for w in ['valid','invalid','success','fail','error','sign','flag','thm'])]
    if flags:
        print(f"  *** FLAG [{label}]: {flags[0]}")
        return True
    print(f"  [{label}] {r.status_code} sig_len={len(sig_hex)} | {relevant[:2] if relevant else clean[300:400]}")
    return False

hash_p_bytes = hashlib.sha256(SEED).digest()
p_int        = int.from_bytes(hash_p_bytes, "big")

mod_seed     = hashlib.sha256(SEED + b"pki").digest()
hash_q_bytes = hashlib.sha256(mod_seed).digest()
q_int        = int.from_bytes(hash_q_bytes, "big")

variants = {
    "256bit_vanilla":      (nextprime(p_int),                    nextprime(q_int)),
    "256bit_highbit":      (nextprime(p_int | (1 << 255)),       nextprime(q_int | (1 << 255))),
    "256bit_2bits":        (nextprime(p_int | (1 << 255) | 1),   nextprime(q_int | (1 << 255) | 1)),
    "512bit_highbit":      (nextprime(p_int | (1 << 511)),       nextprime(q_int | (1 << 511))),
    "1024bit_highbit":     (nextprime(p_int | (1 << 1023)),      nextprime(q_int | (1 << 1023))),
}

msg = "test"
for label, (p_v, q_v) in variants.items():
    try:
        _, sig = make_key_and_sign(p_v, q_v, msg)
        if try_verify(msg, sig, label):
            break
    except Exception as exc:
        print(f"  [{label}] Error: {exc}")

# ── 3. Compose-Response nach Signatur durchsuchen ─────────────────────────────
print("\n--- Vollstaendige Compose-Response ---")
r = s.post(f"{TARGET}/compose", data={"to_user": "admin", "subject": "sigcheck", "message": "signature test"})
# Alle potentiellen Signaturen
hex64plus = re.findall(r'[0-9a-fA-F]{64,}', r.text)
b64_40plus = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', r.text)
print(f"Hex-Strings (>64 chars): {hex64plus[:3]}")
print(f"Base64-Strings (>40 chars): {b64_40plus[:5]}")
# HTML komplett (nach CSS)
idx = r.text.find("</style>")
if idx > 0:
    relevant_html = r.text[idx:]
    print(f"\nHTML nach CSS:\n{relevant_html[:3000]}")
