#!/usr/bin/env python3
"""
Signed Messages — Key Reconstruction + Flag
============================================
Debug-Log verrät den deterministischen Key-Gen-Algorithmus:

  seed = "{username}_lovenote_2026_valentine"
  p    = nextprime( int(SHA256(seed)) )
  q    = nextprime( int(SHA256(SHA256(seed + b"pki"))) )
  n    = p * q
  e    = 65537
  d    = modinv(e, (p-1)*(q-1))
"""

import hashlib, re, requests
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as CryptoSHA256

TARGET   = "http://10.113.167.230:5000"
USERNAME = "admin"
SEED     = f"{USERNAME}_lovenote_2026_valentine".encode()

# ── 1. Key rekonstruieren ─────────────────────────────────────────────────────

print("[1] Rekonstruiere RSA-Key aus Seed …")

# Prime p
hash_p  = hashlib.sha256(SEED).digest()
p_start = int.from_bytes(hash_p, "big")
# Auf 1024 Bit strecken (High-Bit setzen) — typisch für naive Implementierungen
p_start_1024 = p_start | (1 << 1023)
p = nextprime(p_start_1024)
print(f"  p ({p.bit_length()} bit): {hex(p)[:40]}")

# Prime q
modified_seed = hashlib.sha256(SEED + b"pki").digest()
hash_q        = hashlib.sha256(modified_seed).digest()
q_start       = int.from_bytes(hash_q, "big")
q_start_1024  = q_start | (1 << 1023)
q = nextprime(q_start_1024)
print(f"  q ({q.bit_length()} bit): {hex(q)[:40]}")

e = 65537
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d, p, q))
print(f"  n ({n.bit_length()} bit)")
print(f"  Key rekonstruiert!")

# Fallback: falls 1024-Bit-Strecken nicht stimmt, auch 256-Bit versuchen
# (wird weiter unten automatisch probiert)
p_256 = nextprime(p_start)
q_256 = nextprime(int.from_bytes(hash_q, "big"))
key_256 = RSA.construct((p_256 * q_256, e, pow(e, -1, (p_256-1)*(q_256-1)), p_256, q_256))

# ── 2. /compose verwenden um Beispiel-Signatur zu holen ──────────────────────

print("\n[2] Login + /compose aufrufen …")
s = requests.Session()
s.post(f"{TARGET}/login", data={"username": USERNAME})

# /compose Formularfelder: subject, message  (recipient wird als hidden field gesucht)
# Zunächst HTML analysieren
r = s.get(f"{TARGET}/compose")
all_inputs = re.findall(r'name="([^"]+)"', r.text)
print(f"  Formular-Felder: {all_inputs}")

# Nachricht senden mit allen möglichen Feldern
r = s.post(f"{TARGET}/compose", data={
    "subject":   "test",
    "message":   "hello",
    "recipient": "admin",
    "to":        "admin",
})
print(f"  POST /compose → HTTP {r.status_code}")

# Signatur aus Response holen
sigs_hex = re.findall(r'[0-9a-f]{64,}', r.text)
flash_msgs = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', r.text, re.DOTALL)
for f in flash_msgs:
    print(f"  Flash: {re.sub(chr(60)+'[^>]+'+chr(62), '', f).strip()[:200]}")
if sigs_hex:
    print(f"  Signaturen im Body: {sigs_hex[:3]}")

# Interessanter Body-Teil
print(r.text[4500:6000])

# ── 3. Eigene Signatur erstellen und bei /verify einreichen ──────────────────

print("\n[3] Signiere Nachrichten mit rekonstruiertem Key …")

def sign_message(key_obj, message: str) -> str:
    h = CryptoSHA256.new(message.encode())
    sig = pkcs1_15.new(key_obj).sign(h)
    return sig.hex()

test_msgs = [
    "hello",
    "admin",
    "get_flag",
    "flag",
    "I am admin",
]

for attempt_key, label in [(key, "1024-bit"), (key_256, "256-bit")]:
    print(f"\n  --- Key-Variante: {label} ---")
    for msg in test_msgs:
        try:
            sig_hex = sign_message(attempt_key, msg)
        except Exception as exc:
            print(f"  Sign error: {exc}")
            break

        r = s.post(f"{TARGET}/verify", data={"message": msg, "signature": sig_hex})
        # Flag suchen
        flags = re.findall(r'THM\{[^}]+\}|flag\{[^}]+\}|FLAG\{[^}]+\}', r.text, re.IGNORECASE)
        if flags:
            print(f"\n  *** FLAG: {flags[0]}\n")
        # Flash-Messages
        flashes = re.findall(r'class="flash[^"]*"[^>]*>(.*?)</div>', r.text, re.DOTALL)
        for f in flashes:
            clean = re.sub(r'<[^>]+>', '', f).strip()
            if clean:
                print(f"  [{label}] msg='{msg}' → Flash: {clean[:150]}")
        # Versteckte Werte / interessante Daten
        hidden = re.findall(r'value="([^"]{8,})"', r.text)
        if hidden:
            print(f"  hidden: {hidden[:2]}")

# ── 4. /messages Endpoint prüfen ─────────────────────────────────────────────

print("\n[4] /messages …")
r = s.get(f"{TARGET}/messages")
print(f"HTTP {r.status_code}")
flags = re.findall(r'THM\{[^}]+\}|flag\{[^}]+\}', r.text, re.IGNORECASE)
if flags:
    print(f"*** FLAG in /messages: {flags[0]}")
else:
    # Interessante Teile
    ptags = re.findall(r'<(?:p|td|span|div)[^>]*>(.*?)</(?:p|td|span|div)>', r.text, re.DOTALL)
    for p in ptags[:15]:
        clean = re.sub(r'<[^>]+>', '', p).strip()
        if len(clean) > 5 and "font" not in clean and "color" not in clean:
            print(f"  {clean[:120]}")
