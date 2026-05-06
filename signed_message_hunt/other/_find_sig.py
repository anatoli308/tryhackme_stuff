#!/usr/bin/env python3
"""
Schritt: Echte Server-Signatur aus Nachrichten holen + Public Key finden
"""
import re, requests

TARGET = "http://10.113.167.230:5000"
s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

# ── Alle möglichen Endpunkte für Nachrichten-Details ─────────────────────────
print("--- Nachrichten-Endpoint Scan ---")
for ep in ["/messages", "/inbox", "/sent", "/message/1", "/message/2",
           "/messages/1", "/messages/2", "/api/messages", "/api/message/1"]:
    r = s.get(f"{TARGET}{ep}")
    if r.status_code != 404:
        sigs = re.findall(r'[0-9a-f]{40,}', r.text)
        print(f"  {ep} → HTTP {r.status_code} | sigs={len(sigs)}", end="")
        if sigs:
            print(f" | first={sigs[0][:60]}")
        else:
            print()

# ── /messages Detail ausgeben ─────────────────────────────────────────────────
print("\n--- /messages HTML (interessante Teile) ---")
r = s.get(f"{TARGET}/messages")
# Alle hex-artigen Strings
hexstrings = re.findall(r'[0-9a-f]{64,}', r.text)
print(f"Hex strings: {hexstrings[:5]}")

# Alle data-* Attribute
data_attrs = re.findall(r'data-[^=]+="([^"]+)"', r.text)
print(f"data-* attrs: {data_attrs[:10]}")

# Links zu Nachrichten
links = re.findall(r'href="([^"]*message[^"]*)"', r.text)
print(f"Message-Links: {links[:10]}")

# Anchor tags
anchors = re.findall(r'<a [^>]+href="([^"]+)"', r.text)
print(f"Alle Links: {[a for a in anchors if a not in ('#', '/', '/login', '/logout', '/about', '/verify', '/compose', '/messages', '/dashboard')][:15]}")

# Vollständiger Text (relevant)
clean = re.sub(r'<style[^>]*>.*?</style>', '', r.text, flags=re.DOTALL)
clean = re.sub(r'<[^>]+>', ' ', clean)
clean = re.sub(r'\s+', ' ', clean).strip()
print(f"\nBody-Text: {clean[200:1500]}")

# ── Compose und dann Nachrichten-ID finden ───────────────────────────────────
print("\n--- POST /compose (mit to_user) ---")
r = s.post(f"{TARGET}/compose", data={
    "to_user": "admin",
    "subject": "sigtest",
    "message": "test message for signature",
})
print(f"HTTP {r.status_code} | Location: {r.headers.get('Location', 'none')}")
# Links in Antwort
links = re.findall(r'href="([^"]+)"', r.text)
msg_links = [l for l in links if any(x in l for x in ['message', 'inbox', 'sent', 'id=', '/msg'])]
print(f"Message-Links in Response: {msg_links[:10]}")

# ── Public Key Endpunkte ──────────────────────────────────────────────────────
print("\n--- Public Key Suche ---")
for ep in ["/public_key", "/key", "/api/public_key", "/static/public.pem",
           "/about", "/about#encryption", "/crypto", "/pki"]:
    r = s.get(f"{TARGET}{ep}")
    if r.status_code != 404:
        # PEM / base64 Blöcke
        pem = re.findall(r'-----BEGIN[^-]+-----[^-]+-----END[^-]+-----', r.text)
        b64_blocks = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', r.text)
        print(f"  {ep} → {r.status_code} | PEM={len(pem)} | b64={len(b64_blocks)}")
        if pem:
            print(f"    PEM: {pem[0][:200]}")
        # Auch Plain-Text nach Key-Material suchen
        if 'key' in r.text.lower() or 'pem' in r.text.lower():
            clean = re.sub(r'<[^>]+>', ' ', r.text)
            idx = clean.lower().find('key')
            print(f"    Key-Kontext: {clean[max(0,idx-50):idx+200]}")
