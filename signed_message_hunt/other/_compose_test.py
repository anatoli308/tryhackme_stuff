#!/usr/bin/env python3
"""
Phase 3: /compose → Signatur holen → /verify analysieren
"""
import hashlib, hmac, re, requests

TARGET = "http://10.113.167.230:5000"
s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "admin"})

# 1. Nachricht composieren und signieren lassen
print("--- POST /compose ---")
r = s.post(f"{TARGET}/compose", data={"subject": "test", "message": "hello world"})
print(f"HTTP {r.status_code}")
# Signatur aus Response extrahieren
sigs_hex = re.findall(r'[0-9a-f]{32,}', r.text)
sig_display = re.findall(r'signature[^<]*<[^>]*>([^<]+)', r.text, re.IGNORECASE)
print(f"Hex-Strings im Body: {sigs_hex[:5]}")
print(f"Signature displays: {sig_display[:3]}")
# Flash messages
flashes = re.findall(r'class="flash[^"]*"[^>]*>\s*(.+?)\s*<', r.text, re.DOTALL)
print(f"Flash messages: {flashes[:3]}")
# Komplett relevante HTML-Abschnitte
snippet = re.search(r'(signed|signature|verify|message)[^<]{0,500}', r.text, re.IGNORECASE)
if snippet:
    print(f"Snippet: {snippet.group()[:300]}")

# Relevanter Teil des Responses
print("\n--- Response body (interessanter Teil) ---")
# Suche nach Cards / result divs
cards = re.findall(r'<div class="[^"]*card[^"]*">(.*?)</div>', r.text, re.DOTALL)
for c in cards[:3]:
    clean = re.sub(r'<[^>]+>', '', c).strip()
    if clean:
        print(f"Card: {clean[:200]}")

# Alle p-Tags
ptags = re.findall(r'<p[^>]*>(.*?)</p>', r.text, re.DOTALL)
for p in ptags[:10]:
    clean = re.sub(r'<[^>]+>', '', p).strip()
    if len(clean) > 3:
        print(f"<p>: {clean[:150]}")

# Alles nach "result" oder "signed"
result_area = re.search(r'(?:result|signed|signature|hmac)[^\n]{0,1000}', r.text, re.IGNORECASE)
if result_area:
    print(f"\nResult area: {result_area.group()[:500]}")

print("\n--- Vollständige Antwort (3000-6000) ---")
print(r.text[3000:6000])
