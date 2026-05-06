#!/usr/bin/env python3
"""
Phase 2: Flask Session Forgery + /compose /verify Formular-Analyse
"""
import base64, json, re, requests

TARGET = "http://10.113.167.230:5000"
s = requests.Session()

# Normal einloggen
r = s.post(f"{TARGET}/login", data={"username": "admin"})
session_cookie = s.cookies.get("session")
print(f"Flask Session Cookie: {session_cookie}")

# Flask Session dekodieren (kein Secret nötig für den Payload-Teil)
parts = session_cookie.split(".")
payload_b64 = parts[0]
payload_b64 += "=" * (-len(payload_b64) % 4)
try:
    decoded = base64.urlsafe_b64decode(payload_b64)
    print(f"Session Payload: {decoded}")
except Exception as e:
    print(f"Decode error: {e}")

# /compose Formular-Felder analysieren
print("\n--- /compose HTML Formular ---")
r = s.get(f"{TARGET}/compose")
inputs = re.findall(r'<input[^>]+>', r.text)
textareas = re.findall(r'<textarea[^>]+>', r.text)
forms = re.findall(r'<form[^>]+>', r.text)
print(f"Forms: {forms}")
print(f"Inputs: {inputs}")
print(f"Textareas: {textareas}")

# /verify Formular-Felder analysieren  
print("\n--- /verify HTML Formular ---")
r = s.get(f"{TARGET}/verify")
inputs = re.findall(r'<input[^>]+>', r.text)
textareas = re.findall(r'<textarea[^>]+>', r.text)
forms = re.findall(r'<form[^>]+>', r.text)
print(f"Forms: {forms}")
print(f"Inputs: {inputs}")
print(f"Textareas: {textareas}")
# Auch die Script-Tags
scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
for sc in scripts:
    if sc.strip():
        print(f"Script: {sc[:300]}")

# Dashboard analysieren
print("\n--- /dashboard ---")
r = s.get(f"{TARGET}/dashboard")
print(r.text[2000:4000])
