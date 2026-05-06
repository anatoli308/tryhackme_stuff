"""Probe POST /proof with various size+proof payloads to learn the response shape."""
import urllib.request, json

def post(body, label):
    req = urllib.request.Request('http://10.113.161.234/proof', method='POST')
    req.add_header('Content-Type', 'application/json')
    data = json.dumps(body).encode()
    try:
        r = urllib.request.urlopen(req, data=data, timeout=10)
        b = r.read()
        print(f'--- {label} -> {r.status} ({len(b)} bytes) ---')
        print(repr(b[:400]))
    except urllib.error.HTTPError as e:
        b = e.read()
        print(f'--- {label} -> {e.code} ({len(b)} bytes) ---')
        print(repr(b[:400]))
    except Exception as e:
        print(f'--- {label} -> ERR {e}')
    print()

# baseline: missing fields
post({}, 'empty')
post({'size': 42}, 'size only')
post({'proof': 'a'*42}, 'proof only')
post({'size': 42, 'proof': 'a'*42}, 'size+42-proof')
post({'size': 1, 'proof': 'x'}, 'size 1, x')
post({'size': 4096, 'proof': 'x'}, 'big size leak')
# real wallet from page
post({'size': 42, 'proof': 'bc1q989cy4zp8x9xpxgwpznsxx44u0cxhyjjyp78hj'}, 'real wallet')
# trailing slash
req = urllib.request.Request('http://10.113.161.234/proof/', method='POST')
req.add_header('Content-Type', 'application/json')
try:
    r = urllib.request.urlopen(req, data=json.dumps({'size':42,'proof':'a'*42}).encode(), timeout=10)
    print('trailing slash ->', r.status, repr(r.read()[:300]))
except urllib.error.HTTPError as e:
    print('trailing slash err ->', e.code, repr(e.read()[:300]))
