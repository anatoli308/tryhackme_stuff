import requests

urls = [
    'http://10.82.159.192:10000/',
    'http://10.82.159.192:10000/customapi',
]

for url in urls:
    try:
        r = requests.get(url, timeout=6)
        print(f'[DIRECT {r.status_code}] {url} ({len(r.text)}b)')
        print(r.text[:120].replace('\n', ' '))
    except Exception as e:
        print(f'[ERR] {url}: {e}')
