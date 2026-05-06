import requests, socket, concurrent.futures as cf
T='10.114.144.103'
B=f'http://{T}:3000'

# wider port scan
def s(p):
    try:
        with socket.create_connection((T,p),timeout=1):
            return p
    except: return None
ports=list(range(1,1025))+list(range(2000,2400))+list(range(3000,3100))+list(range(4000,4100))+list(range(5000,5100))+list(range(7000,7100))+list(range(8000,8100))+list(range(8080,8090))+[8443,8888,9000,9090,9100,9200,9300,11211,27017,27018,5984,6379,5432,3306,1433,2375,2376,7860,8501,8502,9999,10000,3389,5900]
opens=[]
with cf.ThreadPoolExecutor(300) as ex:
    for r in ex.map(s,ports):
        if r: opens.append(r)
print('OPEN PORTS:', sorted(opens))

# build manifests
for p in [
    '/_next/static/3WpzTMYEK9QGOeqIBQxrR/_buildManifest.js',
    '/_next/static/3WpzTMYEK9QGOeqIBQxrR/_ssgManifest.js',
    '/_buildManifest.js',
    '/_next/static/chunks/app-paths-manifest.json',
    '/_next/static/chunks/pages-manifest.json',
    '/_next/static/chunks/middleware-manifest.json',
    '/_next/static/chunks/server/middleware-manifest.json',
    '/_next/data/3WpzTMYEK9QGOeqIBQxrR/index.json',
]:
    try:
        r=requests.get(B+p,timeout=4)
        print(r.status_code, len(r.content), p, '--', r.text[:100].replace('\n',' ') if r.status_code==200 else '')
    except Exception as e:
        print('ERR',p,e)
