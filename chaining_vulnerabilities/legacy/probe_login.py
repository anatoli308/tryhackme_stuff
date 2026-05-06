import requests

base = 'http://10.82.159.192'
paths = ['/login', '/login.php', '/register', '/register.php', '/user',
         '/account', '/auth', '/signin', '/profile', '/dashboard',
         '/home', '/app', '/library', '/books', '/index.php', '/user/login',
         '/users/login', '/auth/login', '/api/login']

for p in paths:
    try:
        r = requests.get(base + p, timeout=6, allow_redirects=False)
        loc = r.headers.get('Location', '')
        print(f'[{r.status_code}] {p}  ({len(r.text)}b)  {loc}')
    except Exception as e:
        print(f'[ERR] {p}: {e}')
