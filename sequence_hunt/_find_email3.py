import requests, re

s = requests.Session()
s.cookies.set('PHPSESSID', 'k6qh5jtubf314jfo61sh1qk0d2')

r = s.get('http://10.82.129.17/settings.php')
# Print all form inputs
print('=== All inputs in settings.php ===')
for m in re.finditer(r'<input[^>]+>', r.text, re.I):
    print(' ', m.group(0))
print()

# Print all form actions
for m in re.finditer(r'<form[^>]+>', r.text, re.I):
    print('FORM:', m.group(0))
print()

# Check for profile.php or account.php
for path in ['/profile.php', '/account.php', '/user.php', '/me.php']:
    r2 = s.get(f'http://10.82.129.17{path}', allow_redirects=True)
    if r2.status_code == 200 and 'login' not in r2.url:
        print(f'EXISTS: {path}')
        emails = re.findall(r'[\w.]+@[\w.]+', r2.text)
        print('  emails:', emails)

# Look at login page raw
rl = requests.get('http://10.82.129.17/login.php')
print('\n=== login.php inputs ===')
for m in re.finditer(r'<input[^>]+>', rl.text, re.I):
    print(' ', m.group(0))
