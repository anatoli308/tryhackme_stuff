import re
import requests

TARGET = 'http://10.82.129.17'
SID = 'k6qh5jtubf314jfo61sh1qk0d2'

s = requests.Session()
s.cookies.set('PHPSESSID', SID)
r = s.get(f'{TARGET}/dashboard.php', allow_redirects=True, timeout=10)
html = r.text

# dump around table / rows
for m in re.finditer(r'<tr>.*?</tr>', html, re.I | re.S):
    row = m.group(0)
    txt = re.sub(r'<[^>]+>', ' ', row)
    txt = ' '.join(txt.split())
    if txt:
        print(txt)

print('\nnavbar snippet:')
idx = html.find('navbar-text')
print(html[idx:idx+250])
