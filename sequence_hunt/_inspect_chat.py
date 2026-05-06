import re
import requests

TARGET = 'http://10.82.129.17'
SID = 'k6qh5jtubf314jfo61sh1qk0d2'

s = requests.Session()
s.cookies.set('PHPSESSID', SID)

for page in ['chat.php', 'settings.php', 'dashboard.php']:
    r = s.get(f'{TARGET}/{page}', allow_redirects=True, timeout=10)
    print('\n===', page, r.status_code, r.url, '===')
    print('flags:', re.findall(r'THM\{[^}]+\}', r.text))

    # print forms
    forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.I | re.S)
    print('forms:', len(forms))
    for i, f in enumerate(forms[:5], 1):
        action = re.search(r'action=[\"\']([^\"\']+)', f, re.I)
        method = re.search(r'method=[\"\']([^\"\']+)', f, re.I)
        print(f'  form#{i}: action={action.group(1) if action else ""} method={method.group(1) if method else ""}')
        names = re.findall(r'name=[\"\']([^\"\']+)', f, re.I)
        print('   names=', names)

    # print script refs and inline fetch/xhr hints
    scripts = re.findall(r'<script[^>]*src=[\"\']([^\"\']+)', r.text, re.I)
    if scripts:
        print('script src:', scripts)
    for pat in [r'fetch\([^\)]*\)', r'XMLHttpRequest', r'chat', r'message', r'send']:
        m = re.findall(pat, r.text, re.I)
        if m:
            print('hit', pat, 'count', len(m))

open('chat_page_dump.html', 'w', encoding='utf-8').write(s.get(f'{TARGET}/chat.php').text)
print('\nSaved chat_page_dump.html')
