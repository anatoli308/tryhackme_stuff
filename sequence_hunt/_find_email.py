import requests, re

s = requests.Session()
s.cookies.set('PHPSESSID', 'k6qh5jtubf314jfo61sh1qk0d2')

# Check settings page for email display
r = s.get('http://10.82.129.17/settings.php')
# Look for email fields or displayed email
for line in r.text.splitlines():
    if 'email' in line.lower() or '@' in line:
        print(repr(line.strip()))

print('\n--- Also checking dump.txt ---')
r2 = requests.get('http://10.82.129.17/mail/dump.txt')
# Find any mod-related lines
for line in r2.text.splitlines():
    if 'mod' in line.lower() or '@' in line:
        print(repr(line.strip()))
