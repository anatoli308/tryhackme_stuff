import requests, re
s = requests.Session()
s.post("http://10.113.167.230:5000/login", data={"username": "admin"})
r = s.get("http://10.113.167.230:5000/verify")
idx = r.text.rfind("</style>")
body = r.text[idx:] if idx > 0 else r.text
print(body[:4000])
