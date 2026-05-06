import requests
s = requests.Session()
s.post("http://10.113.167.230:5000/login", data={"username": "admin"})
r = s.get("http://10.113.167.230:5000/debug")
print(r.text)
