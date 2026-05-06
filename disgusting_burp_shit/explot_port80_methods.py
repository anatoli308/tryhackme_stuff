#!/usr/bin/env python3
"""
Port 80 - Test OPTIONS, Form-Data, and other content types
"""

import requests
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import re

HOST = "10.81.131.108"
PORT = 80
FLAG_RE = re.compile(r"THM\{[^}]+\}")

CLIENT_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCHFhkwcfgZNVDe
KogLYzQSTTr8wgCi7WNepqeMuTTSXIX22SbzlK/gYlKtPPPxi2JzCkfa9VnTLsTd
3M4ZAL6d0rfo3L0KJ/SKMPq8VnGV9/y5YGyPmgbE1Dy8R2llP0m5GuO4giAoahZX
ePHsPbhNxtQuNW/EiGKcZaz5GQHILEQk2/0ZzqT0e/8jQMljpnbMUoGKe4yhT4JG
QGB7w7wPtQpFhDcASctUO8j3bcOL8tyrPfUcpNKFrkSNY0XT1gqnOuKe29YP0YnC
3bE/m5UPn7atBxP/4FrVRaQvM2S9ta+tZiDU5jP+xU3sBmMLlZByY5KiEeUGkvEz
FjfaMHihAgMBAAECggEAAMiqAvD721dW47Gh7EU+L/Of1afxZ5CeoaXQWcOoutZh
qn5tRHdAv6HJbJb6nESKkMvi0apoG+6g4r/PaDer63v1sEuw2v9jKta8uzlaD5B+
uGOG4LzQSI3J2A625dEImjLlxrAmXC6sqFN3zaboaAbg+/9IUabYEePRBYlhpEv7
jP9IquO6pO3q13gDhot0fS7MM4sTfYKdPfb8qEwYCpsz3Qi7lFdbBqZxz/O/tkPq
giNJNJnHBLmXNOIdSCocMldIhZaPMmcDODPXAehmrru7l/Kh5hnfdK7Njcoph5T4
EJqAPOU7XVSyBeJKiKj1x/S+2jzLn8s3hOKCiBbbwQKBgQC+IvSbRXVA16he1yBE
183VRAALdVRDDTZcFALaexuNfly2SMU9SL/AAFrbNMaQ83y79XtAbDqk8C6YRhyi
z2Il9puVu8G61UB2lWzD5DvDYbb4OS+AroluYZQzeR1+02sZUkR4R0QnfNRQUtMR
3awfBIgf9B6Kr90Dnn/OLmQrYQKBgQC14V2azqz4Nkg4bg1LLk612H2fhwz38Evj
mlMmxAxdIqGJUz+wGb3tSGmGz7fPxmIga9k8n22nMpfZOyyGF9D93LVa+/9NeFEV
DWH5yph+xBN7SSyQMb+Q1xD6gTigLmkIynUXzcucgZB8oUGtexR2IoFu3Li7R9F3
HYpUpsKVQQKBgQCFB3X20TEJbhm6SW+lWwwDY7FYUv3ib/MRl1qrvCh55eg+DUoa
57RpRJZM+m7XadRiuY1DdLXPQtCG778HVmvIPfN7XsNb0eppTYCsyhnaSJq4r2IB
+ZvkI9eJ7/poCsnLDJklQk94BUmS7XAJ9vt/NC99k9JunD7ZUmL/QcwJ4QKBgQCG
a812gJEt0VCHBC8nBU5+70XJBVL8W8h6qrAR0osguluQ1soXKK9KE16KmDJNiV00
gQDI4Tt1etrnXeiGIkv/k4Mlf2EsrGOgn4dtyeHyro+HaolY+KuQLKMLwT1MhYBz
Us4/jYWSYd+bfMLBqFlzBgWLHe4Z2/ZfhqGZ9rWRAQKBgGX7uHz9nUaldXxt4lBn
94FR8D6FJxyKGr0/35XrPE3gc1nDJIQGl62E9vk8eVuBsFgqhm2ISroRSxeRI6ml
djzuBNJ/gQ5hxhj7ifv1ZakiwvxR2D5uJBPU5gve19Fyrq5On6R+KvVR4b+vcZ5A
0HuYuUaGZhtLd9ouH49CvSXj
-----END PRIVATE KEY-----"""

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def rsa_sign(data: bytes, priv_key: RSA.RsaKey) -> bytes:
    digest = SHA256.new(data)
    return pkcs1_15.new(priv_key).sign(digest)

def extract_flag(text: str):
    m = FLAG_RE.search(text)
    return m.group(0) if m else None

client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)

print(f"[*] Target: http://{HOST}:{PORT}\n")

# Test 1: OPTIONS to see what's allowed
print("[*] Test 1: OPTIONS requests")
endpoints = ["/", "/authenticate"]
for ep in endpoints:
    try:
        resp = requests.options(f"http://{HOST}:{PORT}{ep}", timeout=5)
        print(f"    {ep} -> HTTP {resp.status_code}")
        if "Allow" in resp.headers:
            print(f"       Allow: {resp.headers['Allow']}")
        print(f"       Headers: {dict(resp.headers)}\n")
    except Exception as e:
        print(f"    {ep} -> Error: {str(e)[:40]}\n")

# Test 2: GET on root
print("\n[*] Test 2: Simple GET /")
try:
    resp = requests.get(f"http://{HOST}:{PORT}/", timeout=5)
    print(f"    HTTP {resp.status_code}")
    print(f"    Content: {resp.text[:500]}\n")
except Exception as e:
    print(f"    Error: {str(e)[:50]}\n")

# Test 3: Form-encoded POST (not JSON)
print("[*] Test 3: Form-encoded POST")
endpoints = ["/", "/authenticate", "/api/authenticate"]
for endpoint in endpoints:
    data_to_sign = b"authenticate=1"
    signature = rsa_sign(data_to_sign, client_priv)
    
    form_data = {
        "authenticate": "1",
        "signature": b64(signature),
    }
    
    try:
        resp = requests.post(
            f"http://{HOST}:{PORT}{endpoint}",
            data=form_data,  # Form-encoded, NOT JSON
            timeout=5
        )
        print(f"    {endpoint} -> HTTP {resp.status_code}")
        if resp.status_code == 200:
            print(f"       Content: {resp.text[:200]}")
            flag = extract_flag(resp.text)
            if flag:
                print(f"       [FLAG]: {flag}")
    except Exception as e:
        print(f"    {endpoint} -> Error: {str(e)[:40]}")

# Test 4: Try with simple params (no signature)
print("\n[*] Test 4: Simple POST with username (no signature)")
for username in ["admin", "ecorp_admin"]:
    try:
        resp = requests.post(
            f"http://{HOST}:{PORT}/authenticate",
            data={"username": username},
            timeout=5
        )
        if resp.status_code == 200:
            print(f"    username={username} -> HTTP 200")
            print(f"       {resp.text[:200]}")
            flag = extract_flag(resp.text)
            if flag:
                print(f"       [FLAG]: {flag}")
        else:
            print(f"    username={username} -> HTTP {resp.status_code}")
    except Exception as e:
        print(f"    username={username} -> Error: {str(e)[:40]}")
