#!/usr/bin/env python3
"""
Minimal exploit test: ROT13 + AES-CBC + random key
Kein Bruteforce, keine RSA komplexität.
"""

import base64
import os
import re
import urllib.parse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = "10.81.188.92"
PORT = 80
USE_HTTPS = True
FIXED_IV = b"0000000000000000"
FLAG_RE = re.compile(r"THM\{[^}]+\}")


def base_url():
    scheme = "https" if USE_HTTPS else "http"
    return f"{scheme}://{HOST}:{PORT}"


def flip_scheme():
    global USE_HTTPS
    USE_HTTPS = not USE_HTTPS


def rot13(text: str) -> str:
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr(base + (ord(c) - base + 13) % 26))
        else:
            result.append(c)
    return "".join(result)


def encrypt_aes(plain: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)
    return cipher.encrypt(pad(plain, AES.block_size))


def decrypt_aes(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def encode_param(data: bytes) -> str:
    return urllib.parse.quote(base64.b64encode(data).decode())


def decode_param(value: str) -> bytes:
    return base64.b64decode(urllib.parse.unquote(value))


def extract_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def try_authenticate(session: requests.Session, username: str, secret: str, endpoint: str) -> bool:
    """Try /authenticate with multiple payload variants. Return True if flag found."""
    url = f"{base_url()}{endpoint}"
    headers = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    
    # Try both: plain and ROT13 versions
    payload_variants = [
        ("plain", f"username={username}&secret={secret}"),
        ("rot13-both", f"{rot13('username')}={rot13(username)}&{rot13('secret')}={rot13(secret)}"),
        ("rot13-values", f"username={rot13(username)}&secret={rot13(secret)}"),
    ]

    for variant_name, plain_str in payload_variants:
        plain = plain_str.encode("utf-8")
        key = os.urandom(16)
        encrypted = encrypt_aes(plain, key)

        mac = encode_param(key)
        data = encode_param(encrypted)
        body = f"mac={mac}&data={data}"

        print(f"[*] {variant_name:15} -> {url}")
        print(f"    Payload: {plain_str}")

        try:
            resp = session.post(url, data=body, headers=headers, timeout=15, verify=False)
        except requests.exceptions.SSLError as exc:
            if "WRONG_VERSION_NUMBER" in str(exc):
                print(f"    [SSL err, retry HTTP]")
                flip_scheme()
                url_retry = f"{base_url()}{endpoint}"
                try:
                    resp = session.post(url_retry, data=body, headers=headers, timeout=15, verify=False)
                except requests.RequestException:
                    continue
            else:
                print(f"    [SSL error: {str(exc)[:40]}]")
                continue
        except requests.RequestException as exc:
            print(f"    [Network error: {str(exc)[:40]}]")
            continue

        print(f"    HTTP {resp.status_code} | {len(resp.text)} bytes", end="")

        # Try to extract flag from raw response
        flag = extract_flag(resp.text)
        if flag:
            print(f" | FLAG FOUND: {flag}")
            return True

        # Try to decrypt response
        result_match = re.search(r"(?:result|data|ct)=([^&\s]+)", resp.text)
        if result_match:
            try:
                ct = decode_param(result_match.group(1))
                plain_resp = decrypt_aes(ct, key).decode("utf-8", errors="replace")
                # Response might also be ROT13-encrypted
                plain_resp_decoded = rot13(plain_resp)
                print(f"\n    Encrypted: {plain_resp[:80]}")
                print(f"    Decrypted: {plain_resp_decoded[:100]}")
                flag = extract_flag(plain_resp_decoded)
                if flag:
                    print(f"    [+] FLAG FOUND: {flag}")
                    return True
            except Exception as e:
                print(f"\n    [Decrypt failed: {str(e)[:40]}]")
                continue
        
        if 200 <= resp.status_code < 300:
            print(f"\n    SUCCESS! Body:\n{resp.text[:300]}")
            return True
        
        print()

    return False


def main():
    endpoints = [
        "/authenticate",
        "/login",
    ]

    username = "ecorp_admin"
    secret = "THM{Breaking.Custom.Crypto.Is.Fun}"

    print(f"[*] Target: {base_url()}")
    print(f"[*] Username: {username}")
    print(f"[*] Secret: {secret}\n")

    with requests.Session() as session:
        for ep in endpoints:
            print(f"\n=== Testing {ep} ===")
            if try_authenticate(session, username, secret, ep):
                print(f"\n[+] SUCCESS on {ep}!")
                return
    
    print("\n[!] No flag found on any endpoint.")


if __name__ == "__main__":
    main()
