#!/usr/bin/env python3
"""
Port 80 WebSocket Client for RSA Challenge
WebSockify server - try to establish handshake and send RSA-authenticated payload
"""

import base64
import json
import re
import struct
import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

HOST = "10.81.131.108"
PORT = 80
FLAG_RE = re.compile(r"THM\{[^}]+\}", re.IGNORECASE)

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

def try_raw_socket():
    """Try raw socket connection to WebSockify."""
    print("[*] Attempting raw socket connection to WebSockify\n")
    
    client_priv = RSA.import_key(CLIENT_PRIVATE_KEY_PEM)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        
        # Try 1: Send simple HTTP request to see response
        print("\n[*] Sending HTTP request...")
        http_request = b"POST /RFB HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.send(http_request)
        
        response = sock.recv(1024)
        print(f"[+] Response (first 200 bytes):")
        print(response[:200])
        
        # Check for flag
        text_response = response.decode('utf-8', errors='ignore')
        flag = extract_flag(text_response)
        if flag:
            print(f"[FLAG FOUND]: {flag}")
            return True
        
        sock.close()
    except Exception as e:
        print(f"[-] Error: {str(e)}")
    
    return False

def try_websocket_handshake():
    """Try WebSocket upgrade handshake."""
    print("\n[*] Attempting WebSocket handshake\n")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        print(f"[+] Connected")
        
        # WebSocket handshake
        ws_request = (
            "GET / HTTP/1.1\r\n"
            "Host: 10.81.131.108:80\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: http://localhost\r\n"
            "\r\n"
        )
        
        print("[*] Sending WebSocket upgrade request...")
        sock.send(ws_request.encode())
        
        response = sock.recv(4096)
        print(f"[+] Response:")
        print(response.decode('utf-8', errors='ignore')[:500])
        
        # Check for flag
        text_response = response.decode('utf-8', errors='ignore')
        flag = extract_flag(text_response)
        if flag:
            print(f"[FLAG FOUND]: {flag}")
            return True
        
        sock.close()
    except Exception as e:
        print(f"[-] Error: {str(e)}")
    
    return False

def try_vnc_rfb():
    """Try VNC RFB protocol (WebSockify's native protocol)."""
    print("\n[*] Attempting VNC RFB protocol\n")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        print(f"[+] Connected")
        
        # WebSockify expects RFB (Remote Frame Buffer) protocol
        # Send a minimal RFB client init
        response = sock.recv(1024)
        print(f"[+] Server greeting: {response[:100]}")
        
        text_response = response.decode('utf-8', errors='ignore')
        flag = extract_flag(text_response)
        if flag:
            print(f"[FLAG FOUND]: {flag}")
            return True
        
        sock.close()
    except Exception as e:
        print(f"[-] Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    print(f"[*] Target: {HOST}:{PORT} (WebSockify Server)\n")
    
    if try_raw_socket():
        exit(0)
    
    if try_websocket_handshake():
        exit(0)
    
    if try_vnc_rfb():
        exit(0)
    
    print("\n[!] No success with WebSocket/WebSockify protocols")
    print("[*] Note: WebSockify is a VNC proxy - may not be the actual challenge")
    print("[*] The RSA challenge might be running on a different port/endpoint")
