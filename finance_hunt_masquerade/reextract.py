#!/usr/bin/env python3
"""Re-extract decrypted payload from PCAP."""
import sys, hashlib
from scapy.all import rdpcap, TCP, IP, Raw

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
PCAP = r'C:\Users\anato\Downloads\dist\traffic.pcapng'
KEY = 'X9vT3pL2QwE8xR6ZkYhC4s'

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    r = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        r.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(r)

print('Loading PCAP...')
pkts = rdpcap(PCAP)
streams = {}
for p in pkts:
    if p.haslayer(TCP) and p.haslayer(Raw):
        k = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
        streams.setdefault(k, []).append((p[TCP].seq, bytes(p[Raw].load)))
for k in streams:
    streams[k] = b''.join(d for _, d in sorted(streams[k], key=lambda x: x[0]))

hex_chars = set('0123456789abcdefABCDEF')
for k, data in streams.items():
    t = data.decode('ascii', errors='ignore')
    if '/amd.bin' in t:
        rk = (k[2], k[3], k[0], k[1])
        if rk in streams:
            resp = streams[rk]
            hdr_end = resp.find(b'\r\n\r\n')
            body = resp[hdr_end+4:]
            cleaned = ''.join(c for c in body.decode('ascii', errors='ignore').strip() if c in hex_chars)
            payload = bytes.fromhex(cleaned)
            dec = rc4(KEY.encode(), payload)
            is_mz = dec[:2] == b'MZ'
            print(f'Decrypted: {len(dec)} bytes, MZ={is_mz}')
            print(f'SHA-256: {hashlib.sha256(dec).hexdigest()}')
            with open('decrypted_payload.bin', 'wb') as f:
                f.write(dec)
            print('Saved decrypted_payload.bin')
            break
