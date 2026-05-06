"""
Masquerade Challenge - PCAP & EVTX Analyzer
Analyzes traffic.pcapng for C2 communication and decrypts payloads.
"""

import hashlib
import struct
import os
import sys
import base64
from datetime import datetime, timezone

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# === Paths ===
ARTIFACT_DIR = r"C:\Users\anato\Downloads\dist"
PCAP_FILE = os.path.join(ARTIFACT_DIR, "traffic.pcapng")

# === Known from PowerShell ScriptBlock ===
STAGE1_KEY_STR = "X9vT3pL2QwE8xR6ZkYhC4s"
STAGE1_DOMAIN = "api-edgecloud.xyz"

print("=" * 70)
print("MASQUERADE CHALLENGE ANALYZER")
print("=" * 70)

print("\n[+] STATIC ANALYSIS FROM POWERSHELL SCRIPTBLOCK:")
print(f"    External domain contacted: {STAGE1_DOMAIN}")
print(f"    Encryption algorithm: RC4")
print(f"    Decryption key (stage 1): {STAGE1_KEY_STR}")


def rc4_crypt(key_bytes, data_bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def parse_pcapng(filepath):
    packets = []
    with open(filepath, 'rb') as f:
        data = f.read()
    pos = 0
    link_type = 1
    while pos < len(data):
        if pos + 8 > len(data):
            break
        block_type = struct.unpack_from('<I', data, pos)[0]
        block_len = struct.unpack_from('<I', data, pos + 4)[0]
        if block_len < 12 or pos + block_len > len(data):
            break
        if block_type == 0x00000001:  # IDB
            if block_len >= 20:
                link_type = struct.unpack_from('<H', data, pos + 8)[0]
        elif block_type == 0x00000006:  # EPB
            if block_len >= 28:
                ts_high = struct.unpack_from('<I', data, pos + 12)[0]
                ts_low = struct.unpack_from('<I', data, pos + 16)[0]
                captured_len = struct.unpack_from('<I', data, pos + 20)[0]
                pkt_data = data[pos + 28: pos + 28 + captured_len]
                timestamp_us = (ts_high << 32 | ts_low)
                packets.append((timestamp_us, pkt_data, link_type))
        pos += block_len
        if pos % 4 != 0:
            pos += 4 - (pos % 4)
    return packets


def parse_packet(pkt_data):
    if len(pkt_data) < 14:
        return None
    eth_type = struct.unpack_from('>H', pkt_data, 12)[0]
    if eth_type != 0x0800:
        return None
    ip_data = pkt_data[14:]
    if len(ip_data) < 20:
        return None
    ihl = (ip_data[0] & 0x0F) * 4
    protocol = ip_data[9]
    src_ip = '.'.join(str(b) for b in ip_data[12:16])
    dst_ip = '.'.join(str(b) for b in ip_data[16:20])

    if protocol == 6:  # TCP
        tcp_data = ip_data[ihl:]
        if len(tcp_data) < 20:
            return None
        src_port = struct.unpack_from('>H', tcp_data, 0)[0]
        dst_port = struct.unpack_from('>H', tcp_data, 2)[0]
        seq = struct.unpack_from('>I', tcp_data, 4)[0]
        data_offset = ((tcp_data[12] >> 4) & 0xF) * 4
        flags = tcp_data[13]
        payload = tcp_data[data_offset:]
        return {'proto': 'tcp', 'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': src_port, 'dst_port': dst_port,
                'seq': seq, 'flags': flags, 'payload': payload}
    elif protocol == 17:  # UDP
        udp_data = ip_data[ihl:]
        if len(udp_data) < 8:
            return None
        src_port = struct.unpack_from('>H', udp_data, 0)[0]
        dst_port = struct.unpack_from('>H', udp_data, 2)[0]
        payload = udp_data[8:]
        return {'proto': 'udp', 'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': src_port, 'dst_port': dst_port, 'payload': payload}
    return None


def unchunk(body):
    unchunked = b''
    bpos = 0
    while bpos < len(body):
        line_end = body.find(b'\r\n', bpos)
        if line_end == -1:
            break
        size_str = body[bpos:line_end].decode('ascii', errors='ignore').strip()
        if not size_str:
            bpos = line_end + 2
            continue
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        chunk_start = line_end + 2
        unchunked += body[chunk_start:chunk_start + chunk_size]
        bpos = chunk_start + chunk_size + 2
    return unchunked


def ts_to_str(ts_raw):
    """Convert pcapng timestamp to string. Try microseconds first, then nanoseconds."""
    for divisor in [1_000_000, 1_000_000_000, 1_000, 1]:
        try:
            t = ts_raw / divisor
            if 946684800 < t < 2524608000:  # 2000-01-01 to 2050-01-01
                return datetime.fromtimestamp(t, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (OSError, OverflowError, ValueError):
            continue
    return f"raw_ts={ts_raw}"


# =====================================================================
# Parse PCAP
# =====================================================================
print("\n[+] PARSING PCAP FILE...")
packets = parse_pcapng(PCAP_FILE)
print(f"    Total packets parsed: {len(packets)}")

# =====================================================================
# DNS Queries
# =====================================================================
print("\n[+] DNS QUERIES:")
for ts, pkt_data, _ in packets:
    p = parse_packet(pkt_data)
    if p and p['proto'] == 'udp' and p['dst_port'] == 53:
        dns = p['payload']
        if len(dns) < 12:
            continue
        pos2 = 12
        name_parts = []
        while pos2 < len(dns):
            length = dns[pos2]
            if length == 0:
                break
            pos2 += 1
            name_parts.append(dns[pos2:pos2+length].decode('ascii', errors='ignore'))
            pos2 += length
        domain = '.'.join(name_parts)
        print(f"    {p['src_ip']} -> {domain}")

# =====================================================================
# TCP flows
# =====================================================================
print("\n[+] ANALYZING TCP FLOWS...")
tcp_with_payload = []
for ts, pkt_data, _ in packets:
    p = parse_packet(pkt_data)
    if p and p['proto'] == 'tcp' and len(p['payload']) > 0:
        p['timestamp'] = ts
        tcp_with_payload.append(p)

flows = {}
for pkt in tcp_with_payload:
    key = (pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
    flows.setdefault(key, []).append(pkt)

print(f"    TCP flows with data: {len(flows)}")
for fk, pkts in flows.items():
    total = sum(len(p['payload']) for p in pkts)
    if total > 0:
        print(f"      {fk[0]}:{fk[1]} -> {fk[2]}:{fk[3]} ({len(pkts)} pkts, {total} bytes)")

# =====================================================================
# HTTP Requests
# =====================================================================
print("\n[+] HTTP REQUESTS:")
for pkt in tcp_with_payload:
    text = pkt['payload'].decode('ascii', errors='ignore')
    if text.startswith(('GET ', 'POST ', 'PUT ', 'HEAD ', 'DELETE ', 'PATCH ')):
        first_line = text.split('\r\n')[0]
        host = ''
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
        ts_str = ts_to_str(pkt['timestamp'])
        print(f"    [{ts_str}] {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        print(f"      {first_line} (Host: {host})")
        # Print body for POST
        if text.startswith('POST '):
            body_start = text.find('\r\n\r\n')
            if body_start > 0:
                body = text[body_start+4:].strip()
                if body:
                    print(f"      BODY: {body[:500]}")

# =====================================================================
# HTTP Responses
# =====================================================================
print("\n[+] HTTP RESPONSES:")
response_data = {}
for fk, pkts in flows.items():
    first_text = pkts[0]['payload'].decode('ascii', errors='ignore')
    if first_text.startswith('HTTP/'):
        sorted_pkts = sorted(pkts, key=lambda p: p['seq'])
        reassembled = b''
        for p in sorted_pkts:
            reassembled += p['payload']
        response_data[fk] = (reassembled, sorted_pkts)

        status_line = first_text.split('\r\n')[0]
        ts_str = ts_to_str(sorted_pkts[0]['timestamp'])
        print(f"    [{ts_str}] {fk[0]}:{fk[1]} -> {fk[2]}:{fk[3]}: {status_line}")

        hdr_end = reassembled.find(b'\r\n\r\n')
        if hdr_end > 0:
            headers = reassembled[:hdr_end].decode('ascii', errors='ignore')
            for hline in headers.split('\r\n'):
                print(f"      {hline}")

# =====================================================================
# Decrypt amd.bin
# =====================================================================
print("\n" + "=" * 70)
print("[+] DECRYPTING STAGE 1 PAYLOAD (amd.bin)...")
print("=" * 70)

hex_chars = set('0123456789abcdefABCDEF')

for fk, (reassembled, sorted_pkts) in response_data.items():
    hdr_end = reassembled.find(b'\r\n\r\n')
    if hdr_end == -1:
        continue

    headers = reassembled[:hdr_end].decode('ascii', errors='ignore')
    body = reassembled[hdr_end + 4:]

    if not body or len(body) < 10:
        continue

    # Date header
    date_header = ''
    for hline in headers.split('\r\n'):
        if hline.lower().startswith('date:'):
            date_header = hline.split(':', 1)[1].strip()

    # Handle chunked
    if 'transfer-encoding: chunked' in headers.lower():
        body = unchunk(body)

    # Try hex decode
    body_text = body.decode('ascii', errors='ignore').strip()
    cleaned = ''.join(c for c in body_text if c not in ' \r\n\t')

    if len(cleaned) > 50 and len(cleaned) % 2 == 0 and all(c in hex_chars for c in cleaned):
        print(f"\n    [!] Hex payload in {fk[0]}:{fk[1]} -> {fk[2]}:{fk[3]}")
        print(f"    [!] Date header: {date_header}")

        ts_str = ts_to_str(sorted_pkts[0]['timestamp'])
        print(f"    [!] Packet timestamp: {ts_str}")

        payload_bytes = bytes.fromhex(cleaned)
        key = STAGE1_KEY_STR.encode('utf-8')
        decrypted = rc4_crypt(key, payload_bytes)

        sha256 = hashlib.sha256(decrypted).hexdigest()
        print(f"    [!] SHA-256 of decrypted payload: {sha256}")

        if decrypted[:2] == b'MZ':
            print("    [!] Payload is a PE executable (MZ header)")
        else:
            print(f"    [!] Start hex: {decrypted[:40].hex()}")
            print(f"    [!] Start text: {decrypted[:100].decode('ascii', errors='replace')}")

        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_payload.bin")
        with open(out_path, 'wb') as f:
            f.write(decrypted)
        print(f"    [!] Saved to: {out_path}")

# =====================================================================
# C2 Analysis - non-HTTP flows
# =====================================================================
print("\n" + "=" * 70)
print("[+] C2 ANALYSIS - NON-HTTP FLOWS")
print("=" * 70)

for fk, pkts in flows.items():
    first_text = pkts[0]['payload'].decode('ascii', errors='ignore')
    if first_text.startswith(('HTTP/', 'GET ', 'POST ', 'PUT ')):
        continue
    total = sum(len(p['payload']) for p in pkts)
    if total < 5:
        continue
    sorted_pkts = sorted(pkts, key=lambda p: p['timestamp'])
    reassembled = b''
    for p in sorted_pkts:
        reassembled += p['payload']
    ts_str = ts_to_str(sorted_pkts[0]['timestamp'])
    print(f"\n  [{ts_str}] {fk[0]}:{fk[1]} -> {fk[2]}:{fk[3]} ({total} bytes)")
    print(f"    Hex: {reassembled[:200].hex()}")
    print(f"    ASCII: {reassembled[:200].decode('ascii', errors='replace')}")

# =====================================================================
# Full HTTP dump for manual analysis
# =====================================================================
print("\n" + "=" * 70)
print("[+] FULL HTTP BODY DUMP")
print("=" * 70)

for pkt in tcp_with_payload:
    text = pkt['payload'].decode('ascii', errors='ignore')
    if text.startswith(('GET ', 'POST ', 'PUT ', 'PATCH ', 'DELETE ')):
        ts_str = ts_to_str(pkt['timestamp'])
        print(f"\n  --- REQUEST [{ts_str}] from {pkt['src_ip']} ---")
        print(f"  {text[:3000]}")

for fk, (reassembled, sorted_pkts) in response_data.items():
    ts_str = ts_to_str(sorted_pkts[0]['timestamp'])
    hdr_end = reassembled.find(b'\r\n\r\n')
    body = reassembled[hdr_end+4:] if hdr_end > 0 else b''
    headers = reassembled[:hdr_end].decode('ascii', errors='ignore') if hdr_end > 0 else ''
    
    if 'transfer-encoding: chunked' in headers.lower():
        body = unchunk(body)
    
    print(f"\n  --- RESPONSE [{ts_str}] from {fk[0]}:{fk[1]} ---")
    print(f"  Headers: {headers[:500]}")
    print(f"  Body ({len(body)} bytes): {body[:3000].decode('ascii', errors='replace')}")

# =====================================================================
# Try decrypting C2 commands with various approaches
# =====================================================================
print("\n" + "=" * 70)
print("[+] C2 COMMAND DECRYPTION ATTEMPTS")
print("=" * 70)

# Collect all POST bodies and response bodies
post_bodies = []
for pkt in tcp_with_payload:
    text = pkt['payload'].decode('ascii', errors='ignore')
    if text.startswith('POST '):
        body_start = text.find('\r\n\r\n')
        if body_start > 0:
            body = text[body_start+4:].strip()
            if body:
                post_bodies.append((pkt, body))

response_bodies = []
for fk, (reassembled, sorted_pkts) in response_data.items():
    hdr_end = reassembled.find(b'\r\n\r\n')
    if hdr_end > 0:
        headers = reassembled[:hdr_end].decode('ascii', errors='ignore')
        body = reassembled[hdr_end+4:]
        if 'transfer-encoding: chunked' in headers.lower():
            body = unchunk(body)
        if body:
            response_bodies.append((fk, sorted_pkts, body))

# Try decrypting all collected data with RC4 + stage1 key
for pkt, body in post_bodies:
    print(f"\n  POST from {pkt['src_ip']}:{pkt['src_port']}:")
    print(f"    Raw: {body[:300]}")
    
    # Try base64
    try:
        b64_decoded = base64.b64decode(body)
        print(f"    Base64 decoded hex: {b64_decoded[:100].hex()}")
        # Try RC4 on base64 decoded
        key = STAGE1_KEY_STR.encode('utf-8')
        dec = rc4_crypt(key, b64_decoded)
        print(f"    RC4+base64: {dec[:200].decode('ascii', errors='replace')}")
    except Exception as e:
        print(f"    Base64 failed: {e}")
    
    # Try hex decode
    cleaned_body = ''.join(c for c in body if c in '0123456789abcdefABCDEF')
    if len(cleaned_body) > 10 and len(cleaned_body) % 2 == 0:
        try:
            hex_decoded = bytes.fromhex(cleaned_body)
            key = STAGE1_KEY_STR.encode('utf-8')
            dec = rc4_crypt(key, hex_decoded)
            print(f"    RC4+hex: {dec[:200].decode('ascii', errors='replace')}")
        except Exception as e:
            print(f"    Hex failed: {e}")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
