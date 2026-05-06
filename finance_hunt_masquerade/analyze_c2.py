"""
Masquerade Challenge - Phase 2: Scapy-based PCAP Analysis
Proper TCP stream reassembly + C2 command decryption
"""
import hashlib
import base64
import sys
import os
from scapy.all import rdpcap, TCP, UDP, DNS, DNSQR, IP, Raw
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PCAP_FILE = r"C:\Users\anato\Downloads\dist\traffic.pcapng"
STAGE1_KEY = "X9vT3pL2QwE8xR6ZkYhC4s"

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

print("[+] Loading PCAP with scapy...")
packets = rdpcap(PCAP_FILE)
print(f"    {len(packets)} packets loaded")

# =====================================================================
# DNS
# =====================================================================
print("\n[+] DNS Queries:")
for pkt in packets:
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('ascii', errors='ignore')
        print(f"    {pkt[IP].src} -> {qname}")

# =====================================================================
# Reassemble TCP streams
# =====================================================================
print("\n[+] Reassembling TCP streams...")
streams = {}
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        ip = pkt[IP]
        tcp = pkt[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if key not in streams:
            streams[key] = []
        streams[key].append({
            'seq': tcp.seq,
            'data': bytes(pkt[Raw].load),
            'time': float(pkt.time)
        })

# Sort each stream by sequence number and reassemble
reassembled = {}
for key, pkts in streams.items():
    sorted_pkts = sorted(pkts, key=lambda p: p['seq'])
    data = b''
    for p in sorted_pkts:
        data += p['data']
    reassembled[key] = {
        'data': data,
        'time': sorted_pkts[0]['time'],
        'pkts': sorted_pkts
    }
    if len(data) > 0:
        src_ip, src_port, dst_ip, dst_port = key
        text_preview = data[:80].decode('ascii', errors='replace')
        print(f"    {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({len(data)} bytes) [{text_preview[:60]}]")

# =====================================================================
# Extract HTTP requests and responses
# =====================================================================
print("\n" + "=" * 70)
print("[+] HTTP ANALYSIS")
print("=" * 70)

http_sessions = []  # (request_key, response_key, req_data, resp_data)

for key, info in reassembled.items():
    data = info['data']
    text = data.decode('ascii', errors='ignore')
    
    if text.startswith(('GET ', 'POST ')):
        first_line = text.split('\r\n')[0]
        host = ''
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
        
        ts = datetime.fromtimestamp(info['time'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        src_ip, src_port, dst_ip, dst_port = key
        print(f"\n  [{ts}] {first_line} (Host: {host})")
        
        # Find matching response
        resp_key = (dst_ip, dst_port, src_ip, src_port)
        if resp_key in reassembled:
            resp = reassembled[resp_key]
            resp_text = resp['data'].decode('ascii', errors='ignore')
            if resp_text.startswith('HTTP/'):
                status = resp_text.split('\r\n')[0]
                print(f"    Response: {status}")
                
                # Extract headers and body
                hdr_end = resp['data'].find(b'\r\n\r\n')
                if hdr_end > 0:
                    headers = resp['data'][:hdr_end].decode('ascii', errors='ignore')
                    body = resp['data'][hdr_end+4:]
                    
                    # Print key headers
                    for hline in headers.split('\r\n')[1:]:
                        if hline.lower().startswith(('content-length:', 'date:', 'etag:', 'content-type:')):
                            print(f"    {hline}")
                    
                    print(f"    Body size: {len(body)} bytes")
                    http_sessions.append((key, resp_key, data, resp['data'], body, headers, info['time']))

# =====================================================================
# Find and decrypt the amd.bin payload  
# =====================================================================
print("\n" + "=" * 70)
print("[+] STAGE 1: Finding amd.bin payload")
print("=" * 70)

hex_chars = set('0123456789abcdefABCDEF')

for req_key, resp_key, req_data, resp_data, body, headers, req_time in http_sessions:
    req_text = req_data.decode('ascii', errors='ignore')
    if '/amd.bin' in req_text:
        print(f"\n  [!] Found amd.bin request!")
        
        # Date header for timestamp answer
        for hline in headers.split('\r\n'):
            if hline.lower().startswith('date:'):
                print(f"  [!] Server response timestamp: {hline}")
        
        # Check if body is hex
        body_text = body.decode('ascii', errors='ignore').strip()
        cleaned = ''.join(c for c in body_text if c not in ' \r\n\t')
        
        print(f"  [!] Body length: {len(body)} bytes")
        print(f"  [!] Cleaned hex length: {len(cleaned)}")
        print(f"  [!] Body preview: {body_text[:200]}")
        
        is_hex = len(cleaned) > 0 and len(cleaned) % 2 == 0 and all(c in hex_chars for c in cleaned)
        
        if is_hex:
            print(f"  [!] Body IS hex-encoded ({len(cleaned)} hex chars = {len(cleaned)//2} bytes)")
            payload_bytes = bytes.fromhex(cleaned)
            key_bytes = STAGE1_KEY.encode('utf-8')
            decrypted = rc4_crypt(key_bytes, payload_bytes)
            sha256 = hashlib.sha256(decrypted).hexdigest()
            print(f"  [!] SHA-256 of decrypted payload: {sha256}")
            if decrypted[:2] == b'MZ':
                print("  [!] Payload is PE executable (MZ)")
            else:
                print(f"  [!] Start: {decrypted[:50].hex()}")
                print(f"  [!] Text: {decrypted[:100].decode('ascii', errors='replace')}")
            
            out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_payload.bin")
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            print(f"  [!] Saved: {out_path}")
        else:
            # Maybe body is binary already
            sha256_raw = hashlib.sha256(body).hexdigest()
            print(f"  [!] Body is NOT hex. SHA256 of raw body: {sha256_raw}")
            print(f"  [!] First 100 hex bytes: {body[:100].hex()}")
            
            # Try RC4 on raw body
            key_bytes = STAGE1_KEY.encode('utf-8')
            decrypted = rc4_crypt(key_bytes, body)
            sha256_dec = hashlib.sha256(decrypted).hexdigest()
            print(f"  [!] SHA256 after RC4: {sha256_dec}")
            if decrypted[:2] == b'MZ':
                print("  [!] RC4(raw body) = PE executable!")
                out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_payload.bin")
                with open(out_path, 'wb') as f:
                    f.write(decrypted)

# =====================================================================
# C2 Communication Analysis
# =====================================================================
print("\n" + "=" * 70)
print("[+] C2 COMMUNICATION ANALYSIS")
print("=" * 70)

# The C2 URL pattern: GET /images?guid=<base64> and GET / with Cookie
c2_guids = []
c2_responses = []

for req_key, resp_key, req_data, resp_data, body, headers, req_time in http_sessions:
    req_text = req_data.decode('ascii', errors='ignore')
    
    if '/images?guid=' in req_text:
        # Extract guid
        guid_start = req_text.find('guid=') + 5
        guid_end = req_text.find(' HTTP/', guid_start)
        guid_b64 = req_text[guid_start:guid_end]
        
        ts = datetime.fromtimestamp(req_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"\n  [EXFIL] [{ts}] guid length: {len(guid_b64)}")
        
        try:
            guid_decoded = base64.b64decode(guid_b64)
            print(f"    Base64 decoded ({len(guid_decoded)} bytes): {guid_decoded[:100]}")
            print(f"    Hex: {guid_decoded[:100].hex()}")
            
            # Try RC4 with stage1 key
            key_bytes = STAGE1_KEY.encode('utf-8')
            dec = rc4_crypt(key_bytes, guid_decoded)
            print(f"    RC4(stage1 key): {dec[:200].decode('ascii', errors='replace')}")
            
            c2_guids.append((ts, guid_b64, guid_decoded))
        except Exception as e:
            print(f"    Base64 decode error: {e}")
            c2_guids.append((ts, guid_b64, None))
    
    elif 'Host: 34.174.57.99' in req_text and 'GET / ' in req_text:
        ts = datetime.fromtimestamp(req_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Extract response body (commands)
        if len(body) > 0:
            # Extract Etag
            etag = ''
            for hline in headers.split('\r\n'):
                if hline.lower().startswith('etag:'):
                    etag = hline.split(':', 1)[1].strip().strip('"')
            
            print(f"\n  [POLL] [{ts}] Response body: {len(body)} bytes, Etag: {etag}")
            c2_responses.append((ts, body, headers, etag))

# =====================================================================
# Analyze C2 response bodies (HTML with embedded commands)
# =====================================================================
print("\n" + "=" * 70)
print("[+] ANALYZING C2 RESPONSE BODIES")
print("=" * 70)

unique_etags = {}
for ts, body, headers, etag in c2_responses:
    if etag not in unique_etags:
        unique_etags[etag] = (ts, body, headers)

print(f"\n  Unique response ETags: {len(unique_etags)}")
for etag, (ts, body, headers) in unique_etags.items():
    print(f"\n  [{ts}] Etag: {etag}")
    print(f"    Body size: {len(body)} bytes")
    
    # Look for patterns in the HTML body
    body_text = body.decode('ascii', errors='replace')
    
    # Check if it looks like HTML
    if '<html' in body_text.lower() or '<script' in body_text.lower():
        print("    Content type: HTML")
        # Look for script tags or encoded data
        import re
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body_text, re.DOTALL)
        if scripts:
            for i, script in enumerate(scripts):
                print(f"    Script {i}: {script[:500]}")
        
        # Look for hidden fields, comments, base64 data
        comments = re.findall(r'<!--(.*?)-->', body_text, re.DOTALL)
        if comments:
            for c in comments:
                if len(c.strip()) > 10:
                    print(f"    Comment: {c.strip()[:500]}")
        
        # Look for specific patterns that could be encrypted data
        # Could be in a div, hidden input, or custom attribute
        hidden_inputs = re.findall(r'value="([A-Za-z0-9+/=]{20,})"', body_text)
        if hidden_inputs:
            for h in hidden_inputs:
                print(f"    Hidden value: {h[:200]}")
        
        # Look for long base64 or hex strings anywhere
        long_b64 = re.findall(r'[A-Za-z0-9+/=]{50,}', body_text)
        for lb in long_b64[:5]:
            print(f"    Long encoded string: {lb[:200]}")
        
        long_hex = re.findall(r'[0-9a-fA-F]{50,}', body_text)
        for lh in long_hex[:5]:
            print(f"    Long hex string: {lh[:200]}")
    else:
        print(f"    Not HTML. Preview: {body_text[:500]}")

# =====================================================================
# Try different decryption approaches on C2 data
# =====================================================================
print("\n" + "=" * 70)
print("[+] TRYING DIFFERENT DECRYPTION KEYS ON GUID DATA")
print("=" * 70)

# The first guid (registration/init) is small
if c2_guids:
    for ts, b64, decoded in c2_guids:
        if decoded is None:
            continue
        print(f"\n  [{ts}] Raw decoded ({len(decoded)} bytes):")
        print(f"    Hex: {decoded.hex()}")
        print(f"    ASCII: {decoded.decode('ascii', errors='replace')}")
        
        # The decoded data might itself be base64
        try:
            double_decoded = base64.b64decode(decoded)
            print(f"    Double base64 ({len(double_decoded)} bytes): {double_decoded[:200]}")
            print(f"    Double b64 hex: {double_decoded[:100].hex()}")
            
            # Try RC4 with stage1 key on double decoded
            key_bytes = STAGE1_KEY.encode('utf-8')
            dec = rc4_crypt(key_bytes, double_decoded)
            dec_text = dec.decode('ascii', errors='replace')
            print(f"    RC4(double_b64): {dec_text[:200]}")
        except Exception:
            pass

# =====================================================================
# Extract first full C2 response body for analysis
# =====================================================================
print("\n" + "=" * 70)
print("[+] FIRST UNIQUE C2 RESPONSE BODY SAMPLES")
print("=" * 70)

for i, (etag, (ts, body, headers)) in enumerate(unique_etags.items()):
    if i >= 3:
        break
    body_text = body.decode('ascii', errors='replace')
    # Print first 2000 chars and last 500 chars
    print(f"\n  === Etag: {etag} ({len(body)} bytes) ===")
    print(f"  FIRST 2000 chars:")
    print(body_text[:2000])
    print(f"\n  LAST 500 chars:")
    print(body_text[-500:])

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  1. External domain: api-edgecloud.xyz")
print(f"  2. Encryption algorithm: RC4")
print(f"  3. Decryption key (stage1): {STAGE1_KEY}")
print(f"  4. C2 server: 34.174.57.99")
print(f"  5. C2 URL: http://34.174.57.99/")
print(f"  6. Total C2 poll requests: {len(c2_responses)}")
print(f"  7. Total exfil (guid) requests: {len(c2_guids)}")
print(f"  8. Unique responses (by etag): {len(unique_etags)}")
