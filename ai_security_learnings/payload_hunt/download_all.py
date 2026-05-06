"""Download all tools, scripts, and incident files from the TryHackMe server."""
import paramiko
import os
import stat

HOST = "10.112.142.193"
USER = "analyst"
PASS = "analyst123"
LOCAL_BASE = os.path.dirname(os.path.abspath(__file__))

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASS, timeout=15)
sftp = client.open_sftp()


def run(cmd):
    _, stdout, stderr = client.exec_command(cmd, timeout=60)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out.strip(), err.strip()


def download_tree(remote_dir, local_dir):
    """Recursively download a remote directory."""
    os.makedirs(local_dir, exist_ok=True)
    try:
        entries = sftp.listdir_attr(remote_dir)
    except IOError as e:
        print(f"  [SKIP] Cannot list {remote_dir}: {e}")
        return

    for entry in entries:
        remote_path = f"{remote_dir}/{entry.filename}"
        local_path = os.path.join(local_dir, entry.filename)
        if stat.S_ISDIR(entry.st_mode):
            download_tree(remote_path, local_path)
        else:
            size_kb = entry.st_size / 1024
            if entry.st_size > 50 * 1024 * 1024:
                print(f"  [SKIP] {remote_path} ({size_kb:.0f} KB) - too large")
                continue
            print(f"  {remote_path} -> {local_path} ({size_kb:.1f} KB)")
            sftp.get(remote_path, local_path)


# === 1. Re-examine the pickle payload exactly ===
print("=" * 60)
print("RE-EXAMINING PICKLE PAYLOAD")
print("=" * 60)

# pickletools disassembly
out, _ = run("python3 -m pickletools /opt/supply-chain/incident/models/production_model.pkl")
print("\n--- pickletools ---")
print(out)

# fickling decompilation
out, _ = run("fickling /opt/supply-chain/incident/models/production_model.pkl")
print("\n--- fickling ---")
print(out)

# strings from the pickle
out, _ = run("strings /opt/supply-chain/incident/models/production_model.pkl")
print("\n--- strings ---")
print(out)

# === 2. Download incident directory ===
print("\n" + "=" * 60)
print("DOWNLOADING /opt/supply-chain/incident/")
print("=" * 60)
local_incident = os.path.join(LOCAL_BASE, "server_files", "incident")
download_tree("/opt/supply-chain/incident", local_incident)

# === 3. Download tools directory ===
print("\n" + "=" * 60)
print("DOWNLOADING /opt/supply-chain/tools/")
print("=" * 60)
local_tools = os.path.join(LOCAL_BASE, "server_files", "tools")
download_tree("/opt/supply-chain/tools", local_tools)

# === 4. Find any other relevant files ===
print("\n" + "=" * 60)
print("FINDING ALL FILES UNDER /opt/supply-chain/")
print("=" * 60)
out, _ = run("find /opt/supply-chain/ -type f 2>/dev/null | sort")
print(out)

# Download anything else that's not in incident/ or tools/
for line in out.splitlines():
    line = line.strip()
    if not line or "/incident/" in line or "/tools/" in line:
        continue
    rel = line.replace("/opt/supply-chain/", "")
    local_path = os.path.join(LOCAL_BASE, "server_files", rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    try:
        sftp.get(line, local_path)
        print(f"  {line} -> {local_path}")
    except Exception as e:
        print(f"  [SKIP] {line}: {e}")

# === 5. Check installed Python packages for analysis tools ===
print("\n" + "=" * 60)
print("INSTALLED ANALYSIS TOOLS")
print("=" * 60)
out, _ = run("pip3 list 2>/dev/null | grep -iE 'fickling|pickle|h5py|keras|tensorflow|modelscan'")
print(out)
out, _ = run("which fickling modelscan pickletools 2>/dev/null")
print(out)

sftp.close()
client.close()
print("\n[DONE] All files downloaded to:", os.path.join(LOCAL_BASE, "server_files"))
