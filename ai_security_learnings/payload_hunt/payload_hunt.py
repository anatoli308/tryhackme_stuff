#!/usr/bin/env python3
"""
TryHackMe - AI Supply Chain: The Quiet Leak
Automated investigation script for the incident at /opt/supply-chain/incident/

Usage: python payload_hunt.py
Requires: paramiko (pip install paramiko)
"""

import paramiko
import re
import sys

TARGET_HOST = "10.112.142.193"
SSH_USER = "analyst"
SSH_PASS = "analyst123"

client = None


def connect():
    """Establish SSH connection to the target."""
    global client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(TARGET_HOST, username=SSH_USER, password=SSH_PASS, timeout=15)
    print(f"[+] Connected to {TARGET_HOST}")


def ssh_cmd(cmd: str, timeout: int = 60) -> str:
    """Run a command on the remote target and return combined output."""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    return out + err


def banner(section: str, num: int):
    print(f"\n{'=' * 70}")
    print(f"  [{num}] {section}")
    print(f"{'=' * 70}")


def main():
    print("=" * 70)
    print("  AI Supply Chain Incident Investigation - The Quiet Leak")
    print("=" * 70)

    connect()

    # ─────────────────────────────────────────────────────────────────
    # 0. Recon: list all incident files
    # ─────────────────────────────────────────────────────────────────
    banner("Full Incident Directory Listing", 0)
    listing = ssh_cmd("find /opt/supply-chain/incident/ -type f 2>/dev/null | sort")
    print(listing)

    # Locate the inspect script (check common paths, avoid full fs search)
    inspect_script = ssh_cmd(
        "ls /opt/supply-chain/inspect_h5_model.py "
        "/opt/supply-chain/tools/inspect_h5_model.py "
        "/home/analyst/inspect_h5_model.py "
        "/usr/local/bin/inspect_h5_model.py 2>/dev/null | head -5"
    )
    if not inspect_script.strip():
        inspect_script = ssh_cmd("which inspect_h5_model.py 2>/dev/null")
    if not inspect_script.strip():
        inspect_script = ssh_cmd(
            "find /opt /home -name 'inspect_h5_model.py' 2>/dev/null | head -3"
        )
    print(f"inspect_h5_model.py locations:\n{inspect_script}")

    # ─────────────────────────────────────────────────────────────────
    # Q1 & Q2: Read the deployment log
    #   - Which organisation did the replacement model come from?
    #   - How many days between deployment and SOC alert?
    # ─────────────────────────────────────────────────────────────────
    banner("Deployment Log", 1)
    deploy_log = ssh_cmd("cat /opt/supply-chain/incident/logs/deployment.log")
    print(deploy_log)

    # ─────────────────────────────────────────────────────────────────
    # Q3 & Q4: Decompile the production model (pickle payload)
    #   - What Python function executes the shell command?
    #   - What shell command captures the host identity?
    # ─────────────────────────────────────────────────────────────────
    banner("Decompiling Production Model", 2)

    print("--- pickletools disassembly ---")
    print(ssh_cmd("python3 -m pickletools /opt/supply-chain/incident/models/production_model.pkl"))

    print("\n--- fickling decompile ---")
    print(ssh_cmd("python3 -m fickling /opt/supply-chain/incident/models/production_model.pkl 2>/dev/null || fickling /opt/supply-chain/incident/models/production_model.pkl 2>/dev/null"))

    # Also decompile original for comparison
    print("\n--- original_model.pkl pickletools ---")
    print(ssh_cmd("python3 -m pickletools /opt/supply-chain/incident/models/original_model.pkl"))

    # ─────────────────────────────────────────────────────────────────
    # Q5: Beacon capture log — HTTP method
    # ─────────────────────────────────────────────────────────────────
    banner("Beacon Capture Log", 3)
    beacon_log = ssh_cmd("cat /opt/supply-chain/incident/logs/beacon_capture.log")
    print(beacon_log)

    # ─────────────────────────────────────────────────────────────────
    # Q6: Inspect candidate_model.h5 — suspicious layer name
    # ─────────────────────────────────────────────────────────────────
    banner("Inspecting candidate_model.h5", 4)

    print("--- inspect_h5_model.py ---")
    print(ssh_cmd(
        "python3 /opt/supply-chain/tools/inspect_h5_model.py "
        "/opt/supply-chain/incident/models/candidate_model.h5"
    ))

    # Also dump h5 structure directly
    print("\n--- Direct h5 layer dump ---")
    print(ssh_cmd(
        "python3 -c \""
        "import h5py; "
        "f = h5py.File('/opt/supply-chain/incident/models/candidate_model.h5', 'r'); "
        "[print(k, list(f[k].attrs.items()) if hasattr(f[k], 'attrs') else '') for k in f.keys()]; "
        "f.visititems(lambda n,o: print(n, dict(o.attrs) if hasattr(o,'attrs') else '')); "
        "f.close()\""
    ))

    # Also inspect baseline for comparison
    print("\n--- inspect_h5_model.py on baseline ---")
    print(ssh_cmd(
        "python3 /opt/supply-chain/tools/inspect_h5_model.py "
        "/opt/supply-chain/incident/models/baseline_model.h5"
    ))

    # ─────────────────────────────────────────────────────────────────
    # Q7: Flag recovery — split across beacon log & candidate model
    # ─────────────────────────────────────────────────────────────────
    banner("Flag Recovery", 5)

    # Search text files for flag patterns
    print("Searching all incident files for flag/campaign fragments...")
    print(ssh_cmd(
        "grep -rhi 'THM{\\|thm{\\|flag\\|campaign\\|_part\\|PART' "
        "/opt/supply-chain/incident/ 2>/dev/null"
    ))

    # Search binary content with strings
    print("\n--- strings from production_model.pkl ---")
    print(ssh_cmd(
        "strings /opt/supply-chain/incident/models/production_model.pkl"
    ))

    print("\n--- strings from candidate_model.h5 (flag/campaign) ---")
    print(ssh_cmd(
        "strings /opt/supply-chain/incident/models/candidate_model.h5 | "
        "grep -iE 'THM|flag|campaign|part|split'"
    ))

    # Full strings dump of candidate in case it's hidden
    print("\n--- all strings from candidate_model.h5 ---")
    print(ssh_cmd(
        "strings /opt/supply-chain/incident/models/candidate_model.h5"
    ))

    # ─────────────────────────────────────────────────────────────────
    # Bonus: other logs and checksums
    # ─────────────────────────────────────────────────────────────────
    banner("Network Log", 6)
    print(ssh_cmd("cat /opt/supply-chain/incident/logs/network.log"))

    banner("Expected Hashes", 7)
    print(ssh_cmd("cat /opt/supply-chain/incident/checksums/expected_hashes.json"))

    banner("Project Requirements", 8)
    print(ssh_cmd("cat /opt/supply-chain/incident/project/requirements.txt"))

    # Hash comparison
    banner("Model File Hashes", 9)
    print(ssh_cmd(
        "sha256sum /opt/supply-chain/incident/models/*.pkl "
        "/opt/supply-chain/incident/models/*.h5 "
        "/opt/supply-chain/incident/models/*.safetensors 2>/dev/null"
    ))

    client.close()
    print("\n[+] Investigation complete. Review outputs above for answers.")


if __name__ == "__main__":
    main()
