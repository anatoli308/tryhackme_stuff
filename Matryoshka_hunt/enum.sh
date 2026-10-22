#!/bin/bash
# Matryoshka Containment Unit - Layer Recon
# Auf JEDER Ebene ausführen: bash enum.sh
# Sucht typische Container-Escape-Vektoren.

echo "================ LAYER FINGERPRINT ================"
echo "[*] hostname : $(hostname)"
echo "[*] uname    : $(uname -a)"
echo "[*] whoami   : $(whoami)  (uid=$(id -u))"
echo "[*] id       : $(id)"
echo
echo "[*] /etc/hostname:"; cat /etc/hostname 2>/dev/null
echo "[*] /etc/os-release:"; cat /etc/os-release 2>/dev/null | head -5
echo

echo "================ CONTAINER MARKERS ================"
echo "[*] /.dockerenv     : $([ -f /.dockerenv ] && echo YES || echo no)"
echo "[*] /run/.container : $(ls /run/.container* 2>/dev/null)"
echo "[*] /proc/1/cgroup  :"; cat /proc/1/cgroup 2>/dev/null
echo "[*] container env   : $(env | grep -i -E 'container|docker|lxc|kube')"
echo "[*] /proc/self/status (Cap*):"
grep -E '^(Cap|Name|Pid|NSpid)' /proc/self/status 2>/dev/null
echo

echo "================ CAPABILITIES (capsh) ================"
command -v capsh >/dev/null && capsh --print 2>/dev/null | head -20
echo "[*] capabilities decoded:"
awk '/CapEff/ {print $2}' /proc/self/status | while read c; do
  command -v capsh >/dev/null && capsh --decode=$c 2>/dev/null
done
echo

echo "================ MOUNTS / FILESYSTEMS ================"
mount | grep -v -E '^(proc|sysfs|cgroup|tmpfs|devpts|mqueue|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|hugetlbfs|nsfs|ramfs)' | head -40
echo
echo "[*] block devices:"
lsblk 2>/dev/null
ls -la /dev/sd* /dev/vd* /dev/nvme* /dev/xvd* /dev/loop* 2>/dev/null
echo
echo "[*] /proc/mounts (filtered):"
grep -E '/(host|hostfs|mnt|outer|root)' /proc/mounts 2>/dev/null
echo

echo "================ DOCKER / RUNTIME SOCKETS ================"
ls -la /var/run/docker.sock /run/docker.sock /var/run/containerd/containerd.sock 2>/dev/null
ls -la /run/containerd/ 2>/dev/null
echo "[*] docker binary: $(command -v docker)"
echo "[*] runc binary  : $(command -v runc)"
echo "[*] crictl       : $(command -v crictl)"
echo "[*] nsenter      : $(command -v nsenter)"
echo

echo "================ SUID / SUDO / WRITABLES ================"
echo "[*] sudo -l:"; sudo -n -l 2>/dev/null
echo "[*] SUID files:"
find / -perm -4000 -type f 2>/dev/null | head -30
echo
echo "[*] world-writable in suspicious paths:"
find /opt /srv /var/tmp /tmp /root -maxdepth 3 -writable 2>/dev/null | head -20
echo

echo "================ INTERESTING FILES ================"
ls -la / 2>/dev/null
echo "---"
ls -la /root /home /opt /srv 2>/dev/null
echo "[*] flags in obvious places:"
find / -maxdepth 4 -iname '*flag*' 2>/dev/null | head -30
echo

echo "================ NETWORK ================"
ip a 2>/dev/null || ifconfig 2>/dev/null
echo
ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null
echo "[*] /etc/hosts:"; cat /etc/hosts 2>/dev/null
echo "[*] arp:"; ip neigh 2>/dev/null || arp -a 2>/dev/null
echo

echo "================ KERNEL / RELEASE_AGENT VECTOR ================"
echo "[*] /sys/fs/cgroup writable? "
ls -la /sys/fs/cgroup 2>/dev/null | head -5
echo "[*] cgroup v1 release_agent paths:"
find /sys/fs/cgroup -name 'release_agent' 2>/dev/null | head -5
echo "[*] notify_on_release:"
find /sys/fs/cgroup -name 'notify_on_release' 2>/dev/null | head -3
echo

echo "================ HISTORY / CREDS ================"
for f in ~/.bash_history /root/.bash_history /home/*/.bash_history /home/*/.ssh /root/.ssh /etc/ssh; do
  ls -la $f 2>/dev/null
done
cat ~/.bash_history 2>/dev/null | tail -40
echo

echo "================ DONE ================"
