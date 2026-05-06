# Signed Messages — Walkthrough & Vulnerability Report

**Ziel:** `http://10.113.167.230:5000` (LoveNote)
**Flag:** `THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}`
**Schwachstelle:** Deterministische RSA-Schlüsselableitung aus dem Benutzernamen → Private Key des `admin` ist vollständig rekonstruierbar.

---

## 1. Recon

### 1.1 Endpoints

Nach Login (jeder Username wird ohne Passwort akzeptiert) sind erreichbar:

| Pfad | Funktion |
|------|----------|
| `/login` | Login (nur `username` Feld) |
| `/dashboard` | Eigene Inbox/Sent |
| `/compose` | Nachricht senden (`to_user`, `subject`, `message`) |
| `/messages` | Öffentliche Nachrichten |
| `/verify` | **Signaturprüfung** (`username`, `message`, `signature` Hex) |
| `/about` | Marketing-Seite mit Hinweis auf RSA-2048 |
| `/debug` | **Leakt den Key-Generierungsalgorithmus** |

### 1.2 Hinweise auf der Seite

- *"Protected by RSA-2048 digital signatures"*
- `/about` erwähnt PKI / Encryption Details
- `/verify` erwartet einen **hex-kodierten** Signaturstring

---

## 2. Die Schwachstelle

`/debug` legt offen, wie der Server pro User einen RSA-Key ableitet:

```python
# server-side pseudocode
seed       = f"{username}_lovenote_2026_valentine".encode()
hash_p     = sha256(seed)
p          = nextprime(int.from_bytes(hash_p, "big"))   # 256-bit Primzahl
mod_seed   = sha256(seed + b"pki")
hash_q     = sha256(mod_seed)
q          = nextprime(int.from_bytes(hash_q, "big"))   # 256-bit Primzahl
n          = p * q                                      # ~505-bit Modulus
e          = 65537
```

**Probleme:**

1. **Deterministisch:** Gleicher Username → gleicher Key. Kein zufälliges Material.
2. **Öffentlich bekannter Seed:** Format `{username}_lovenote_2026_valentine` ist offen einsehbar (`/debug`).
3. **Schwacher Modulus:** ~505 Bit statt der beworbenen 2048 Bit — sogar ohne den Seed-Leak in Sekunden faktorisierbar.
4. **Privater Schlüssel = Funktion vom Public Username:** Jeder kann den `admin`-Private-Key lokal regenerieren und Nachrichten signieren.

CWE-Bezug:

- **CWE-330** — Use of Insufficiently Random Values
- **CWE-326** — Inadequate Encryption Strength
- **CWE-1391** — Use of Weak Credentials
- **CWE-345** — Insufficient Verification of Data Authenticity

---

## 3. Exploit-Pfad

### 3.1 Private Key des admin rekonstruieren

```python
import hashlib
from Crypto.Util.number import isPrime, inverse, bytes_to_long
from Crypto.PublicKey import RSA

USERNAME = "admin"
E = 65537

def next_prime(n):
    while not isPrime(n):
        n += 1
    return n

seed = f"{USERNAME}_lovenote_2026_valentine".encode()
p = next_prime(bytes_to_long(hashlib.sha256(seed).digest()))
q = next_prime(bytes_to_long(hashlib.sha256(seed + b"pki").digest()))
n = p * q
d = inverse(E, (p - 1) * (q - 1))
key = RSA.construct((n, E, d, p, q))
```

### 3.2 Korrektes Signaturschema bestimmen

Der Server verifiziert mit **RSA-PSS / SHA-256 / max salt** (nicht PKCS#1 v1.5).
Bei den 505-Bit ergibt das:

- `emLen   = (modBits - 1 + 7) // 8 = 64`
- `maxSalt = emLen - 32 (SHA-256) - 2 = 30`

```python
from Crypto.Signature import pss
from Crypto.Hash      import SHA256

MESSAGE = (b"Welcome to LoveNote! Send encrypted love messages this Valentine's Day. "
           b"Your communications are secured with industry-standard RSA-2048 digital signatures.")

h       = SHA256.new(MESSAGE)
emLen   = (key.size_in_bits() - 1 + 7) // 8
maxSalt = emLen - h.digest_size - 2
sig_hex = pss.new(key, salt_bytes=maxSalt).sign(h).hex()
```

### 3.3 An `/verify` einreichen

```python
import requests

s = requests.Session()
s.post("http://10.113.167.230:5000/login", data={"username": "admin"})
r = s.post("http://10.113.167.230:5000/verify", data={
    "username":  "admin",
    "message":   MESSAGE.decode(),
    "signature": sig_hex,
})
print(r.text)
```

Server-Response (gekürzt):

> *"This message was cryptographically verified and is authentic — You successfully forged an admin signature!"*
> `THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}`

---

## 4. Fallstricke beim Lösen

| Fehler | Symptom | Lösung |
|--------|---------|--------|
| Falsche Form-Feldnamen | `/verify` wirft HTTP 500 bei JEDEM Input | HTML lesen → Felder sind `username`, `message`, `signature` |
| PKCS#1 v1.5 statt PSS | HTTP 200, aber kein "valid" Banner | Auf `pss.new(...)` mit max salt umstellen |
| Bit-Stretching mit `\| (1 << 1023)` | 2048-bit Modulus, falscher Key | Im `/debug` steht KEIN `\|`-Operator → `nextprime` direkt auf den 256-bit Hash |
| `alg:none` JWT-Versuch | False positive durch HTML-Match auf "flag" | LoveNote nutzt keine JWTs — Flask-Session signiert mit `itsdangerous` |

---

## 5. Mitigation

1. **Schlüsselgenerierung mit echter Entropie** (`os.urandom` / `Crypto.PublicKey.RSA.generate(2048)`) — niemals aus Public-Identifiers ableiten.
2. **Schlüssel persistieren**, nicht aus dem Username on-the-fly bauen.
3. **Mindestens 2048-bit Modulus** — PSS mit kleineren Modulen ist trivial brechbar wegen Faktorisierung.
4. **`/debug` Endpoint entfernen**, niemals Crypto-Internals exponieren.
5. **Rate-Limiting + Audit-Log** auf `/verify`, damit Brute-Force-Versuche auffallen.
6. **Signatur-Schema explizit dokumentieren** und serverseitig nur ein Schema akzeptieren.

---

## 6. Beweis-Skript

`_exploit_pss.py` (im selben Ordner) iteriert über mehrere Schemata und Stretches und liefert:

```
[PSS-maxSalt msg='Welcome to LoveNote! Send...'] HTTP 200 sig_len=128
   >> This message was cryptographically verified and is authentic
   >> You successfully forged an admin signature!
*** FLAG: ['THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}']
```

---

## 7. Lessons Learned

- **Niemals Crypto-Material aus öffentlich bekannten Daten ableiten.**
- "RSA-2048" im Marketing-Text != tatsächlich verwendete Schlüsselgröße — immer messen.
- HTTP 500 ≠ Signature ungültig: Oft sind nur die Form-Felder falsch.
- Form-HTML lesen, bevor man stundenlang Krypto-Varianten durchprobiert.
