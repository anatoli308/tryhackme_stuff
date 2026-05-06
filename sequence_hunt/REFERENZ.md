# REFERENZ - Sequence Lösungsweg (Session-Protokoll)

Diese Datei dokumentiert den final funktionierenden Weg aus unserer gemeinsamen Session.

## Ziel

Alle drei Flags aus der Sequence-Kette vollständig holen.

## Endgültiger Exploit-Flow

## Phase A - Flag 1 (Mod-Access)

1. Stored XSS über `/contact.php` einreichen.
2. Bot ruft Payload auf und exfiltriert `PHPSESSID`.
3. Session validieren über `/dashboard.php`.
4. Erste Flag auslesen.

Ergebnis:

- `THM{M0dH@ck3dPawned007}`

## Phase B - Flag 2 (Admin-Eskalation)

1. Mit Mod-Session Passwort auf bekannten Wert setzen (`update_password.php`).
2. Promote-Link generieren mit vorhersehbarem CSRF:
   - `csrf_token_promote = md5("admin")`
   - URL: `/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3`
3. Link über `chat.php` senden (Bot klickt Links).
4. WICHTIG: Host im Link auf `review.thm` setzen, nicht auf IP.
5. Nach Role-Flip neu einloggen, dann zweite Flag lesen.

Ergebnis:

- `THM{Adm1NPawned007}`

## Phase C - Final Flag (Foothold -> Docker -> Host Flag)

1. Als Admin in `dashboard.php` interne Feature-Route missbrauchen (`feature=finance.php`).
2. Finance-Passwort aus `/mail/dump.txt` verwenden.
3. Upload-Panel freischalten und PHP-Shell hochladen.
4. Shell über Feature-Request triggern (`feature=/uploads/shell.php?...`).
5. Im Container Docker-Mount-Angriff ausführen:

```sh
docker run --rm -v /:/host phpvulnerable:latest sh -c 'cat /host/root/flag.txt'
```

6. Root-Flag aus Host-Dateisystem auslesen.

Ergebnis:

- `THM{rootAccessD0n3}`

## Wichtige Learnings aus der Session

- Bot-Verhalten ist asynchron; Polling + Geduld nötig.
- `review.thm` im Promote-Link ist kritisch für zuverlässige Bot-Klicks.
- Chat-Link-Click funktionierte, auch wenn XSS im Chat serverseitig gefiltert wurde.
- Sessions können gültig wirken, aber dennoch stale sein -> bei Problemen neue SID holen.
- Ein einzelner sauberer Promote-Post kann reichen; Spam ist nicht zwingend nötig.

## Verwendete Skripte

- `sequence_first_flag.py`
- `sequence_second_flag.py`
- `sequence_this_flag.py`
- `full_sequences_run.py`

## Abschlussstatus

- Flag 1: erledigt
- Flag 2: erledigt
- Flag 3 (final): erledigt

Alle Ziele erreicht.
