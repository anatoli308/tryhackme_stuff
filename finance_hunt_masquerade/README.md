# Masquerade – Attack Analysis

## Übersicht

Ein mehrstufiger Angriff, bei dem ein **TrevorC2**-Implant über ein verschleiertes PowerShell-Skript ausgeliefert und C2-Kommunikation in gefälschten Google-Startseiten versteckt wird.

## Angriffsablauf

```
PowerShell-Dropper
    │
    ▼
api-edgecloud.xyz/amd.bin   ← RC4-verschlüsselter Payload (Hex-kodiert)
    │
    ▼
TrevorC2 .NET Client         ← AES-256-CBC verschlüsselte Kommunikation
    │
    ▼
34.174.57.99 (C2-Server)     ← Befehle in HTML-Kommentaren versteckt
```

## Stage 1 – Payload-Delivery

- **Domain:** `api-edgecloud.xyz`
- **Pfad:** `/amd.bin`
- **Verschlüsselung:** RC4
- **Schlüssel:** `X9vT3pL2QwE8xR6ZkYhC4s`
- **Server-Antwort:** `Date: Fri, 10 Apr 2026 05:28:23 GMT`

Der Dropper lädt eine Hex-kodierte Datei herunter, dekodiert sie und entschlüsselt sie mit RC4. Das Ergebnis ist ein .NET-PE-Binary (9216 Bytes).

**SHA-256 des entschlüsselten Payloads:**
```
e3d39d42df63c6874780737244370ba517820f598fd2443e47ff6580f10c17cb
```

## Stage 2 – TrevorC2 Client

Das entschlüsselte Binary ist ein **TrevorC2**-Client, kompiliert für .NET Framework v4.0.30319.

### C2-Konfiguration (aus dem #US-Heap extrahiert)

| Parameter | Wert |
|-----------|------|
| C2-Server | `http://34.174.57.99` |
| Polling-Endpunkt | `/images?guid=` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko` |
| Command-Tag | `oldcss=` |
| Idle-Response | `nothing` |
| Shell | `cmd.exe /Q /c {0} 2>&1` |
| Hostname-Format | `magic_hostname={0}` |
| Befehlsformat | `HOSTNAME::::command` |

### Verschlüsselung der C2-Kommunikation

- **Algorithmus:** AES-256-CBC mit PKCS7-Padding
- **Schlüssel:** `M4squ3r4d3Th3P4ck3tSt34lthM0d31337`
- **Key-Derivation:** SHA-256-Hash des Schlüsselstrings → 32-Byte AES-Key
- **IV:** Erste 16 Bytes des Ciphertexts (pro Nachricht zufällig generiert)

## Stage 3 – C2-Kommunikation

Der Client pollt regelmäßig den C2-Server per HTTP GET. Die Antwort ist eine **gefälschte Google-Startseite**, in deren HTML-Kommentaren die Befehle als Base64-kodierter, AES-verschlüsselter `oldcss=`-Wert eingebettet sind:

```html
<!-- oldcss=<base64-verschlüsselter Befehl> --></body>
```

Wenn kein Befehl ansteht, liefert der Server den Wert `nothing` (verschlüsselt). Der ETag-Header `da39a3ee...` (SHA-1 von leerem String) zeigt ebenfalls eine leere Antwort an.

## Entschlüsselte Befehle

| # | Befehl |
|---|--------|
| 1 | *(kein Befehl – Polling)* |
| 2 | `whoami /all` |
| 3 | *(kein Befehl – Polling)* |
| 4 | `ipconfig /all` |
| 5 | *(kein Befehl – Polling)* |
| 6 | `echo THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}` |
| 7 | *(kein Befehl – Polling)* |

Der Angreifer hat zunächst Reconnaissance durchgeführt (`whoami`, `ipconfig`) und anschließend das Flag ausgegeben.

## Zusammenfassung der Antworten

| # | Frage | Antwort |
|---|-------|---------|
| 1 | Externe Domain | `api-edgecloud.xyz` |
| 2 | Verschlüsselungsalgorithmus (Stage 1) | RC4 |
| 3 | Entschlüsselungsschlüssel (Stage 1) | `X9vT3pL2QwE8xR6ZkYhC4s` |
| 4 | Zeitstempel der Server-Antwort | `Fri, 10 Apr 2026 05:28:23 GMT` |
| 5 | SHA-256 des Payloads | `e3d39d42df63c6874780737244370ba517820f598fd2443e47ff6580f10c17cb` |
| 6 | Verschlüsselung des Clients | AES / `M4squ3r4d3Th3P4ck3tSt34lthM0d31337` |
| 7 | Flag | `THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}` |

## Verwendete Artefakte

- `traffic.pcapng` – Netzwerkmitschnitt mit Payload-Download und C2-Kommunikation
- `Powershell-Operational.evtx` – Windows Event Log mit dem PowerShell-Dropper

## Tools & Methoden

- **scapy** – PCAP-Parsing und TCP-Stream-Reassembly
- **Manuelle .NET-Analyse** – Parsing des #US-Heaps (User Strings) zur Extraktion von Konfiguration und AES-Schlüssel
- **cryptography (Python)** – AES-CBC-Entschlüsselung der C2-Befehle
