# THM Hunt Framework

Semi-universelles Framework fuer Web-Hunt Aufgaben:

1. Recon (Endpoints + Backup-Leaks)
2. Auth-Flow (Login + OTP-Tampering)
3. Post-Auth Probes (z. B. Feed-Import / Injection)
4. Report als Text und optional JSON

## Quick Start

```bash
python interceptor_hunt_burp/run_framework.py --target http://10.114.136.231
```

Mit JSON-Report:

```bash
python interceptor_hunt_burp/run_framework.py \
  --target http://10.114.136.231 \
  --json-out interceptor_hunt_burp/framework_report.json
```

Zusatzkandidaten:

```bash
python interceptor_hunt_burp/run_framework.py \
  --target http://10.114.136.231 \
  --email admin@example.com \
  --password Summer2026 \
  --extra-path api_verify.php
```

## Hinweise

- Das Tool ist absichtlich "semi-universell": Wiederverwendbare Methodik, aber challenge-spezifische Probes bleiben notwendig.
- Nur in autorisierten CTF/Lab-Umgebungen einsetzen.
