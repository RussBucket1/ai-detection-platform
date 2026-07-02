# Module 03 — RAG Alert Triage Assistant

A production-grade **Retrieval-Augmented Generation (RAG)** alert triage engine that receives raw SIEM alerts and produces structured analyst recommendations. The assistant retrieves relevant context from three knowledge bases — enriched IOC data (module 01), SIGMA detection rules (module 02), and MITRE ATT&CK — then calls Claude to reason over the combined evidence and produce a confidence-scored `TriageResult`.

---

## What It Does and Why It Matters

Modern SOC environments generate thousands of alerts per day. Tier-1 analysts spend the majority of their time on repetitive context-gathering — cross-referencing IP addresses against threat feeds, looking up detection rule intent, and mapping behavior to ATT&CK techniques. This module automates that context assembly and applies LLM-scale reasoning to produce:

- A **verdict** (true positive, likely TP, needs investigation, FP)
- A **recommended action** (escalate immediately, investigate, monitor, suppress, close)
- **MITRE ATT&CK technique attribution** with per-technique confidence
- **Analyst-ready summary** and detailed notes
- **Follow-up SIEM searches** (specific SPL or KQL)
- **False positive indicators** to help reviewers decide quickly

This frees analysts to focus on escalated investigations rather than mechanical triage.

---

## Architecture

```
SIEM Alert (Splunk / Elastic webhook  OR  CLI / manual)
                        |
              Alert Normalization
               (RawAlert model)
                        |
            ┌───────────▼────────────┐
            │    Context Retrieval   │
            │      (ChromaDB)        │
            │                        │
            │  ┌─────────────────┐   │
            │  │ IOC Collection  │   │  ← module 01 enriched output
            │  │ (ioc_enrichment)│   │
            │  └─────────────────┘   │
            │  ┌─────────────────┐   │
            │  │  SIGMA Rules    │   │  ← module 02 generated rules
            │  │ (sigma_rules)   │   │
            │  └─────────────────┘   │
            │  ┌─────────────────┐   │
            │  │  MITRE ATT&CK   │   │  ← downloaded from MITRE CTI repo
            │  │ (mitre_attack)  │   │
            │  └─────────────────┘   │
            └───────────┬────────────┘
                        │
             LLM Triage Reasoning
          (Claude claude-sonnet-4-20250514)
                        │
                  TriageResult
        (verdict, severity, MITRE techniques,
         recommended searches, analyst notes)
```

---

## Quick Start

### 1. Install dependencies

```bash
cd 03-rag-triage-assistant
pip install -r requirements.txt
# or in development mode:
pip install -e .
```

### 2. Configure

```bash
cp config/config.example.yaml config/config.yaml
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Ingest the knowledge bases

```bash
# Ingest MITRE ATT&CK (downloads ~10 MB from GitHub)
triage-assistant ingest mitre --cache-path ./data/mitre/enterprise-attack.json

# Ingest IOC data from module 01 output
triage-assistant ingest iocs --path ../01-ioc-enrichment-pipeline/output/

# Ingest SIGMA rules from module 02 output
triage-assistant ingest sigma --path ../02-sigma-rule-generator/output/
```

### 4. Run your first triage

```bash
triage-assistant triage --title "Mimikatz execution detected" \
  --source-ip 192.168.100.50 \
  --command-line "mimikatz.exe sekurlsa::logonpasswords" \
  --severity high
```

Or from a JSON file:

```bash
triage-assistant triage -f my_alert.json
```

### 5. Check knowledge base status

```bash
triage-assistant status
```

---

## REST API

Start the server:

```bash
triage-assistant serve --port 8000
# or with dev reload:
triage-assistant serve --reload
```

Interactive docs: `http://localhost:8000/docs`

### Endpoints

#### `POST /triage` — Triage a raw alert

```bash
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious PowerShell",
    "description": "Encoded PowerShell execution detected",
    "source_ip": "10.0.0.5",
    "process": "powershell.exe",
    "command_line": "powershell -enc JABQ...",
    "severity": "high"
  }'
```

#### `POST /triage/splunk` — Splunk webhook

```bash
curl -X POST http://localhost:8000/triage/splunk \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "Mimikatz Detected",
    "result": {
      "src_ip": "10.0.0.5",
      "host": "WIN-WORKSTATION",
      "CommandLine": "sekurlsa::logonpasswords",
      "EventCode": "4688"
    }
  }'
```

#### `POST /triage/elastic` — Elastic webhook

```bash
curl -X POST http://localhost:8000/triage/elastic \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {
      "name": "PowerShell Execution Policy Bypass",
      "description": "Detects bypass flag usage",
      "severity": "high"
    },
    "signal": {
      "_source": {
        "host": {"name": "srv-01"},
        "user": {"name": "alice"}
      }
    }
  }'
```

#### `POST /ingest/iocs` — Ingest IOC files

```bash
curl -X POST http://localhost:8000/ingest/iocs \
  -H "Content-Type: application/json" \
  -d '{"path": "./data/iocs"}'
```

#### `POST /ingest/sigma` — Ingest SIGMA rules

```bash
curl -X POST http://localhost:8000/ingest/sigma \
  -H "Content-Type: application/json" \
  -d '{"path": "./data/sigma_rules"}'
```

#### `POST /ingest/mitre` — Download and ingest MITRE ATT&CK

```bash
curl -X POST http://localhost:8000/ingest/mitre \
  -H "Content-Type: application/json" \
  -d '{"cache_path": "./data/mitre/enterprise-attack.json"}'
```

#### `GET /knowledge-base/stats` — Collection sizes

```bash
curl http://localhost:8000/knowledge-base/stats
```

#### `GET /health` — Health check

```bash
curl http://localhost:8000/health
```

---

## CLI Reference

```
triage-assistant [OPTIONS] COMMAND [ARGS]...

Options:
  --config PATH           Path to config YAML file
  --log-level LEVEL       DEBUG | INFO | WARNING | ERROR
  --json-logs             Emit structured JSON logs

Commands:
  triage   Triage a SIEM alert through the RAG pipeline
  ingest   Ingest knowledge base data
    iocs   --path PATH       Ingest IOC JSON / NDJSON files
    sigma  --path PATH       Ingest SIGMA rule YAML files
    mitre  --cache-path PATH Download and ingest MITRE ATT&CK
  status   Show knowledge base readiness
  serve    Start the FastAPI server
  version  Print version
```

---

## Splunk Integration

1. In Splunk, create or edit a saved search alert.
2. Under **Trigger Actions**, add a **Webhook** action.
3. Set the URL to: `http://<your-server>:8000/triage/splunk`
4. Set the content type to `application/json`.
5. Splunk will POST its standard alert webhook payload (includes `result` dict and `search_name`).

The triage assistant automatically maps Splunk fields:
- `result.src_ip` → `source_ip`
- `result.dest_ip` → `dest_ip`
- `result.CommandLine` → `command_line`
- `result.EventCode` → `event_id`
- `result.host`, `result.user`, `result.process` → corresponding alert fields
- `search_name` → `title`

---

## Elastic Integration

1. In Elastic Security, navigate to **Rules** → select a rule → **Edit Rule**.
2. Under **Actions**, add an **Webhook** connector.
3. Set the URL to: `http://<your-server>:8000/triage/elastic`
4. Set the body to the default Elastic alert action payload format (includes `rule` and `signal` objects).

The triage assistant automatically maps Elastic fields:
- `rule.name` → `title`
- `rule.description` → `description`
- `rule.severity` → `severity`
- `signal._source.host.name` → `host`
- `signal._source.user.name` → `user`
- `signal._source.source.ip` → `source_ip`

---

## How Modules 01, 02, and 03 Connect

```
Module 01 (IOC Enrichment Pipeline)
  └── Produces enriched IOC JSON / NDJSON files
        └── triage-assistant ingest iocs --path <module-01-output>/
              └── Indexed in ChromaDB → ioc_enrichment collection

Module 02 (SIGMA Rule Generator)
  └── Produces SIGMA rule YAML files
        └── triage-assistant ingest sigma --path <module-02-output>/
              └── Indexed in ChromaDB → sigma_rules collection

MITRE ATT&CK (External)
  └── triage-assistant ingest mitre
        └── Downloaded and indexed → mitre_attack collection

Module 03 (RAG Triage Assistant) ← THIS MODULE
  ├── Receives raw alerts (CLI, Splunk webhook, Elastic webhook)
  ├── Retrieves context from all three collections
  ├── Calls Claude for structured triage reasoning
  └── Returns TriageResult (verdict, MITRE, searches, analyst notes)
```

---

## Running Tests

```bash
cd 03-rag-triage-assistant
pytest                        # run all tests
pytest -v                     # verbose output
pytest --cov=triage_assistant # with coverage
pytest tests/test_models.py   # single file
```

---

## Portfolio Context

This module demonstrates:

- **RAG architecture** with three distinct knowledge domains (threat intel, detection rules, technique taxonomy)
- **Pydantic v2** request/response validation with custom field validators
- **FastAPI** webhook integration with live SIEM platforms
- **ChromaDB** persistent vector store with local SentenceTransformer embeddings
- **Claude API** integration with structured JSON output and robust error handling
- **Click + Rich** CLI with colored verdict display and formatted output tables
- **structlog** JSON logging for production observability
- **pytest + mocking** test suite covering ingestion, retrieval, orchestration, and API layers
- Integration of multiple AI-assisted modules in a single cohesive platform
