# AI Detection Engineering Platform

A portfolio of production-grade security tools demonstrating AI-augmented detection engineering. Each module is an independent, deployable system that also integrates with the others to form an end-to-end detection workflow — from raw threat intelligence to validated detections to triaged alerts.

## Platform Overview

```
 Threat Intelligence          Detection Authoring        Alert Operations
 ─────────────────────        ───────────────────        ────────────────
 ┌─────────────────┐          ┌─────────────────┐        ┌─────────────────┐
 │  Module 01      │          │  Module 02      │        │  Module 03      │
 │  IOC Enrichment │─────────▶│  SIGMA Rule     │───────▶│  RAG Triage     │
 │  Pipeline       │  scored  │  Generator      │  rules │  Assistant      │
 └─────────────────┘  IOCs    └─────────────────┘        └─────────────────┘
                                                                  │
 ┌─────────────────┐          ┌─────────────────┐                │ alerts
 │  Module 05      │          │  Module 04      │◀───────────────┘
 │  AI Threat      │          │  ML Anomaly     │
 │  Model Generator│          │  Detection      │
 └─────────────────┘          └─────────────────┘
```

## Modules

### Module 01 — IOC Enrichment Pipeline
**Status: Complete**

An async pipeline that enriches indicators of compromise (IPs, domains, file hashes, URLs) against five threat intelligence APIs in parallel. Applies a weighted scoring model to produce a 0–100 risk score with explainable per-feature contributions and MITRE ATT&CK technique mapping.

**Key capabilities:**
- Concurrent enrichment via `asyncio.gather()` with per-provider rate limiting and retry/backoff
- 5 providers: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, URLScan.io
- Weighted risk scoring across 6 feature dimensions with confidence bands (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- MITRE ATT&CK technique mapping from aggregated provider tags
- Output in JSON, NDJSON (Elastic Common Schema), CSV, or Rich terminal table
- Defanging reversal: handles `[.]`, `hxxp`, `[at]` patterns automatically

**Tech:** Python 3.11+, asyncio, aiohttp, Pydantic v2, structlog, Click, Rich

```bash
cd 01-ioc-enrichment-pipeline
pip install -e .
ioc-enricher enrich --ioc 198.51.100.1
ioc-enricher enrich --input-file iocs.txt --output-format ndjson
```

[Full documentation →](01-ioc-enrichment-pipeline/README.md)

---

### Module 02 — SIGMA Rule Generator
**Status: Complete**

An LLM-powered tool that converts unstructured threat intelligence — threat reports, CVE descriptions, IOC lists, raw log snippets — into validated, production-ready SIGMA detection rules. Uses Claude to generate detection logic with MITRE ATT&CK mapping, false positive guidance, and a confidence score with rationale.

**Key capabilities:**
- Auto-detects input type (threat report, CVE, IOC list, log snippet) from content patterns
- Generates 1–3 SIGMA rules per input depending on complexity and scope
- Validates output against the SIGMA specification before writing files
- Confidence scoring (0–100%) with LLM-generated rationale for each rule
- pySigma-compatible YAML output for direct SIEM import
- Batch mode for processing directories of threat reports

**Tech:** Python 3.11+, Anthropic SDK (claude-sonnet-4-6), Pydantic v2, Jinja2, ruamel.yaml, structlog, Click, Rich

```bash
cd 02-sigma-rule-generator
pip install -e .
sigma-generator generate --text "Mimikatz credential dumping via sekurlsa::logonpasswords"
sigma-generator generate --input examples/threat_reports/cobalt_strike.txt --format both
sigma-generator batch --input-dir examples/threat_reports/ --output-dir ./output/
```

[Full documentation →](02-sigma-rule-generator/README.md)

---

### Module 03 — RAG Triage Assistant
**Status: Complete**

An LLM-powered alert triage assistant with retrieval-augmented generation. Ingests enriched IOCs (Module 01), SIGMA rules (Module 02), and MITRE ATT&CK into three ChromaDB collections, then triages incoming SIEM alerts — explaining why an alert fired, the likely attack path, and what to investigate next.

**Key capabilities:**
- Splunk and Elastic webhook endpoints that normalize each SIEM's native alert payload into a common schema
- Three-collection RAG retrieval (IOC enrichment, SIGMA rules, MITRE ATT&CK) with collection-specific query shaping
- Local embeddings via SentenceTransformer (`all-MiniLM-L6-v2`) — no embedding API key required
- Claude-powered triage reasoning producing a structured verdict, recommended action, severity, confidence with rationale, MITRE technique attribution, and follow-up SPL/KQL searches
- FastAPI REST API (`/triage`, `/triage/splunk`, `/triage/elastic`, `/ingest/*`, `/health`) plus a Click CLI
- Graceful degradation on malformed LLM output — falls back to a safe `needs_investigation` verdict instead of failing the request

**Tech:** Python 3.11+, Anthropic SDK (claude-sonnet-4-6), ChromaDB, FastAPI, Pydantic v2, Jinja2, structlog, Click, Rich

```bash
cd 03-rag-triage-assistant
pip install -r requirements.txt
triage-assistant ingest mitre --cache-path ./data/mitre/enterprise-attack.json
triage-assistant ingest iocs --path ../01-ioc-enrichment-pipeline/output/
triage-assistant ingest sigma --path ../02-sigma-rule-generator/output/
triage-assistant triage --title "Mimikatz execution detected" --source-ip 192.168.100.50 --severity high
```

[Full documentation →](03-rag-triage-assistant/README.md)

---

### Module 04 — ML Anomaly Detection
**Status: Planned**

Unsupervised behavioral anomaly detection for network and endpoint telemetry. Trains baseline models on normal behavior and flags statistical outliers for analyst review, feeding high-confidence anomalies into the Module 03 triage workflow.

---

### Module 05 — AI Threat Model Generator
**Status: Planned**

Generates STRIDE/MITRE ATT&CK threat models from architecture diagrams and service descriptions. Outputs a prioritized list of attack paths with detection coverage gaps mapped against the SIGMA rules in Module 02.

---

## How the Modules Connect

| Data Flow | Source | Destination | What Moves |
|-----------|--------|-------------|------------|
| Enriched IOCs → rule context | Module 01 | Module 02 | High-risk IOCs as input to rule generation |
| Enriched IOCs → triage context | Module 01 | Module 03 | Enriched IOC JSON/NDJSON indexed into the `ioc_enrichment` ChromaDB collection |
| SIGMA rules → triage context | Module 02 | Module 03 | Generated `.yml` rules indexed into the `sigma_rules` ChromaDB collection |
| Anomaly alerts → triage queue | Module 04 | Module 03 | Scored anomalies submitted for LLM-assisted triage |
| Threat model gaps → rules | Module 05 | Module 02 | Uncovered attack paths used as rule generation prompts |

## Shared Infrastructure

The [shared/](shared/) directory contains models and utilities used across modules:

- `shared/models/` — Common data types (IOC, alert, finding)
- `shared/utils/` — Cross-module helpers

## Secrets Management

Each module loads secrets from a local file that is gitignored. Never hardcode API keys in config files.

| Module | Secrets File | Key Variables |
|--------|-------------|---------------|
| 01 | `config/secrets.pem` | `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY` |
| 02 | `.env` | `ANTHROPIC_API_KEY` |
| 03 | `.env` or `config/config.yaml` | `ANTHROPIC_API_KEY` |

Shell environment variables always take priority over file-based secrets.

## Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Python 3.11+ | Async support, rich ML/security ecosystem |
| Data models | Pydantic v2 | Runtime validation, serialization, IDE support |
| Async I/O | asyncio + aiohttp | Concurrent provider calls without thread overhead |
| LLM | Anthropic Claude (claude-sonnet-4-6) | Best-in-class reasoning for security analysis |
| Vector store | ChromaDB + local SentenceTransformer embeddings | RAG retrieval without an embedding API dependency |
| Web API | FastAPI + uvicorn | Async webhook ingestion from Splunk/Elastic, auto-generated docs |
| Logging | structlog | JSON structured logs, compatible with SIEM ingestion |
| CLI | Click + Rich | Composable commands, readable terminal output |
| Testing | pytest + pytest-asyncio | Async test support, full API mocking |
| Config | YAML + env var overrides | Twelve-factor app pattern, secrets never in YAML |

## Portfolio Context

This platform demonstrates skills relevant to **Detection Engineering**, **Security Data Engineering**, and **AI/ML Security** roles:

- **Detection Engineering**: SIGMA rule authoring, MITRE ATT&CK mapping, false positive analysis, SIEM integration
- **Threat Intelligence**: Multi-source IOC enrichment, risk scoring, indicator lifecycle management
- **AI Engineering**: LLM prompt engineering for structured output, RAG system design, confidence scoring
- **Production Python**: Async-first design, Pydantic v2, structlog, retry/backoff, rate limiting, full test coverage
- **Security Architecture**: Secrets management, separation of concerns, composable tool design
