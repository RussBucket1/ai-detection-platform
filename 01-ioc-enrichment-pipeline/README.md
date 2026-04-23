# IOC Enrichment Pipeline

An enterprise-grade, async indicator of compromise (IOC) enrichment pipeline built for Detection Engineering portfolios. Queries multiple threat intelligence APIs in parallel, applies weighted ML-style scoring, maps results to MITRE ATT&CK techniques, and outputs structured data in JSON, NDJSON (ECS), CSV, or Rich terminal tables.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     IOC Enrichment Pipeline                     │
└─────────────────────────────────────────────────────────────────┘

  ┌──────────────┐    ┌─────────────────────────────────────────┐
  │  INGESTION   │    │              ENRICHMENT                 │
  │              │    │                                         │
  │  • File      │    │  ┌──────────┐  ┌──────────┐            │
  │  • CLI arg   │───▶│  │VirusTotal│  │AbuseIPDB │            │
  │  • API call  │    │  └──────────┘  └──────────┘            │
  │              │    │  ┌──────────┐  ┌──────────┐  ┌───────┐ │
  │  Defanging   │    │  │  Shodan  │  │   OTX    │  │URLScan│ │
  │  + parsing   │    │  └──────────┘  └──────────┘  └───────┘ │
  └──────────────┘    │                                         │
                      │  asyncio.gather() — concurrent per IOC  │
                      └──────────────────┬────────────────────-─┘
                                         │
                      ┌──────────────────▼────────────────────-─┐
                      │               SCORING                   │
                      │                                         │
                      │  ScoringFeatures → weighted sum → band  │
                      │  Explainability: per-feature % contrib  │
                      └──────────────────┬────────────────────-─┘
                                         │
                      ┌──────────────────▼────────────────────-─┐
                      │             MITRE MAPPING               │
                      │                                         │
                      │  Tag signals → ATT&CK techniques        │
                      │  Confidence boosting per trigger match  │
                      └──────────────────┬────────────────────-─┘
                                         │
                      ┌──────────────────▼────────────────────-─┐
                      │               OUTPUT                    │
                      │                                         │
                      │  • Rich terminal table (colored bands)  │
                      │  • JSON (pretty or compact)             │
                      │  • NDJSON (Elastic Common Schema)       │
                      │  • CSV (importable to SIEM)             │
                      └─────────────────────────────────────────┘
```

## Features

- **Async-first**: `asyncio.gather()` dispatches all providers concurrently per IOC, with semaphore-controlled batch concurrency
- **5 threat intelligence providers**: VirusTotal, AbuseIPDB, Shodan, OTX (AlienVault), URLScan.io
- **Defanging reversal**: Handles `[.]`, `hxxp`, `[at]`, `[:]`, `(.)` patterns
- **IOC classification**: IPv4/IPv6, domain, URL, MD5/SHA1/SHA256, email
- **Weighted risk scoring**: Six feature dimensions with configurable weights and explainability
- **MITRE ATT&CK mapping**: 16 technique rules matched against aggregated tag signals
- **Elastic Common Schema**: `to_ecs()` serializes results for direct Elasticsearch ingestion
- **Retry + backoff**: Exponential backoff on 429/5xx, configurable max retries
- **Token bucket rate limiter**: Per-provider async rate limiting
- **Structured logging**: structlog JSON lines in production, colored console in development
- **Rich CLI**: Color-coded terminal tables, multiple output formats

## Quick Start

### Install

```bash
pip install -e .
# or
pip install -r requirements.txt
```

### Configure

```bash
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your API keys, OR use environment variables:
export VT_API_KEY=your_vt_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
export SHODAN_API_KEY=your_shodan_key
export OTX_API_KEY=your_otx_key
export URLSCAN_API_KEY=your_urlscan_key
```

### CLI Usage

```bash
# Enrich a single IOC (table output)
ioc-enricher enrich --ioc 198.51.100.1

# Enrich multiple IOCs from a file
ioc-enricher enrich --input-file iocs.txt

# Output as Elastic Common Schema NDJSON
ioc-enricher enrich --input-file iocs.txt --output-format ndjson --output results.ndjson

# Output as JSON
ioc-enricher enrich --ioc evil.com --ioc 1.2.3.4 --output-format json

# Filter by minimum risk score
ioc-enricher enrich --input-file iocs.txt --min-score 50

# JSON structured logs
ioc-enricher --json-logs enrich --input-file iocs.txt
```

### Run as module

```bash
python -m ioc_enricher --help
python -m ioc_enricher enrich --ioc 8.8.8.8
```

## IOC File Format

Plain text, one IOC per line. Lines starting with `#` are treated as comments. Defanged IOCs are automatically refanged:

```
# Malicious IPs from incident 2024-01
198.51.100[.]1
192[.]0[.]2[.]100
# Malicious domain
hxxps://evil[.]example[.]com/payload
# File hashes
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Output Schema (JSON)

```json
{
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "pipeline_version": "1.0.0",
  "enriched_at": "2024-01-15T12:00:00Z",
  "providers_queried": ["virustotal", "abuseipdb"],
  "providers_failed": [],
  "ioc": {
    "value": "198.51.100.1",
    "ioc_type": "ipv4",
    "source": "manual",
    "tags": []
  },
  "risk": {
    "score": 78,
    "band": "HIGH",
    "confidence": 0.75,
    "feature_contributions": {
      "malicious_engine_ratio": 23.5,
      "abuse_confidence_score": 16.75,
      "community_pulse_count": 0.0,
      "historical_reports": 3.2,
      "open_ports_risk": 0.0,
      "urlscan_verdict": 0.0
    }
  },
  "mitre_techniques": [
    {
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "tactic": "Credential Access",
      "confidence": 0.85
    }
  ],
  "all_tags": ["abuseipdb:high_confidence", "abuseipdb:brute-force", "vt:malicious"],
  "provider_results": [...]
}
```

## Project Structure

```
ioc-enrichment-pipeline/
├── ioc_enricher/
│   ├── __init__.py           # Package version
│   ├── __main__.py           # Click CLI entry point
│   ├── pipeline.py           # Async orchestration engine
│   ├── classifier.py         # Weighted risk scoring + feature extraction
│   ├── ioc_parser.py         # IOC parsing, defanging, classification
│   ├── models/
│   │   └── ioc.py            # Pydantic v2 data models + ECS serialization
│   ├── providers/
│   │   ├── base.py           # Abstract provider with retry/backoff
│   │   ├── virustotal.py     # VirusTotal v3 API
│   │   ├── abuseipdb.py      # AbuseIPDB v2 API
│   │   ├── shodan.py         # Shodan host API
│   │   └── otx.py            # OTX + URLScan providers
│   └── utils/
│       ├── config.py         # YAML + env var config management
│       ├── logger.py         # structlog JSON/console logging
│       ├── rate_limiter.py   # Async token bucket rate limiter
│       └── mitre.py          # MITRE ATT&CK technique mapping
├── tests/                    # Full pytest test suite
├── config/
│   └── config.example.yaml   # Documented example configuration
├── requirements.txt
├── setup.py
└── pytest.ini
```

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=ioc_enricher --cov-report=term-missing
```

## Environment Variables

| Variable | Config Path | Description |
|---|---|---|
| `VT_API_KEY` | `providers.virustotal.api_key` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | `providers.abuseipdb.api_key` | AbuseIPDB API key |
| `SHODAN_API_KEY` | `providers.shodan.api_key` | Shodan API key |
| `OTX_API_KEY` | `providers.otx.api_key` | AlienVault OTX API key |
| `URLSCAN_API_KEY` | `providers.urlscan.api_key` | URLScan.io API key |
| `LOG_LEVEL` | `pipeline.log_level` | Logging verbosity |
| `PIPELINE_CONCURRENCY` | `pipeline.concurrency` | Max concurrent IOC enrichments |

## Certifications Context

Built as a portfolio project demonstrating skills relevant to:

- **Detection Engineering**: IOC normalization, enrichment pipeline design, ECS output for SIEM ingestion
- **Threat Intelligence**: Multi-source aggregation, MITRE ATT&CK mapping, confidence scoring
- **ML in Security**: Feature engineering, weighted scoring models, explainable AI contributions
- **Security Engineering**: Async Python, retry logic, rate limiting, structured logging, production-ready code quality
