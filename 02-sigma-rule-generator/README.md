# Module 02 — SIGMA Rule Generator

> AI-augmented detection engineering: converts unstructured threat intelligence into production-ready SIGMA rules in seconds.

## What It Does

The SIGMA Rule Generator takes raw, unstructured threat intelligence — threat reports, CVE descriptions, IOC lists, raw log snippets — and uses Claude to produce validated, deployment-ready [SIGMA](https://sigmahq.io) detection rules with:

- **MITRE ATT&CK mapping** — technique and tactic tags auto-populated
- **Confidence scoring** — 0–100% with LLM rationale explaining the score
- **False positive guidance** — realistic, enterprise-specific FP callouts
- **YAML validation** — rules verified against SIGMA specification before output
- **Multi-format output** — `.yml` for SIEM import, `.json` for pipeline integration

## Architecture

```
Threat Intel Input
       │
       ▼
 ┌─────────────┐
 │PromptBuilder│  ← detects input type, renders Jinja2 template
 └──────┬──────┘
        │  user prompt
        ▼
 ┌─────────────┐
 │  Claude LLM │  ← claude-sonnet-4-6, temp=0 (deterministic)
 │  (Anthropic)│
 └──────┬──────┘
        │  JSON response
        ▼
 ┌─────────────┐
 │  RuleParser │  ← extracts JSON, maps dicts → SigmaRule models
 └──────┬──────┘
        │  list[SigmaRule]
        ▼
 ┌──────────────┐
 │SigmaValidator│  ← checks required fields, MITRE IDs, YAML structure
 └──────┬───────┘
        │  ValidationResult
        ▼
 ┌─────────────┐
 │ SIGMA YAML  │  ← pySigma-compatible output + JSON metadata
 └─────────────┘
```

## Supported Input Types

| Type | Description | Example |
|------|-------------|---------|
| `threat_report` | SOC analysis, IR reports, blog posts | `examples/threat_reports/cobalt_strike.txt` |
| `cve` | CVE descriptions, NVD entries, advisory text | Any text containing `CVE-YYYY-NNNNN` |
| `ioc_list` | IPs, domains, file hashes with context | Structured IOC feeds |
| `log_snippet` | Raw Windows/Sysmon/firewall log lines | Event logs showing malicious activity |
| `freeform` | Anything else | General security notes |

Input type is auto-detected from content patterns; override with `--type`.

## Quick Start

### 1. Install

```bash
cd 02-sigma-rule-generator
pip install -e .
```

### 2. Configure API Key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Or copy `config/config.example.yaml` to `config/config.yaml` and set `llm.api_key`.

### 3. Generate Rules

```bash
# From a threat report file
sigma-generator generate --input examples/threat_reports/mimikatz.txt

# From inline text
sigma-generator generate --text "Mimikatz credential dumping via sekurlsa::logonpasswords detected"

# Force input type, output both YAML and JSON
sigma-generator generate \
  --input examples/threat_reports/cobalt_strike.txt \
  --type threat_report \
  --format both \
  --output ./my-rules

# Filter low-confidence rules
sigma-generator generate \
  --input examples/threat_reports/ransomware.txt \
  --min-confidence 0.7
```

### 4. Batch Process a Directory

```bash
sigma-generator batch \
  --input-dir examples/threat_reports/ \
  --output-dir ./output/ \
  --format yaml
```

### 5. Validate an Existing Rule

```bash
sigma-generator validate --input ./output/suspicious-powershell-download-cradle_20240315T120000.yml
```

## Example Generated Rule

Given the mimikatz threat report, the generator produces:

```yaml
title: Mimikatz Credential Dumping via sekurlsa Module
id: a7f3b291-4c8e-4d5a-9f12-3e8b7c2a1d6f
status: experimental
description: Detects execution of Mimikatz credential dumping module sekurlsa against
  LSASS memory. This technique is used by threat actors to extract plaintext credentials
  and NTLM hashes from Windows authentication processes.
author: AI Detection Platform
date: 2024/03/15
modified: 2024/03/15
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://github.com/gentilkiwi/mimikatz
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - sekurlsa::
      - lsadump::
      - privilege::debug
      - Invoke-Mimikatz
  condition: selection
falsepositives:
  - Authorised red team operations with prior written approval
  - Security product testing in isolated lab environments
level: high
```

## CLI Reference

### `generate`

```
sigma-generator generate [OPTIONS]

  --input, -i PATH          Input file (threat report, CVE, log snippet)
  --text, -t TEXT           Inline text input
  --type [threat_report|cve|ioc_list|log_snippet|freeform]
  --output, -o PATH         Output directory (default: ./output)
  --format, -f [yaml|json|both]  Output format (default: yaml)
  --author TEXT             Override rule author field
  --min-confidence FLOAT    Filter rules below this threshold (0.0–1.0)
  --no-validate             Skip validation step
```

### `validate`

```
sigma-generator validate --input PATH

  Validates an existing SIGMA rule YAML file against the specification.
  Exit code 1 if invalid.
```

### `batch`

```
sigma-generator batch [OPTIONS]

  --input-dir, -i PATH      Directory of .txt/.md input files
  --output-dir, -o PATH     Output directory (default: ./output)
  --format [yaml|json|both]
```

### Global Options

```
  --config PATH             YAML config file path
  --log-level [DEBUG|INFO|WARNING|ERROR]
  --json-logs/--no-json-logs  Structured JSON logs (default: on)
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

All tests use mocked Anthropic API calls — no real API key required for testing.

## Environment Variables

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `ANTHROPIC_API_KEY` | `llm.api_key` | Anthropic API key |
| `SIGMA_MODEL` | `llm.model` | Override model (default: claude-sonnet-4-6) |
| `SIGMA_OUTPUT_DIR` | `output.output_dir` | Output directory |
| `SIGMA_AUTHOR` | `generator.default_author` | Default rule author |
| `LOG_LEVEL` | `generator.log_level` | Log verbosity |
| `SIGMA_CONFIG` | — | Path to config YAML file |

## Module Context — AI Detection Platform

This is **Module 02** of a 5-module AI detection engineering platform:

| Module | Name | Description |
|--------|------|-------------|
| 01 | IOC Enrichment Pipeline | Multi-source IOC enrichment with risk scoring |
| **02** | **SIGMA Rule Generator** | **AI-powered detection rule authoring** |
| 03 | RAG Triage Assistant | LLM-powered alert triage with context retrieval |
| 04 | ML Anomaly Detection | Unsupervised behavioral anomaly detection |
| 05 | AI Threat Model Generator | Attack surface modeling from architecture diagrams |

Generated SIGMA rules from this module flow downstream to Module 03 (RAG Triage) which uses them as context when triaging alerts, creating a closed feedback loop between detection authoring and alert investigation.

## Portfolio Context

This module demonstrates:

**For hiring managers / senior engineers:**
- Production-quality Python (type hints, Pydantic v2, async/await, structlog)
- LLM prompt engineering for structured output — system prompt design that produces consistent, schema-valid JSON
- Domain expertise in SIGMA specification, MITRE ATT&CK, and enterprise detection engineering
- Separation of concerns: generator, parser, validator, and models are independently testable
- Test design with full mocking of external API dependencies (100% test isolation)
- CLI design with Rich output, progress bars, and proper exit codes

**Detection engineering skills demonstrated:**
- Understanding of SIEM logsource semantics (Sysmon, Windows Security, network logs)
- MITRE ATT&CK taxonomy and technique/tactic relationships
- False positive analysis in enterprise environments
- SIGMA rule specification compliance (pySigma-compatible output)
