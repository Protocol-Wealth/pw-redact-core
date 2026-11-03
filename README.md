> [!WARNING]
> **Discontinued.** This repository is no longer maintained. Use the TypeScript package [`@protocolwealthos/pii-guard`](https://www.npmjs.com/package/@protocolwealthos/pii-guard) in [pwos-core](https://github.com/Protocol-Wealth/pwos-core) (`packages/pii-guard`) instead. Open issue [#3](https://github.com/Protocol-Wealth/pw-redact-core/issues/3) (overlapping detections can drop the longer span) is tracked in [pwos-core #125](https://github.com/Protocol-Wealth/pwos-core/issues/125).

# pw-redact-core

**Open-source PII redaction engine for financial services AI pipelines.**

The repository is named `pw-redact-core`; the Python package and API retain the `pw-redact` name.

**Project status:** Discontinued reference implementation. Its [CI workflow](.github/workflows/ci.yml) is manual-only. New work belongs in [`@protocolwealthos/pii-guard`](https://www.npmjs.com/package/@protocolwealthos/pii-guard). The examples below describe this codebase; they do not indicate an active deployment.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

Built by [Protocol Wealth LLC](https://protocolwealthllc.com), an SEC-registered
investment adviser, to ensure client data never reaches third-party AI models.

> We believe transparency in how client data is handled shouldn't be a competitive
> secret — it should be an industry standard.

---

**Table of Contents:**
[Why This Exists](#why-this-exists) |
[How It Works](#how-it-works) |
[Quick Start](#quick-start) |
[API Reference](#api-reference) |
[Supported Entity Types](#supported-entity-types) |
[Security](#security) |
[Use Cases](#use-cases) |
[Testing](#testing) |
[Performance](#performance) |
[Deployment](#deployment) |
[Project Structure](#project-structure) |
[Documentation](#documentation) |
[Contributing](#contributing) |
[License](#license)

---

## Why This Exists

Financial advisors increasingly use AI for meeting transcription, tax analysis,
and planning recommendations. Most solutions send raw client data — names, SSNs,
addresses — to cloud AI providers. pw-redact sits between your data and the AI
model, stripping PII while preserving the financial data models need to work.

**The problem:**
```
"John Smith's AGI is $425,000. SSN: 123-45-6789."
                    ↓ sent to AI model ↓
        AI sees real names, real SSNs — compliance violation
```

**With pw-redact:**
```
"John Smith's AGI is $425,000. SSN: 123-45-6789."
                    ↓ pw-redact /v1/redact ↓
"<PERSON_1> AGI is $425,000. SSN: <US_SSN_1>."
                    ↓ sent to AI model ↓
        AI sees placeholders — PII never leaves your infrastructure
                    ↓ pw-redact /v1/rehydrate ↓
        Original names restored for advisor display
```

## How It Works

pw-redact uses a four-layer architecture to catch PII while preserving financial data:

```
Raw text (transcript, tax notes, mortgage docs)
        |
        v
   [ Security Layer ]
   Input validation, prompt injection detection, rate limiting
        |
        v
   pw-redact /v1/redact
   |-- Layer 1: Deterministic regex (SSN, CC, EIN, loan numbers, crypto keys...)
   |-- Layer 2: Presidio NLP (names, addresses, phone, email via spaCy NER)
   |-- Layer 3: Custom financial recognizers (CUSIP, account refs, policy numbers)
   |-- Layer 4: Allow-list (preserve $amounts, %, tax brackets, dates)
   `-- Returns: sanitized_text + redaction_manifest + security metadata
        |
        v
   Sanitized text -> your AI model (safe to send externally)
        |
        v
   pw-redact /v1/rehydrate
   |-- Takes: AI model output + redaction_manifest
   `-- Returns: output with original values restored
```

**Key design principles:**

- **Stateless** — pw-redact stores nothing. No database, no disk writes. Manifests are returned to the caller.
- **Deterministic first** — Regex patterns run before NLP. If regex catches it, NLP doesn't need to.
- **Financial data survives** — Dollar amounts, percentages, tax brackets, basis points, and 60+ financial acronyms pass through intact.
- **Consistent placeholders** — "John Smith" becomes `<PERSON_1>` everywhere in the document, so the AI model can track entity relationships.
- **Security built in** — Input sanitization, prompt injection detection, output validation, and rate limiting are part of the pipeline, not bolted on.

For deep architecture details, see [docs/architecture.md](docs/architecture.md).

## Quick Start

### Install

```bash
# With pip
pip install -e ".[dev]"
python -m spacy download en_core_web_lg

# With uv (faster)
uv venv && uv pip install -e ".[dev]"
uv pip install en_core_web_lg@https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

### As a Library

```python
from pw_redact.redactor.engine import PWRedactor
from pw_redact.rehydrator.engine import PWRehydrator

redactor = PWRedactor()
rehydrator = PWRehydrator()

# Redact PII
result = redactor.redact(
    "John Smith has SSN 123-45-6789. His AGI is $425,000.",
    context="meeting_transcript",
)

print(result.sanitized_text)
# "<PERSON_1> has SSN <US_SSN_1>. His AGI is $425,000."

# Rehydrate after AI processing
ai_output = "Based on the data, <PERSON_1> should consider a Roth conversion."
restored = rehydrator.rehydrate(ai_output, result.manifest.to_dict())
print(restored)
# "Based on the data, John Smith should consider a Roth conversion."
```

### Different Document Contexts

```python
# Meeting transcript — aggressive name detection
result = redactor.redact(text, context="meeting_transcript")

# Tax return — catches EINs, ITINs
result = redactor.redact(text, context="tax_return")

# Mortgage document — catches NMLS, loan numbers, APN, FHA case numbers
result = redactor.redact(text, context="mortgage")

# Real estate — catches parcel numbers, MLS, title references
result = redactor.redact(text, context="real_estate")
```

### As an API Server

```bash
# At least 32 characters; the server refuses to start with an unset, short or placeholder key
export PW_REDACT_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
uvicorn pw_redact.main:app --host 0.0.0.0 --port 8080
```

```bash
# Redact
curl -X POST http://localhost:8080/v1/redact \
  -H "Authorization: Bearer $PW_REDACT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text": "John Smith SSN 123-45-6789", "context": "general"}'

# Health check (no auth required)
curl http://localhost:8080/v1/health
```

### Docker

```bash
docker build -t pw-redact .
docker run -p 8080:8080 -e PW_REDACT_API_KEY="$PW_REDACT_API_KEY" pw-redact
```

## API Reference

### POST /v1/redact

Redact PII from text. Returns sanitized text, a manifest for rehydration, and security metadata.

**Request:**
```json
{
  "text": "John Smith discussed his AGI of $425,000. SSN: 123-45-6789.",
  "context": "meeting_transcript"
}
```

**Context values:** `meeting_transcript` | `tax_return` | `financial_notes` | `mortgage` | `real_estate` | `general`

**Response:**
```json
{
  "sanitized_text": "<PERSON_1> discussed his AGI of $425,000. SSN: <US_SSN_1>.",
  "manifest": {
    "version": "1.0",
    "redaction_id": "red_a1b2c3d4",
    "placeholders": [
      {"placeholder": "<PERSON_1>", "original": "John Smith", "entity_type": "PERSON", "start": 0, "end": 10},
      {"placeholder": "<US_SSN_1>", "original": "123-45-6789", "entity_type": "US_SSN", "start": 47, "end": 58}
    ],
    "stats": {"entities_found": 2, "entities_by_type": {"PERSON": 1, "US_SSN": 1}, "text_length_original": 60, "text_length_sanitized": 58}
  },
  "security": {
    "input_sanitized": false,
    "sanitization_actions": [],
    "injection_detected": false,
    "injection_score": 0.0,
    "injection_patterns": [],
    "output_valid": true,
    "output_warnings": [],
    "request_id": "req_a1b2c3d4e5f6"
  }
}
```

**Response headers:**
- `X-Request-ID` — Unique request identifier for tracing
- `X-Processing-Time-Ms` — Server-side processing time

### POST /v1/rehydrate

Restore original values from placeholders using the manifest.

**Request:**
```json
{
  "text": "Based on <PERSON_1>'s data, a Roth conversion is recommended.",
  "manifest": {"version": "1.0", "redaction_id": "red_a1b2c3d4", "placeholders": [...]}
}
```

**Response:**
```json
{
  "rehydrated_text": "Based on John Smith's data, a Roth conversion is recommended."
}
```

A malformed manifest (placeholders not a list, a placeholder not in `<TYPE_N>`
format, a non-string value, an original over 1,000 characters) is answered with
422 and `{"detail": "Invalid manifest: ..."}`.

### POST /v1/detect

Detect PII locations without redacting. Returns entity positions, types, and confidence scores. Useful for UI highlighting. Input validation is the same as for `/v1/redact`: oversized input is refused with 413, and detection runs on the sanitized text, so offsets match the `/v1/redact` manifest. **Offsets refer to the sanitized text**, not the raw request text: when `security.input_sanitized` is true (HTML stripped, control characters removed, ...), `start`/`end` index into the text after sanitization. Previously `/v1/detect` skipped sanitization and its offsets indexed the raw text. Every occurrence of a detected value is reported, including copies in another case or with look-alike separators.

**Request:**
```json
{
  "text": "John Smith's SSN is 123-45-6789.",
  "context": "general"
}
```

**Response:**
```json
{
  "entities": [
    {"entity_type": "PERSON", "text": "John Smith", "start": 0, "end": 10, "score": 0.85},
    {"entity_type": "US_SSN", "text": "123-45-6789", "start": 20, "end": 31, "score": 0.90}
  ],
  "security": {
    "input_sanitized": false,
    "sanitization_actions": [],
    "injection_detected": false,
    "injection_score": 0.0,
    "injection_patterns": [],
    "request_id": "req_a1b2c3d4e5f6"
  }
}
```

### GET /v1/health

No authentication required.

```json
{"status": "healthy", "version": "0.1.0", "models_loaded": true}
```

## Supported Entity Types

### Layer 1: Regex Detection (30 patterns)

All regex patterns run regardless of document context.

| Category | Entity Type | Example |
|----------|-------------|---------|
| **PII** | `US_SSN` | 123-45-6789 |
| | `CREDIT_CARD` | 4111 1111 1111 1111 |
| | `EMAIL` | john@example.com |
| | `US_PHONE` | (610) 555-1234 |
| | `EIN` | 12-3456789 |
| | `DATE_OF_BIRTH` | DOB: 03/15/1980, birthdate: 1980-03-15 |
| | `ACCOUNT_NUMBER` | account #12345678 |
| | `DRIVERS_LICENSE` | DL# A12345678 |
| | `STREET_ADDRESS` | 42 Oak Lane, 123 Main Street #201 |
| | `US_ROUTING` | routing: 021000021 |
| **Secrets** | `JWT` | eyJ... tokens |
| | `API_KEY` | api_key=..., STRIPE_API_KEY=... |
| | `PASSWORD` | password=..., passwd:... |
| | `SECRET_VALUE` | secret=..., SECRET_KEY=..., private_key=... |
| | `AUTH_TOKEN` | access_token=..., refresh_token=..., session_id=... |
| | `BEARER_TOKEN` | Bearer ... |
| | `DB_URL` | postgres://user:pass@host |
| | `MAGIC_LINK` | reset_link=https://... |
| **Crypto** | `CRYPTO_PRIVATE_KEY` | 0x + 64 hex chars (ETH private keys) |
| | `CRYPTO_ADDRESS` | 0x + 40 hex chars (ETH addresses) |
| | `CRYPTO_SEED` | Quoted seed phrases / mnemonics |
| **Mortgage/RE** | `NMLS_ID` | NMLS# 456789 |
| | `LOAN_NUMBER` | Loan #MTG-2025-004821 |
| | `MERS_MIN` | MERS# + 18 digits |
| | `FHA_CASE_NUMBER` | FHA case #123-4567890 |
| | `PARCEL_NUMBER` | APN: 07-14-302-015 |
| | `MLS_NUMBER` | MLS# PM23456789 |
| | `FILE_REFERENCE` | escrow# NCS-123456-LA |
| **System IDs** | `CRM_ID` | client_id: 987654 |
| | `PLATFORM_ID` | wallet_id=deadbeef... (hex/UUID) |

### Layer 2: Presidio NLP Detection

Presidio entities vary by context. spaCy `en_core_web_lg` provides the NER backbone.

| Entity | Detected In |
|--------|-------------|
| `PERSON` | All contexts |
| `LOCATION` | All contexts |
| `PHONE_NUMBER` | All contexts |
| `EMAIL_ADDRESS` | All contexts |
| `US_SSN` | All contexts (backup to regex) |
| `CREDIT_CARD` | All contexts (backup to regex) |
| `NRP` | meeting_transcript, mortgage |
| `CUSIP` | financial_notes |
| `ACCOUNT_REF` | All except general |
| `POLICY_NUMBER` | meeting_transcript, financial_notes, mortgage, real_estate |

### Layer 4: Financial Data Preserved

The allow-list ensures these are **never redacted**. See [docs/allow-list-guide.md](docs/allow-list-guide.md) for details on customizing.

| Type | Examples |
|------|----------|
| Dollar amounts | $425,000, $50k, 95,000 |
| Percentages | 32%, 6.75% |
| Tax brackets | 32% bracket, 24% rate |
| Basis points | 250 bps, 50 bp |
| Planning years | 2032, 2026 |
| Ages | age 59.5, age 70.5 |
| Form references | Form 1040, Schedule D, IRC S1015 |
| Financial acronyms | AGI, RMD, QCD, 529, W2, 1099 |
| Mortgage/RE terms | LTV, DTI, PMI, TILA, RESPA, HMDA, ALTA, FNMA, VOE |

## Security

pw-redact includes built-in security hardening for AI pipeline protection.
For vulnerability reports, see [SECURITY.md](SECURITY.md).

### Input Validation
- Max payload: 1MB / 50,000 lines (rejects with 413)
- Strips null bytes, ASCII control characters (preserves `\n` and `\t`)
- Strips invisible Unicode (zero-width spaces, bidi overrides, BOM)
- Detects and removes base64-encoded blocks >200 chars (could hide injected instructions)
- Strips HTML tags and `<script>` elements
- Strips markdown image references with external URLs (`![](http://...)`)
- Normalizes excessive whitespace while preserving paragraph structure

### Prompt Injection Detection
- 25 patterns across 7 categories: instruction override, identity manipulation, prompt extraction, injection keywords, encoded variants (leetspeak, spaced characters), role-play/persona, delimiter manipulation
- Returns a confidence score (0.0-1.0) and list of matched patterns
- **Advisory only** — flags suspicious input but does NOT block it. Advisors may legitimately paste client emails containing unusual text. The caller decides policy.
- Injection data included in the `/v1/redact` and `/v1/detect` response `security` key

### Output Validation
- Verifies no original PII values leaked into `sanitized_text`. The comparison ignores case, look-alike dashes and spaces, invisible characters and whitespace runs, so "JOHN SMITH" counts as a leak of "John Smith". The engine already replaces every such occurrence of a detected value (5+ characters), so this is the backstop.
- Warnings are fixed codes (`pii_leak:US_SSN`, `invalid_placeholder_format`) and never quote input text
- Validates all placeholders match the `<TYPE_N>` format
- Checks manifest structural integrity
- **Fails closed** — on a leak, a malformed manifest, or an error in the check itself, `/v1/redact` answers 500 and returns neither `sanitized_text` nor `manifest`. A placeholder-format warning alone stays advisory (caller text can contain `<...>`).

### Rate Limiting
- In-memory token bucket per API key, shared by every authenticated route (`/v1/redact`, `/v1/detect`, `/v1/rehydrate`)
- Default: 60 requests/minute, 10 requests/second burst
- Returns 429 with `Retry-After` header when exceeded
- Failed authentication (401/403) has its own small budget per client IP (5 burst, 10/minute); past it, failed attempts get 429. A correct key is never refused by this budget, so one consumer with a stale key behind a shared proxy cannot lock out the others. Behind a proxy, run uvicorn with `--forwarded-allow-ips` so the client IP is the caller's.
- Configurable via `RATE_LIMIT_RPM` and `RATE_LIMIT_BURST` env vars

### Request Tracing
- `X-Request-ID` header on every response (UUID)
- `X-Processing-Time-Ms` header for latency monitoring

## Use Cases

- **Meeting transcript sanitization** before AI summarization
- **Tax return data extraction** with PII stripped
- **Mortgage/underwriting documents** processed for AI analysis
- **Real estate/title documents** with buyer/seller PII removed
- **Compliance-safe AI integration** for RIAs, broker-dealers, and lenders
- **Client communication review** before sending to AI for drafting
- **Crypto/DeFi operations** with wallet addresses and private keys redacted

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_regex_patterns.py -v
pytest tests/test_security.py -v

# Run with timing
pytest tests/ -v --tb=short
```

**Current:** 332 tests, 97% coverage, ~4s runtime (session-scoped spaCy model load).

## Performance

| Metric | Observed | Notes |
|--------|----------|-------|
| Test suite | 332 tests in ~4s (97% coverage) | spaCy model loaded once per session |
| Short text (<100 words) | <500ms | Regex + Presidio on warm engine |
| Long transcript (~500 words) | ~1-2s | spaCy NER is the bottleneck |
| Cold start (Fly.io resume) | ~8-10s | spaCy en_core_web_lg model load |
| Memory | ~1.2GB steady-state | en_core_web_lg (~560MB) + Presidio + overhead |
| Docker image | ~1.0GB | Python 3.12 slim + spaCy model |

## Deployment

pw-redact runs as a stateless container. See [docs/deployment.md](docs/deployment.md) for full guide.

```bash
# Fly.io (quick start)
cp fly.toml.example fly.toml  # edit app name and region
fly apps create your-app-name
fly secrets set PW_REDACT_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
fly deploy
```

**Note:** Use at least 2GB RAM. spaCy `en_core_web_lg` loads at ~560MB; 1GB VMs will OOM.

## Project Structure

```
pw-redact/
|-- src/pw_redact/
|   |-- main.py                  # FastAPI app, routes, security middleware
|   |-- config.py                # pydantic-settings env var loading
|   |-- auth.py                  # API key authentication
|   |-- redactor/
|   |   |-- engine.py            # PWRedactor — orchestrates all 4 layers
|   |   |-- regex_patterns.py    # Layer 1: 30 deterministic regex patterns
|   |   |-- presidio_config.py   # Layer 2: Presidio + spaCy NLP setup
|   |   |-- financial_recognizers.py  # Layer 3: CUSIP, account ref, policy
|   |   |-- allow_list.py        # Layer 4: financial data preservation
|   |   `-- manifest.py          # Redaction manifest data structures
|   |-- rehydrator/
|   |   `-- engine.py            # Manifest-based placeholder restoration
|   |-- security/
|   |   |-- input_validator.py   # Sanitize dangerous input
|   |   |-- prompt_injection_detector.py  # Flag injection attempts
|   |   |-- output_validator.py  # Verify no PII leaks in output
|   |   `-- rate_limiter.py      # Token bucket rate limiting
|   `-- models/
|       |-- requests.py          # Pydantic request models
|       `-- responses.py         # Pydantic response models
|-- tests/
|   |-- test_regex_patterns.py   # 100+ regex pattern tests
|   |-- test_redactor.py         # Integration tests + round-trip
|   |-- test_allow_list.py       # Financial data preservation
|   |-- test_financial_recognizers.py
|   |-- test_security.py         # Input validation, injection, rate limiting
|   `-- fixtures/                # SYNTHETIC test data only
|-- docs/
|   |-- architecture.md          # Four-layer pipeline deep dive
|   |-- deployment.md            # Docker, Fly.io, Railway, AWS/GCP guide
|   `-- allow-list-guide.md      # How to customize financial preservation
|-- .github/
|   |-- workflows/ci.yml         # Lint + test on push/PR
|   |-- ISSUE_TEMPLATE/          # Bug report + feature request templates
|   `-- PULL_REQUEST_TEMPLATE.md # PR checklist
|-- SECURITY.md                  # Vulnerability disclosure policy
|-- CONTRIBUTING.md              # Code standards, PR process
|-- CHANGELOG.md                 # Version history
|-- AGENTS.md                    # Repository-specific agent instructions
|-- Dockerfile                   # Production container
|-- fly.toml.example             # Fly.io deployment template
`-- pyproject.toml               # Dependencies, build config, tool settings
```

## Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | This file — overview, quick start, API reference |
| [docs/architecture.md](docs/architecture.md) | Four-layer pipeline design, merge algorithm, security pipeline |
| [docs/deployment.md](docs/deployment.md) | Docker, Fly.io, Railway, AWS/GCP deployment guide |
| [docs/allow-list-guide.md](docs/allow-list-guide.md) | How to customize financial data preservation |
| [AGENTS.md](AGENTS.md) | Repository-specific agent instructions |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting: security@protocolwealthllc.com |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code standards, adding patterns, PR process |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Troubleshooting

**spaCy model not found:**
```bash
python -m spacy download en_core_web_lg
# Or with uv:
uv pip install en_core_web_lg@https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

**OOM on Fly.io / Docker:**
Use at least 2GB RAM. If constrained, switch to `en_core_web_md` (~40MB vs ~560MB):
```bash
export SPACY_MODEL=en_core_web_md
python -m spacy download en_core_web_md
```

**False positive — financial data being redacted:**
Check if the value matches an allow-list pattern. If not, add one.
See [docs/allow-list-guide.md](docs/allow-list-guide.md).

**False negative — PII not caught:**
Open a [bug report](https://github.com/Protocol-Wealth/pw-redact-core/issues/new?template=bug_report.md)
with synthetic example data (never real PII).

**"max" detected as person name:**
Known spaCy NLP limitation with common-word names. Over-redacting is safer than
under-redacting. Can be tuned with Presidio score thresholds in a future release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code standards, test requirements, and PR process.

## License

MIT — free for commercial use. See [LICENSE](LICENSE).

## Built By

[Protocol Wealth LLC](https://protocolwealthllc.com) — SEC-registered investment adviser
building transparent AI infrastructure for the advisory industry.

*Built by [Protocol Wealth LLC](https://protocolwealthllc.com)*
