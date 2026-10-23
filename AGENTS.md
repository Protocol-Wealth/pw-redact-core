# AGENTS.md — pw-redact

Engineering and regulatory standards for every agent are `~/projects/AGENTS.md`.
Where this file conflicts with that one, that one wins. This file is only what
is specific to this repository. It does not describe what is live.

## What This Repo Is

pw-redact is an open-source PII redaction engine for financial services AI pipelines.
It strips personally identifiable information from financial text (meeting transcripts,
tax notes, mortgage documents) before it reaches AI models, while preserving dollar
amounts, percentages, tax brackets, and financial acronyms.

It is stateless: it stores nothing, and redaction manifests are returned to the caller.
Regex runs before NLP. Authentication is a service-to-service API key
(`PW_REDACT_API_KEY`); the API is not client-facing.

**Stack:** Python 3.12 · FastAPI · Presidio · spaCy · Fly.io
**License:** MIT
**Status:** discontinued reference implementation (replaced by the pw-os PII guard); nothing deploys it, and CI runs only on manual dispatch.

## Key Files

| File | Purpose |
|------|---------|
| `src/pw_redact/main.py` | FastAPI app, routes, middleware, landing page |
| `src/pw_redact/redactor/engine.py` | Core redaction engine (orchestrates 4 layers) |
| `src/pw_redact/redactor/regex_patterns.py` | Layer 1: 30 deterministic regex patterns |
| `src/pw_redact/redactor/presidio_config.py` | Layer 2: Presidio + spaCy NLP setup |
| `src/pw_redact/redactor/financial_recognizers.py` | Layer 3: CUSIP, account refs, policy numbers |
| `src/pw_redact/redactor/allow_list.py` | Layer 4: financial data preservation |
| `src/pw_redact/security/` | Input validation, injection detection, output validation, rate limiting |
| `src/pw_redact/rehydrator/engine.py` | Manifest-based placeholder restoration |
| `tests/` | Test suite (CI coverage floor 85%) |

## Commands

```bash
# Install
pip install -e ".[dev]" && python -m spacy download en_core_web_lg

# Test
pytest tests/ -v

# Lint
ruff check src/ && ruff format --check src/

# Run locally
uvicorn pw_redact.main:app --port 8080
```

## Boundaries

Public repository. What belongs here: redaction logic, regex patterns, Presidio
configuration, financial allow-list, API server code, tests, documentation,
synthetic fixtures only, and generic deployment examples (`Dockerfile`,
`fly.toml.example`).

Never commit:

- API keys, secrets, tokens, or passwords (use env vars exclusively)
- Internal URLs for private services or dashboards
- Client data, real transcripts, real names, or real SSNs
- Organization-specific deployment config (actual `fly.toml`, actual `.env`)
- References to specific clients, advisors, or internal business processes
- Private governance or compliance documents
- Vendor-specific references or PW business logic

Deployment separation: `fly.toml.example` stays in the repo with placeholder
values. Actual `fly.toml` and `.env` are gitignored.

## Rules

1. **No real PII.** Test fixtures use synthetic data only. Never include real names, SSNs, addresses, or client data.
2. **MIT license header** on every new `.py` file:
   ```python
   # Copyright 2026 Protocol Wealth LLC
   # Licensed under the MIT License
   # https://github.com/Protocol-Wealth/pw-redact-core
   ```
3. **Every new regex pattern** needs 3+ test cases (match, non-match, extracted text).
4. **Financial data must survive.** Verify allow-list doesn't conflict when adding patterns.
5. **Security matters.** This sits at the chokepoint of an AI pipeline processing SEC-regulated data. Use `hmac.compare_digest()` for secrets, validate all external input, use possessive quantifiers in regex to prevent ReDoS.
6. **This is a public repo.** No internal URLs, no vendor-specific references, no PW business logic.
7. **Run tests before committing.** All tests must pass. Lint + format must pass. Coverage must stay above 85%.

## Deploy and CI

- Template: `fly.toml.example`. Copy to `fly.toml` locally; do not commit it.
- CI: `.github/workflows/ci.yml` runs only on manual dispatch: `ruff check src/`, `ruff format --check src/`, and `pytest tests/` with `--cov=pw_redact --cov-fail-under=85`.

## Architecture

```
Request → Rate Limiter → Content-Length Guard → Input Validator
  → Injection Detector → Unicode Normalization
  → Layer 1 (Regex) + Layer 2 (Presidio NLP) → Merge/Dedup
  → Layer 3 (Financial Recognizers) → Layer 4 (Allow-List)
  → Placeholder Generation → Output Validator → Response
```

## Adding New Patterns

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

Quick version:
1. Add `_PatternDef` to `regex_patterns.py` (with score and optional group)
2. Add tests in `test_regex_patterns.py`
3. Verify allow-list compatibility
4. Update README.md "Supported Entity Types" table
5. Run `pytest tests/ -v`

## Document Contexts

| Context | Use for |
|---------|---------|
| `general` | Default — core PII detection |
| `meeting_transcript` | Aggressive name detection + NRP |
| `tax_return` | EINs, account refs |
| `financial_notes` | CUSIPs, policy numbers |
| `mortgage` | NRP + account refs + policy numbers |
| `real_estate` | Account refs + policy numbers |

## Related Documentation

- [docs/architecture.md](docs/architecture.md) — Pipeline deep dive
- [docs/deployment.md](docs/deployment.md) — Deployment guide
- [docs/allow-list-guide.md](docs/allow-list-guide.md) — Allow-list customization
- [SECURITY.md](SECURITY.md) — Vulnerability reporting
