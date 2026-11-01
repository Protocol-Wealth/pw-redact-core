# Changelog

All notable changes to pw-redact will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - 2026-09-21

### Security
- The service refuses to start, and refuses every authenticated request with 503, when `PW_REDACT_API_KEY` is unset, empty, or still the `.env.example` placeholder. Previously the key defaulted to that public placeholder, so an unconfigured deployment accepted it.
- Detection runs on a canonical copy of the text: look-alike dashes (U+2010-U+2015, U+2212, U+FE58, U+FE63, U+FF0D) become `-`, look-alike spaces (NBSP, narrow NBSP, U+2000-U+200A, U+205F, U+3000, U+1680) become a space, and invisible characters (zero-width, soft hyphen, bidi controls, BOM) are dropped. SSNs, card numbers and emails written with them were previously returned unredacted. Offsets, manifest originals and replacement stay on the caller's text, so rehydration restores it exactly. Applies to `redact`, `detect`, and both API routes.
- The API key guard also refuses every example key the docs have shown (`your-secret-key`, `your-key`, `your-strong-random-key`, `new-strong-random-key`, `new-key`, `YOUR_API_KEY`) and any key shorter than 32 characters. README, `docs/deployment.md` and the landing page now generate a key or read `$PW_REDACT_API_KEY` instead of showing a literal one.

### Fixed
- The landing page license tag said "Apache 2.0"; the project is MIT.

### Changed
- Repository agent instructions now live in `AGENTS.md`, and root `CLAUDE.md` was removed after its still-current facts moved.

## [0.1.0] - 2026-03-29

### Added
- Initial release: four-layer PII redaction engine (regex, Presidio NLP, financial recognizers, allow-list)
- Security hardening: input validation, prompt injection detection (25 patterns,
  advisory only), output validation, rate limiting (token bucket)
- FastAPI server with `/v1/redact`, `/v1/rehydrate`, `/v1/detect`, `/v1/health` endpoints
- 30 deterministic regex patterns across 6 categories:
  - **PII**: SSN, credit card, email, phone, EIN, DOB, account numbers, driver's license, street address, routing numbers
  - **Secrets**: JWT, API keys, passwords, secrets/credentials, auth tokens, bearer tokens, DB URLs, magic links
  - **Crypto**: Ethereum private keys (0x+64 hex), wallet addresses (0x+40 hex), seed phrases/mnemonics
  - **Mortgage/RE**: NMLS IDs, loan numbers, MERS MIN, FHA/VA/USDA case numbers, APN/parcel numbers, MLS numbers, escrow/title/instrument file references
  - **System IDs**: CRM record IDs, platform/infrastructure IDs (vendor-agnostic)
- Presidio NLP detection with spaCy `en_core_web_lg` for names, addresses, and contextual entities
- Custom Presidio recognizers for CUSIP, account references, and policy numbers
- Financial data allow-list preserving dollar amounts, percentages, tax brackets, basis points, years, ages, form references, and 60+ financial/mortgage/RE acronyms
- Consistent placeholder generation (`<PERSON_1>`, `<US_SSN_1>`, etc.) with manifest for round-trip rehydration
- 6 document contexts: `meeting_transcript`, `tax_return`, `financial_notes`, `mortgage`, `real_estate`, `general`
- API key authentication (Bearer token, service-to-service)
- 332 tests (regex, financial recognizers, allow-list, security, API, e2e smoke, rehydrator, regression) — 97% coverage
- Docker and Fly.io deployment support
- Sample test fixtures: meeting transcript, tax notes, meeting notes, mortgage pre-qualification
- Request tracing headers (X-Request-ID, X-Processing-Time-Ms)
- SECURITY.md with vulnerability disclosure policy (security@protocolwealthllc.com)
- GitHub CI workflow (lint + test), issue templates, PR template
- Documentation: architecture, deployment guide, allow-list customization guide
- Landing page (GET /), llms.txt, robots.txt, security.txt (RFC 9116)
- MIT license
