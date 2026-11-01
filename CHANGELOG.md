# Changelog

All notable changes to pw-redact will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - 2026-09-21

### Security
- The service refuses to start, and refuses every authenticated request with 503, when `PW_REDACT_API_KEY` is unset, empty, or still the `.env.example` placeholder. Previously the key defaulted to that public placeholder, so an unconfigured deployment accepted it.
- Detection runs on a canonical copy of the text: look-alike dashes (U+2010-U+2015, U+2212, U+FE58, U+FE63, U+FF0D) become `-`, look-alike spaces (NBSP, narrow NBSP, U+2000-U+200A, U+205F, U+3000, U+1680) become a space, and invisible characters (zero-width, soft hyphen, bidi controls, BOM) are dropped. SSNs, card numbers and emails written with them were previously returned unredacted. Offsets, manifest originals and replacement stay on the caller's text, so rehydration restores it exactly. Applies to `redact`, `detect`, and both API routes.
- The API key guard also refuses every example key the docs have shown (`your-secret-key`, `your-key`, `your-strong-random-key`, `new-strong-random-key`, `new-key`, `YOUR_API_KEY`) and any key shorter than 32 characters. README, `docs/deployment.md` and the landing page now generate a key or read `$PW_REDACT_API_KEY` instead of showing a literal one.
- Overlapping detections now merge into their union. Before, the higher-scoring detection replaced the other, so the rest of the lower-scoring span stayed in clear: for "(212) 555-0199 ext 22" the regex match won and "(" and "ext 22" were returned unredacted. The allow-list now runs on each detection before the merge, so an allow-listed span (a year, an amount) can neither absorb nor suppress overlapping PII.
- The output leak check fails closed. If an original value is still in the sanitized text, the manifest is malformed, or the check itself raises, `/v1/redact` answers 500 and returns neither text nor manifest; before, it returned the text with `output_valid: false`. The check also finds originals that start or end with punctuation, such as "(212) 555-0199", which the `\b...\b` search missed. A placeholder-format warning alone stays advisory.
- `/v1/detect` and `/v1/rehydrate` are rate limited; only `/v1/redact` was. The limit is shared across all three routes.
- `/v1/detect` applies the same input validation and sanitization as `/v1/redact` (413 for oversized input) and reports it, with injection detection, in a new `security` object. **Its offsets now refer to the sanitized text**, not the raw request text, so they match the redact manifest; a caller that highlights the raw text must account for `security.sanitization_actions`.
- Every occurrence of a detected value (5+ characters) is redacted, not only the occurrences a detector caught: "JOHN SMITH" after "John Smith", "ab123456" after "AB123456", a copy with a U+2011 hyphen or extra spaces. Each copy keeps its exact original in the manifest, so rehydration is exact.
- The output leak check compares on the same normalized form (`canonicalize()`, case folding, whitespace runs), so those copies count as leaks if any remain. Fail-closed stays the backstop.
- Output warnings are fixed codes only. `invalid_placeholder_format:<text>` quoted caller text, which the withheld 500 then returned: a leaked value inside `<...>` came back in clear. Unknown entity types in a manifest are reported as `UNKNOWN`.
- Failed authentication (401/403) is rate limited per client IP (5 burst, 10/minute); further failures get 429. A correct key is never refused by this budget.
- The configured API key is compared stripped, as `api_key_problem` already judged it; a key with a trailing newline passed the startup check but could never match. A non-ASCII bearer token is answered 403 instead of 500.
- "Roth" is no longer a literal allow-list term, which made Presidio drop the surname in "Mr. Roth". A context rule keeps the account sense unredacted: a product word after ("Roth IRA", "Roth 401(k)", "Roth conversion", "Roth vs traditional") or a planning phrase before ("backdoor Roth", "convert to Roth", "max out the Roth"). "Contribute(d) to" alone does not count ("we contributed to Roth last year", "campaign contributions to Roth" are redacted) unless an account word follows ("contribute to a Roth IRA", "Roth contribution limits"). An article or possessive alone does not count ("the Roth family" is redacted); a title before it (Mr, Mrs, Dr, Judge, Sen, Rep, Rev, Rabbi, Officer, Professor, Grandpa, Grandma, any case) always means a person; "Roth options" is treated as ambiguous and redacted.

### Fixed
- The landing page license tag said "Apache 2.0"; the project is MIT.
- `/v1/rehydrate` answers 422 with `Invalid manifest: ...` for a malformed manifest (placeholders not a list, a bad placeholder format, a non-string value, an overlong original), instead of 500.
- Keyword-triggered patterns no longer redact the next ordinary word. `LOAN_NUMBER`, `FILE_REFERENCE`, `MLS_NUMBER`, `PARCEL_NUMBER` and the `POLICY_NUMBER` recognizer now need the value to contain a digit, and the keyword must not sit inside a lowercase word: "loan application", "title insurance", "listing agreement", "contract renewal" and "Denote everything" were all redacted before. The keyword may still follow `_`, a digit or start a camelCase part ("client_loan: 12345678", "HomeLoan #12345678", "2ndMortgage 12345678"). **Identifiers made only of letters are no longer caught by these patterns.** `POLICY_NUMBER` lost its trailing `\b` and now covers the whole alphanumeric run with possessive quantifiers (linear time; 100 KB inputs take under 0.05 s), so a 21+ character number is no longer missed and no tail is left in clear. The digit must occur in the first 64 characters, and a bare quarter ("contract 2025Q1") is not a policy number.
- Prompt-injection detection (still advisory) matches common phrasings it missed, such as "ignore all the previous instructions", "disregard any of your prior rules", "forget everything above" and "you are no longer bound by". Ordinary sentences like "ignore the previous email" are still not flagged.
- `regex` is declared as a dependency; `regex_patterns.py` imports it, and it was only installed transitively through Presidio.
- `spacy` is pinned to `>=3.8,<3.9`, matching the model wheel CI installs.
- CI caches the pinned `en_core_web_lg` wheel and pip downloads, and checks the wheel's sha256 before installing it. The old cache of `~/.cache/spacy` never hit, because `spacy download` pip-installs the model. CI still runs only on manual dispatch.

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
