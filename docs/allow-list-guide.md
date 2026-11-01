# Allow-List Guide

The allow-list is what makes pw-redact useful for financial services. Without it,
Presidio's NLP would redact dollar amounts, percentages, and tax bracket numbers —
destroying the financial data AI models need to analyze.

## How It Works

The allow-list operates at two levels:

### 1. Regex Patterns (Post-Detection Filter)

After all entities are detected (regex + Presidio), each detected entity's text
is checked against allow-list regex patterns via `re.fullmatch()`. If it matches,
the entity is removed from the redaction list.

**File:** `src/pw_redact/redactor/allow_list.py` → `ALLOW_PATTERNS`

Example: Presidio might detect "2032" as a DATE_TIME entity. The allow-list
pattern `r"20[2-9]\d"` matches "2032" via fullmatch, so it's preserved.

### 2. Literal Terms (Presidio Exclusion)

A list of exact strings is passed to Presidio's `allow_list` parameter, preventing
NLP from detecting them as entities in the first place. This is more efficient than
post-filtering because Presidio never generates the detection.

**File:** `src/pw_redact/redactor/allow_list.py` → `ALLOW_TERMS`

Example: "AGI" might be detected as a person name by spaCy NER. Including "AGI"
in the literal allow-list prevents this.

## Current Patterns

### Dollar Amounts
```
$425,000   $50k   $10.50   $1,200,000
```
Pattern: `\$[\d,]+(?:\.\d{1,2})?(?:[kKmMbB])?`

### Comma-Separated Numbers
```
425,000   95,000   1,200,000
```
Pattern: `\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?`

Note: Numbers **without** commas (like "425000") are NOT in the allow-list.
This is intentional — a bare 6+ digit number could be an account number or
other identifier. Use commas for financial amounts.

### Percentages
```
32%   6.75%   0.95%
```
Pattern: `\d+\.?\d*\s*%`

### Tax Brackets
```
32% bracket   24% rate   37% tier
```
Pattern: `(?:10|12|22|24|32|35|37)\s*%\s*(?:bracket|rate|tier)`

### Basis Points
```
250 bps   50 bp   100 basis points
```
Pattern: `\d+\s*(?:bps?|basis\s+points?)`

### Planning Years
```
2032   2026   2099
```
Pattern: `20[2-9]\d`

Note: Years before 2020 are NOT preserved (could be part of identifiers).

### Ages
```
age 59.5   age 70.5   age 65
```
Pattern: `(?i)age\s+\d{1,3}(?:\.\d)?`

### IRS Form References
```
Form 1040   Schedule D   IRC §1015
```
Pattern: `(?:Form|Schedule|IRC\s*§?)\s*[A-Z0-9§.-]+`

### Financial Acronyms

Investment: AGI, MAGI, QBI, RMD, QCD, NUA, IRA, SEP, SIMPLE, 401k, 403b, 457b, 529, HSA, FSA, W2, W-2, 1099

Mortgage/RE: LTV, DTI, PMI, PITI, MIP, UFMIP, ARM, FRM, HELOC, HEL, TILA, RESPA, ECOA, HMDA, TRID, URLA, QM, ATR, DU, LP, AUS, GFE, LE, CD, HUD, ALTA, CLTA, CPL, FNMA, FHLMC, GNMA, VOE, VOD, VOM, VOR

General: FICO, CUSIP, ISIN, ETF, NAV, AUM, EBITDA, P/E, EPS, ROI, ROE, CROIC, FHA, HUD, HOA, APR, MERS, MLS, Fannie Mae, Freddie Mac, Ginnie Mae

"Roth" is handled by context, not as a literal term, because it is also a surname: `is_roth_account()` keeps "Roth IRA", "Roth 401(k)", "a Roth conversion" and "backdoor Roth", while "Mr. Roth" is still redacted.

## Adding New Patterns

### Adding a Regex Pattern

Add to `ALLOW_PATTERNS` in `allow_list.py`:

```python
ALLOW_PATTERNS: list[str] = [
    # ... existing patterns ...
    # Your new pattern (must work with re.fullmatch)
    r"your_pattern_here",
]
```

Test it:
```python
from pw_redact.redactor.allow_list import compile_allow_patterns

patterns = compile_allow_patterns()
assert any(p.fullmatch("your example text") for p in patterns)
```

### Adding a Literal Term

Add to `ALLOW_TERMS` in `allow_list.py`:

```python
ALLOW_TERMS: list[str] = [
    # ... existing terms ...
    "YOUR_TERM",
]
```

### Testing Your Addition

Always verify both directions:

1. **Preserved:** Your financial term is NOT redacted
   ```python
   result = redactor.redact("John Smith has an LTV of 80%.")
   assert "LTV" in result.sanitized_text
   assert "80%" in result.sanitized_text
   ```

2. **PII still caught:** Real PII near your term is still detected
   ```python
   result = redactor.redact("John Smith has an LTV of 80%.")
   assert "John Smith" not in result.sanitized_text
   ```

## Common Pitfalls

1. **Don't use `\b` in allow patterns.** Use `re.fullmatch()`, which already
   anchors to start/end. Word boundaries inside fullmatch patterns cause issues.

2. **Don't make patterns too broad.** `\d+` would match any number, preventing
   SSN and phone detection. Always be as specific as possible.

3. **Test with the full pipeline.** An allow-list pattern might look correct in
   isolation but conflict with regex or Presidio detection in unexpected ways.

4. **Remember: allow-list checks entity text, not surrounding text.** If Presidio
   detects "425,000" as an entity, the allow-list checks "425,000" — not the
   full sentence.
