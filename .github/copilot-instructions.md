# GitHub Copilot Code Review Instructions

## Review Philosophy: Invert, Always Invert

Apply Charlie Munger's inversion principle: Instead of asking "Is this code good?", ask **"What would make this code fail?"**

Focus on preventing failure rather than achieving brilliance:
- What edge cases would break this?
- What would cause this to fail in production?
- What would make this unmaintainable in 6 months?
- What security holes does this open?

When something could fail, explain **HOW** it would fail and suggest the prevention.

---

## Project Context: octodns-porkbun

Porkbun DNS provider for octoDNS using the oinker library. Python 3.13+.

### Tech Stack
- **DNS Client**: oinker (Porkbun API wrapper)
- **octoDNS**: BaseProvider integration
- **Type checking**: ty
- **Linting/Formatting**: ruff
- **Testing**: pytest
- **Package manager**: uv

### Architecture Patterns
- Provider inherits from `octodns.provider.base.BaseProvider`
- Uses oinker's sync `Piglet` client (octoDNS is sync-based)
- Data conversion between octoDNS format and Porkbun/oinker format
- Update strategy: Delete + Create (not in-place edit)

---

## Inversion Checklists by File Type

### Provider Code (`src/octodns_porkbun/**/*.py`)

**Provider failures to prevent:**
- Not inheriting from BaseProvider correctly
- Missing SUPPORTS or SUPPORTS_GEO class attributes
- populate() not returning exists boolean when target=True
- _apply() not handling Create/Update/Delete changes
- Name conversion errors (trailing dots, relative vs absolute)

**Data conversion failures to prevent:**
- octoDNS format not matching expected structure (values vs value)
- Missing trailing dots on hostnames (CNAME, MX, NS, SRV targets)
- Priority/preference field name mismatches
- Structured records (SRV, CAA, SSHFP) not parsing content correctly

**oinker integration failures to prevent:**
- Not using context manager for Piglet client
- Credentials not passed or env fallback not working
- TTL validation errors (oinker enforces 600s minimum)

**Exception handling failures to prevent:**
- Not catching oinker exceptions and surfacing appropriately
- Zone not found errors not handled gracefully

### Tests (`tests/**/*.py`)

**What would make these tests meaningless?**
- Tests that pass but don't assert meaningful outcomes
- Mocks without proper setup (missing context manager support)
- Missing edge cases: empty zones, unsupported record types
- Not testing both populate and apply paths
- Not testing name conversion edge cases (root, nested subdomains)

### Test Fixtures (`tests/conftest.py`)

**What would make fixtures unreliable?**
- Fixtures without proper cleanup
- Mock Piglet without context manager support
- Fixtures returning mutable state shared across tests

### Project Config (`pyproject.toml`)

**What would break the build/test cycle?**
- Missing octodns or oinker dependencies
- Incompatible version constraints
- Coverage excluding important paths

### CI Workflows (`.github/workflows/**`)

**What would cause CI to give false confidence?**
- Not testing all supported Python versions (3.13, 3.14)
- Missing typecheck step (`ty check`)
- Secrets exposed in logs
- Caching that hides dependency issues

### Makefile

**What would make the Makefile unreliable?**
- Missing `.PHONY` declarations
- Commands that fail silently
- Inconsistency between Makefile and CI commands

---

## What NOT to Review

Don't nitpick these—automated tools handle them:
- **Style issues**: ruff handles formatting and linting
- **Type errors**: ty handles type checking
- **Import order**: ruff's isort handles this

Focus review time on logic, architecture, and failure modes.
