# Security Policy

## Supported Version

| Version | Supported |
|---|---|
| 2.0.0 (Apex) | ✅ |

## Responsible Disclosure

This framework is for **legally authorized** security testing only
(bug bounty programs and authorized engagements).

If you find a vulnerability **in NEXUS itself**:

1. Do **not** open a public issue with exploit details.
2. Email the maintainer (see GitHub profile) with:
   - description + impact
   - reproduction steps (PoC)
   - affected version (`nexus.py --version`)
3. Allow up to 30 days for a response before any disclosure.

## Usage Boundaries

NEXUS enforces a strict **detection + proof-of-concept** boundary:

- ✅ enumerate, fingerprint, detect, prove (PoC)
- ❌ data extraction, modification, persistence, backdoors, shells

Out-of-scope targets are blocked in code (`lib/scope_validator.py`),
destructive payloads are rejected (`lib/payload_guard.py`), and reports
are sanitized to proof-only evidence (`core/sanitizer.py`).

**Operators are responsible for authorization.** Unauthorized use is
prohibited by the license.
