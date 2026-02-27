# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2025-03-15

### Added

- **Core scanning engine** with Pattern, AST, and LLM-powered rule types
- **5 built-in rule packs** (44 rules total):
  - `generic/secrets-detection` — 12 rules for hardcoded keys, tokens, passwords
  - `generic/owasp-top10` — 10 rules for SQL injection, XSS, SSRF, etc.
  - `generic/pii-handling` — 8 rules for email, SSN, credit card exposure
  - `generic/audit-logging` — 7 rules for missing audit logs
  - `generic/tls-encryption` — 7 rules for insecure TLS and ciphers
- **GitHub App integration** with webhook-based PR scanning
- **Multiple output formats**:
  - GitHub Check Runs with inline annotations
  - SARIF upload to GitHub Code Scanning
  - PR comments with detailed violation info
  - Rich CLI table output
- **Rule packs framework** for custom compliance rules
- **DPDP compliance analysis** (Data Protection and Privacy Act compliance)
- **FastAPI** web server with health check endpoints
- **Celery** async task processing with Redis broker
- **PostgreSQL** backend for scan history and results
- **CLI tool** with 6 commands (scan, compliance, init, packs, validate-pack, test-rule, test-pack)
- **Docker Compose** stack for local development
- **Comprehensive test suite** (85+ tests, 80%+ coverage)
- **Documentation**:
  - Quick start guide
  - Rule authoring guide
  - Azure hosting guide
  - Architecture documentation
- **Open-core license** (AGPL-3.0)

### Security

- HMAC-SHA256 webhook signature verification
- JWT RS256 GitHub App authentication
- Automatic secret redaction in scan output
- Input validation via Pydantic

---

## [Unreleased]

### Planned

- **LLM rule improvements** — Enhanced prompt engineering and caching
- **Dependency scanning** — Package vulnerability detection
- **Custom reporters** — Plugin system for output formats
- **Inline suppression** — Per-rule suppression with `@anaya-ignore`
- **Baseline comparison** — Only report new violations vs baseline
- **Web dashboard** — Real-time scan monitoring and reporting
- **CI/CD integrations** — First-class support for GitLab, Bitbucket, Azure DevOps

---

## [0.x] — Development Releases

The project was developed in private with internal releases. See Git history for detailed changes.
