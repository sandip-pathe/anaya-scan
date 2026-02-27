# Agent Instructions — AnaYa

General guidelines for AI agents working on the AnaYa codebase.

## Project

**AnaYa:** Compliance-as-code engine scanning GitHub PRs for security/compliance violations.

**Stack:** Python 3.12, FastAPI, Celery, PostgreSQL, tree-sitter

## Guidelines

### Code Quality
1. Type hints on all public functions
2. Use Pydantic models for data structures
3. Async/await for I/O operations
4. Comprehensive docstrings

### Testing
1. Unit tests with pytest
2. Mock external APIs (GitHub, OpenAI)
3. Test fixtures in `tests/fixtures/`
4. Target 80%+ coverage

### Documentation
1. Update if public APIs change
2. Add examples for new features
3. Link related documentation
4. Keep `anaya.yml` schema documented

### Performance
1. Minimize GitHub API calls (use batching)
2. Cache where possible (tokens, parsed rules)
3. Prefer AST rules over LLM (speed)
4. Profile before optimization

### Security
1. No hardcoded secrets
2. Validate all inputs (Pydantic)
3. Use HMAC-SHA256 for webhook verification
4. Handle errors gracefully

## Common Tasks

**Add rule:** YAML in `anaya/packs/generic/`, test fixtures, test
**Add scanner:** Subclass `BaseScanner`, implement `scan()`, add tests
**Add CLI command:** Add to `cli/main.py` with @app.command()
**Fix bug:** Write test first, then fix, ensure coverage maintained

## Running Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
docker compose up -d
pytest tests/ -v
```

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) — System design
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution guidelines
- [docs/rule-authoring.md](docs/rule-authoring.md) — Rule writing
- [.github/copilot-instructions.md](.github/copilot-instructions.md) — Copilot rules
