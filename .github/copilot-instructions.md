# AnaYa — GitHub Copilot Instructions

You are assisting with **AnaYa**, an open-source compliance-as-code engine that scans GitHub pull requests for security and compliance violations.

## Project Overview

- **Language:** Python 3.12+
- **Type:** FastAPI + Celery web service with CLI
- **Purpose:** Scan code for security/compliance issues via GitHub App webhook or CLI
- **Components:**
  - Web API (FastAPI)
  - Async worker (Celery + Redis)
  - Database (PostgreSQL)
  - Multiple scanners (Pattern, AST, LLM)
  - Rule packs (YAML-defined)

## Architecture

```
GitHub Webhook → FastAPI → Celery Worker → Scanners → Reporters → GitHub API
```

- **Scanners:** Pattern (regex), AST (tree-sitter), LLM (OpenAI)
- **Reporters:** Check Run, SARIF, PR comment, CLI table
- **Rules:** YAML-defined in `/anaya/packs/generic/`

## Code Style & Standards

### Python
- **Formatter:** Ruff format
- **Linter:** Ruff (E, F, W, I, N, UP, B, SIM)
- **Line length:** 120 characters
- **Type hints:** Mandatory on all public functions
- **Async:** Use `async/await` for I/O operations

### Type Hints Example
```python
async def scan_file(content: str, rules: list[Rule]) -> list[Violation]:
    """Scan file against rules."""
    pass
```

### Pydantic Models
- All data structures inherit from Pydantic BaseModel
- Use `model_validate()` for parsing
- Include field validators where needed

### Naming
- Classes: `PascalCase` (e.g., `PatternScanner`, `RuleLoader`)
- Functions: `snake_case` (e.g., `load_pack`, `run_scan`)
- Constants: `UPPER_SNAKE_CASE`
- Private methods: prefix with `_`

## Project Structure

```
anaya/
├── api/              # FastAPI app, webhooks, middleware
├── engine/           # Core scanning logic, rule loading, orchestration
│   ├── scanners/     # Pattern, AST, LLM implementations
│   ├── compliance/   # DPDP compliance analysis
│   └── models.py     # Pydantic models for all data structures
├── github/           # GitHub API integration (auth, client, check runs, SARIF)
├── reporters/        # Output formatters (table, SARIF, PR comment, etc.)
├── worker/           # Celery task processing
├── packs/            # YAML rule packs
└── config.py         # Settings (env vars)

cli/
└── main.py           # Typer CLI commands

tests/
├── conftest.py       # Shared pytest fixtures
├── fixtures/         # Test data (dirty/clean code)
└── test_*.py         # Unit tests
```

## Architecture Principles

1. **Separation of Concerns:**
   - Scanners: Pure scanning logic
   - Reporters: Output formatting only
   - GitHub module: API integration only
   - Engine: Orchestration + rule loading

2. **Async First:**
   - All I/O is async
   - GitHub API calls, database reads, file ops use `async/await`

3. **Type Safety:**
   - Pydantic models for all data
   - Type hints on function signatures
   - Validation at boundaries

4. **Error Handling:**
   - Custom exceptions (e.g., `RuleLoadError`)
   - Human-readable error messages
   - Include context (file path, line number, etc.)

## Testing

- **Framework:** pytest + pytest-asyncio
- **Fixtures:** Use `tests/conftest.py` for shared fixtures
- **Mocking:** Mock GitHub API, OpenAI API (use pytest-httpx)
- **Coverage:** Target 80%+ coverage
- **Fixtures data:** Python code in `tests/fixtures/python/`, JavaScript in `tests/fixtures/javascript/`

**Test naming:** `test_<function>_<scenario>` (e.g., `test_pattern_scanner_detects_secret`)

## Rule Packs

Rules are YAML files in `/anaya/packs/`:

```yaml
id: generic/rule-name
rules:
  - id: rule-1
    type: pattern|ast|llm
    pattern: '...'       # Pattern rules
    query: '...'         # AST rules
    system_prompt: '...' # LLM rules
```

**Rule types:**
- **Pattern:** Regex scanning, fast, good for secrets
- **AST:** tree-sitter queries, more accurate, good for code structure
- **LLM:** AI-powered, slow, good for complex logic

## Common Tasks

### Adding a New Scanner Type

1. Create `anaya/engine/scanners/my_scanner.py`
2. Subclass `BaseScanner` from `anaya/engine/scanners/base.py`
3. Implement `async def scan(...) -> list[Violation]`
4. Add tests in `tests/test_my_scanner.py`
5. Register in orchestrator

### Adding a Rule

1. Add to rule pack YAML in `anaya/packs/generic/`
2. Add test fixtures:
   - `tests/fixtures/python/dirty/` — Should flag
   - `tests/fixtures/python/clean/` — Should not flag
3. Test: `anaya test-rule ./anaya/packs/generic/<pack>.yml <rule-id> <file>`
4. Update [CHANGELOG.md](../CHANGELOG.md)

### Adding a CLI Command

1. Add function to `cli/main.py` with `@app.command()`
2. Use Typer for argument parsing
3. Use Rich for output formatting
4. Add tests in `tests/test_cli.py`

## External Dependencies

- **FastAPI:** Web framework
- **Celery + Redis:** Async task processing
- **SQLAlchemy + asyncpg:** PostgreSQL async ORM
- **Pydantic:** Data validation
- **tree-sitter:** AST parsing
- **Typer:** CLI framework
- **Rich:** Terminal output

**Be cautious adding new dependencies** — discuss in issues first.

## Environment Variables

See `anaya/config.py` and `.env.example`:
- `GITHUB_APP_ID`, `GITHUB_WEBHOOK_SECRET` — GitHub App
- `DATABASE_URL` — PostgreSQL
- `REDIS_URL` — Redis broker
- `OPENAI_API_KEY` — LLM (optional)
- `APP_ENV` — development/staging/production

## Common Mistakes to Avoid

❌ **Hardcoded file paths or secrets**
✅ Use environment variables

❌ **Synchronous code for I/O**
✅ Use `async/await`

❌ **No type hints**
✅ Type every function parameter and return

❌ **Mutable default arguments**
✅ Use `None` and initialize in function body

❌ **Ignoring GitHub rate limits**
✅ Use exponential backoff (already in client)

❌ **Regex with ReDoS vulnerability** (e.g., `(a+)+`)
✅ Test regex performance on regex101.com

## Testing Locally

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
docker compose up -d

# Test
pytest tests/ -v --cov=anaya --cov=cli

# Lint
ruff check --fix anaya/ cli/ tests/
ruff format anaya/ cli/ tests/

# Run locally
uvicorn anaya.api.app:create_app --factory --reload
```

## Performance Considerations

- **Pattern scanner:** O(n × p) — Linear with file size and patterns. Fast.
- **AST scanner:** O(n) — Linear with file size. Tree-sitter is highly optimized.
- **LLM scanner:** O(1) per batch — Constant time per API call (batches up to 50 violations).
- **Caching:** GitHub tokens cached, rule packs loaded at startup, DB connection pooling.

## Resources

- [ARCHITECTURE.md](../ARCHITECTURE.md) — Deep dive
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Contribution guide
- [docs/rule-authoring.md](../docs/rule-authoring.md) — How to write rules
- [GitHub Issues](https://github.com/anaya-scan/anaya/issues) — Roadmap, bugs

## Questions?

- Search [GitHub Issues](https://github.com/anaya-scan/anaya/issues)
- Ask in [GitHub Discussions](https://github.com/anaya-scan/anaya/discussions)
- Check [CONTRIBUTING.md](../CONTRIBUTING.md)

---

**Last updated:** Feb 2025
