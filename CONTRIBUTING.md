# Contributing to AnaYa

Thank you for your interest in contributing to AnaYa! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.12+
- Docker & Docker Compose (for local testing with PostgreSQL + Redis)
- Git

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/anaya-scan/anaya.git
cd anaya

# Create virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# Install package in development mode
pip install -e ".[dev]"

# Start infrastructure (PostgreSQL, Redis)
docker compose up -d postgres redis

# Configure environment
cp .env.example .env
# Edit .env with your GitHub App credentials (if testing webhooks)

# Run tests
pytest tests/ -v

# Run with auto-reload (development)
uvicorn anaya.api.app:create_app --factory --reload
```

## Code Style & Quality

### Linting & Formatting

We use **Ruff** for linting and formatting.

```bash
# Check style
ruff check anaya/ cli/ tests/

# Format code
ruff format anaya/ cli/ tests/

# Fix auto-fixable issues
ruff check --fix anaya/
```

**Key rules:**
- Line length: 120 characters
- Target Python: 3.12+
- Select: E, F, W, I, N, UP, B, SIM

### Type Hints

All public functions and classes must have type hints:

```python
def scan_file(file_path: str, rules: list[Rule]) -> ScanResult:
    """Scan a file against rules and return violations."""
    pass

class BaseScanner(ABC):
    """Abstract base for all scanners."""
    
    async def scan(self, content: str, language: str) -> list[Violation]:
        pass
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_pattern_scanner.py -v

# Run with coverage report
pytest tests/ --cov=anaya --cov=cli --cov-report=html
```

### Writing Tests

- Use **pytest** + **pytest-asyncio** for async code
- Place fixtures in [tests/conftest.py](tests/conftest.py)
- Use [tests/fixtures/](tests/fixtures/) for test data (e.g., "dirty" code that should fail, "clean" code that should pass)
- Mock external APIs (GitHub, OpenAI) using **pytest-httpx** or similar
- Target **80%+ coverage** on new code

**Example test:**

```python
@pytest.mark.asyncio
async def test_pattern_scanner_detects_hardcoded_secret():
    """Pattern scanner should detect hardcoded API key."""
    scanner = PatternScanner()
    rule = PatternRule(
        id="test",
        name="Test Rule",
        pattern=r"api_key\s*=\s*['\"][\w]+['\"]",
        severity=Severity.CRITICAL,
        languages=["python"],
    )
    
    result = await scanner.scan(
        content='api_key = "sk-1234567890"',
        rules=[rule],
        language="python",
    )
    
    assert len(result) == 1
    assert result[0].rule_id == "test"
```

## Rule Pack Development

### Creating a Custom Rule Pack

Rule packs are YAML files located in [anaya/packs/](anaya/packs/). Each pack defines a collection of rules.

**Pack structure:**

```yaml
id: myorg/security-baseline
name: Organization Security Baseline
version: "1.0.0"
description: Custom security rules for internal use

rules:
  - id: no-hardcoded-api-key
    name: Hardcoded API Key
    type: pattern
    severity: critical
    languages: [python, javascript]
    pattern: 'api_key\s*=\s*["\']([a-zA-Z0-9_]+)["\"']'
    exclude_patterns:
      - '.*test.*'  # Skip test files
    message: "API keys must not be hardcoded — use environment variables"
    fix_hint: "Move the key to .env or a secrets manager"
    references:
      - https://cwe.mitre.org/data/definitions/798.html
```

### Rule Types

#### Pattern Rules (Regex)

- **Best for:** Secrets detection, simple patterns, hardcoded values
- **Supports:** Noqa suppression (`# noqa: rule-id`), exclusion patterns, redaction

```yaml
type: pattern
pattern: 'hardcoded_password\s*=\s*["\'](.+?)["\']'
exclude_patterns:
  - '.*test.*'
  - '.*fixture.*'
message: "Passwords must not be hardcoded"
```

#### AST Rules (Tree-sitter)

- **Best for:** Function calls, structural patterns, absence detection
- **Supports:** Named captures, name filtering, must_not_contain absence checks

```yaml
type: ast
languages: [python, javascript]
query: |
  (function_definition
    name: (identifier) @func_name
    body: (block) @body)
name_regex: "^(process_|handle_).*"  # Only functions matching this
must_not_contain:  # Flag if these patterns are NOT found
  - "audit_log"
  - "logger.info"
message: "Sensitive functions must include audit logging"
```

#### Compliance Rules (LLM, Optional)

- **Best for:** Complex logic, semantic analysis, DPDP compliance
- Requires `OPENAI_API_KEY` to be set and `enable_llm: true` in config

### Testing Your Rule Pack

```bash
# Validate pack YAML
anaya validate-pack ./anaya/packs/generic/secrets-detection.yml

# Test single rule
anaya test-rule ./anaya/packs/generic/secrets-detection.yml no-hardcoded-api-key ./test.py

# Test entire pack against fixtures
# Place dirty files (should trigger) in tests/fixtures/python/dirty/
# Place clean files (should not trigger) in tests/fixtures/python/clean/
anaya test-pack ./anaya/packs/generic/secrets-detection.yml ./tests/fixtures/python
```

## Pull Request Process

1. **Fork the repository** and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure tests pass:
   ```bash
   pytest tests/ --cov=anaya --cov=cli
   ```

3. **Format and lint** your code:
   ```bash
   ruff format anaya/ cli/ tests/
   ruff check --fix anaya/
   ```

4. **Write a clear commit message:**
   ```
   [FEATURE] Add LLM rule validation

   - Implement semantic validation for LLM rules
   - Add prompt length checks
   - Include tests for edge cases

   Closes #123
   ```

5. **Push to your fork** and create a pull request with:
   - Clear title and description
   - Link to related issues (if any)
   - Test coverage report
   - Changelog entry in [CHANGELOG.md](CHANGELOG.md)

6. **Code Review:** Maintainers will review your PR. Be responsive to feedback.

## Architecture Overview

For a deep dive into the codebase, see [ARCHITECTURE.md](ARCHITECTURE.md).

**Key modules:**

- **[anaya/engine/](anaya/engine/)** — Core scanning logic (rule loader, scanners, orchestrator)
- **[anaya/github/](anaya/github/)** — GitHub API integration (webhook, auth, check runs)
- **[anaya/reporters/](anaya/reporters/)** — Output formatters (Check Run, SARIF, PR comment, table)
- **[anaya/api/](anaya/api/)** — FastAPI web server
- **[anaya/worker/](anaya/worker/)** — Celery async task processing
- **[cli/main.py](cli/main.py)** — Typer CLI commands

## Common Task Workflows

### Adding a New Scanner Type

1. Create a new subclass of [BaseScanner](anaya/engine/scanners/base.py)
2. Implement `async def scan(...) -> list[Violation]`
3. Add tests in `tests/test_<scanner_name>.py`
4. Document in [ARCHITECTURE.md](ARCHITECTURE.md)

### Adding a New Rule Pack

1. Create a `.yml` file in [anaya/packs/generic/](anaya/packs/generic/) or your org folder
2. Define rules following the YAML schema (see above)
3. Add test fixtures in [tests/fixtures/python/](tests/fixtures/python/)
4. Test with `anaya test-pack`

### Adding a New CLI Command

1. Add function to [cli/main.py](cli/main.py) with `@app.command()` or `@packs_app.command()`
2. Use **Typer** for argument parsing
3. Use **Rich** for output formatting
4. Add tests in [tests/test_cli.py](tests/test_cli.py)

## Documentation

- **README.md** — User-facing overview, quick start
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design and internals
- **[docs/](docs/)** — Detailed guides (rule authoring, CI/CD integration, etc.)
- **Code comments** — Explain "why", not "what" (the code shows what)

## Reporting Issues

### Bug Reports

Use the [Bug Report](https://github.com/anaya-scan/anaya/issues/new?template=bug_report.md) template:

- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Python version, OS, environment

### Feature Requests

Use the [Feature Request](https://github.com/anaya-scan/anaya/issues/new?template=feature_request.md) template:

- Describe the feature and motivation
- Example usage
- Potential implementation approach

### Security Issues

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive community.

## Questions?

- Open a [Discussion](https://github.com/anaya-scan/anaya/discussions) for questions
- Check our [FAQ](docs/faq.md)
- Review existing [Issues](https://github.com/anaya-scan/anaya/issues)

Thank you for contributing!
