# Architecture Guide — AnaYa

This document describes the internal architecture of AnaYa, how it works, and how to extend it.

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  GitHub (PR Push → Webhook)                                     │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │   FastAPI Webhook      │
        │   Signature Verify     │
        │   (HMAC-SHA256)        │
        └────────────┬───────────┘
                     │ enqueue
                     ▼
        ┌────────────────────────┐
        │   Celery Worker        │
        │   (Redis Broker)       │
        └────────────┬───────────┘
                     │
        ┌────────────▼───────────────────────────┐
        │   Scan Orchestrator (run_pr_scan)      │
        │   - Fetch repo config                  │
        │   - Load rule packs                    │
        │   - Get changed files                  │
        │   - Orchestrate scanners               │
        │   - Report results                     │
        │   - Record to database                 │
        └────┬──────────────────────────────────┘
             │
   ┌─────────┼─────────────────┐
   ▼         ▼                 ▼
 Scanner  Scanner           Reporter
 Pattern  AST              Check Run
          LLM              SARIF
                           PR Comment
```

## Module Breakdown

### 1. **anaya/api/** — Web Application

**Responsibility:** FastAPI server, webhook receiver, health checks

**Files:**
- `app.py` — Application factory (`create_app()`) with middleware setup
- `webhooks.py` — `POST /webhooks/github` endpoint, webhook parsing
- `middleware.py` — HMAC signature verification middleware
- `health.py` — `GET /health`, `GET /ready` endpoints

**Key Logic:**
```python
# Webhook flow
1. Receive POST /webhooks/github with X-Hub-Signature-256
2. Verify signature (constant-time comparison)
3. Parse payload with Pydantic models
4. Extract installation_id, repo, pr_number, head_sha
5. Enqueue Celery task: scan_pr.delay(...)
6. Return 202 Accepted
```

**External Dependencies:**
- FastAPI
- Pydantic (request validation)
- Celery (task enqueuing)

---

### 2. **anaya/engine/** — Core Scanning Logic

**Responsibility:** Rule loading, scanning orchestration, and result generation

#### **anaya/engine/models.py**

Defines 19+ Pydantic models for type safety:

| Model | Purpose |
|---|---|
| `Rule`, `PatternRule`, `ASTRule`, `LLMRule` | Rule definitions |
| `RulePack` | Collection of rules + metadata |
| `Violation` | Single violation found |
| `ScanResult` | Violation list + statistics |
| `AnaYaConfig` | Repository configuration (anaya.yml) |
| `SectionResult`, `ComplianceReport` | DPDP compliance analysis |

#### **anaya/engine/rule_loader.py**

Loads and validates rule packs from YAML files.

```python
# Load behavior:
load_pack(path: str) -> RulePack
  ├─ Read YAML file
  ├─ Validate schema (check required fields)
  ├─ Create Rule objects (parse pattern/AST/LLM configs)
  ├─ Apply defaults (language=all languages, severity=medium, etc.)
  └─ Return RulePack

load_pack_directory(dir: str) -> dict[str, RulePack]
  └─ Recursively find all .yml files → load_pack() each
```

**Error Handling:** Raises human-readable `RuleLoadError` with line numbers and suggestions.

#### **anaya/engine/orchestrator.py**

Main entry point for PR scans. Coordinates the entire flow.

```python
async def run_pr_scan(
    installation_id: int,
    repo: str,
    pr_number: int,
    head_sha: str,
) -> ScanResult:
    """Execute a full compliance scan on a pull request."""
    
    # 1. Create in-progress Check Run
    # 2. Fetch anaya.yml from repo
    # 3. Get list of changed files in PR
    # 4. Load rule packs (built-in + anaya.yml packs)
    # 5. For each changed file:
    #    a. Fetch content from GitHub
    #    b. Run Pattern Scanner
    #    c. Run AST Scanner (if applicable language)
    #    d. Run LLM Scanner (if enabled)
    # 6. Collect violations + generate summary
    # 7. Complete Check Run with annotations (batched)
    # 8. Post PR comment with violation details
    # 9. Upload SARIF to Code Scanning
    # 10. Record scan to database
    
    return ScanResult(...)
```

---

### 3. **anaya/engine/scanners/** — Scanning Implementations

**Base Class:** `BaseScanner` (ABC)

```python
class BaseScanner(ABC):
    @abstractmethod
    async def scan(
        self,
        content: str,
        rules: list[Rule],
        language: str,
    ) -> list[Violation]:
        """Scan file content and return violations."""
        pass
```

#### **pattern.py** — Regex Scanning

- Uses Python's `re` module with `re.search` per line
- **Features:**
  - Multiple regex patterns per rule
  - `# noqa` suppression (blanket or rule-specific)
  - `exclude_patterns` for false positive filtering
  - Language-aware filtering
  - Automatic redaction of sensitive content (e.g., `[REDACTED]` for API keys)

**Example:**
```python
rule = PatternRule(
    id="hardcoded-key",
    pattern="api_key\\s*=\\s*['\"]([\\w]+)['\"]",
    exclude_patterns=[".*test.*"],
)
scanner = PatternScanner()
violations = await scanner.scan(content, [rule], language="python")
```

#### **ast_scanner.py** — Tree-sitter Scanning

- Uses tree-sitter's `Query` + `QueryCursor` API (0.25+)
- S-expression queries for structural pattern matching
- **Features:**
  - Named captures: `@function_name`
  - Count ranges: `(call (identifier) @id)` with `min_count`, `max_count`
  - `name_regex` to filter captures by name
  - `must_not_contain` for absence detection

**Example — detect functions missing audit logs:**
```python
query = """
(function_definition
  name: (identifier) @func_name
  body: (block) @body)
"""
rule = ASTRule(
    id="missing-audit-log",
    query=query,
    name_regex="^(payment_|admin_)",  # Only these functions
    must_not_contain=["audit_log", "logger.info"],
)
```

#### **llm_enhancer.py** — LLM-Powered Analysis (Optional)

- Uses OpenAI API (configurable endpoint)
- Analyzes violations for context and suggestions
- **Features:**
  - Batches violations (reduces API calls)
  - Token counting (tiktoken) to avoid limit exceeds
  - Retry logic with exponential backoff
  - Fallback if LLM unavailable

---

### 4. **anaya/github/** — GitHub Integration

Async HTTP client wrapping GitHub's REST and GraphQL APIs.

#### **auth.py** — JWT & Installation Tokens

```python
# Generate JWT for GitHub App
jwt_token = generate_jwt(app_id, private_key)

# Exchange JWT for installation access token (cached)
installation_token = await get_installation_token(
    client, jwt_token, installation_id
)
```

**Caching:** Tokens cached until 1 minute before expiration.

#### **client.py** — HTTP Client

- Async httpx client with SSL verification
- Retry logic (exponential backoff on 429, 5xx)
- Rate limit handling (checks `x-ratelimit-*` headers)
- Request timeout (per `APP_TIMEOUT` config)

#### **check_runs.py** — Check Run API

```python
# Create in-progress check run
await client.create_check_run(
    installation_token, repo, head_sha,
    name="AnaYa Compliance Scan",
    status="in_progress",
)

# Add annotations (batched, max 50 per call)
await client.add_check_run_annotations(
    installation_token, repo, check_run_id,
    annotations=[
        {
            "path": "src/app.py",
            "start_line": 42,
            "end_line": 42,
            "annotation_level": "failure",
            "message": "Hardcoded API key detected",
        },
        # ... up to 50 more
    ]
)
```

#### **sarif.py** — SARIF Upload

- Converts violations to SARIF 2.1.0 format
- Gzip compression + base64 encoding
- Uploads to GitHub Code Scanning via REST API

#### **models.py** — Webhook Payloads

Pydantic models for GitHub webhook events:
- `PullRequestEvent`
- `PullRequestAction` (opened, synchronize, reopened)
- `Repository`, `PullRequest`, `Sender` (nested models)

---

### 5. **anaya/reporters/** — Output Formatters

Each reporter converts `ScanResult` to a specific format.

#### **table.py** — CLI Output

Uses **Rich** library for formatted terminal tables.

```python
render_violations_table(violations) → Rich Table
render_summary(scan_result) → Summary text
```

#### **check_run.py** — GitHub Check Run Payload

Formats violations as `CheckRunAnnotation` (inline code annotations).

#### **sarif_builder.py** — SARIF Output

Builds SARIF 2.1.0-compliant JSON with:
- Tool information
- Results (one per violation)
- Locations, ruleIds, messages, severity levels

#### **pr_review.py** — PR Comment

Generates Markdown for PR comments:
- Collapsible summary (if <10 violations)
- Severity breakdown
- Link to docs
- Time taken

#### **compliance_comment.py** — Compliance Report

Formats DPDP compliance analysis as Markdown.

---

### 6. **anaya/compliance/** — Compliance Analysis

For DPDP (India's Data Protection Act) compliance scanning.

#### **indexer.py** — Deterministic Code Analysis

- Uses AST (tree-sitter) for structural analysis
- Grep for string patterns
- **Zero external API calls**

Maps codebase to:
- Data stores (databases, files, APIs)
- Function signatures
- Error handling
- Encryption usage

#### **pii_mapper.py** — Classify Personal Data

Takes `CodebaseMap` and produces `PersonalDataMap`:
- Identifies which models/fields contain personal data
- Classifies by sensitivity (emails, SSNs, etc.)
- Links to storage locations

#### **analyzers/ directory** — Section Evaluators

- `/analyzers/base.py` — `BaseSectionAnalyzer` ABC
- `/analyzers/runner.py` — `DPDPComplianceRunner` orchestrator
- Individual analyzers per DPDP section

Each analyzer:
1. Reads section requirements (e.g., "data must be encrypted")
2. Evaluates codebase against requirements
3. Returns `SectionResult` (pass/fail + evidence)

---

### 7. **anaya/worker/** — Async Task Processing

#### **celery_app.py**

Celery configuration:
- Redis broker
- Task routing
- Retry policies

#### **tasks.py**

```python
@shared_task
async def scan_pr(
    installation_id: int,
    repo: str,
    pr_number: int,
    head_sha: str,
) -> dict:
    """Task enqueued by webhook, executed by worker."""
    result = await run_pr_scan(...)
    # Save to database
    # Update Check Run with results
    return result.model_dump()
```

**Retry Logic:**
- Max 3 retries
- Exponential backoff (2, 4, 8 seconds)
- Failures logged + Check Run marked failed

---

### 8. **cli/main.py** — Command Line Interface

Using **Typer** framework for clean CLI structure.

**Commands:**

| Command | Purpose |
|---|---|
| `scan` | Scan directory/file against packs |
| `compliance` | Run DPDP analysis on codebase |
| `init` | Create default anaya.yml |
| `packs list` | List available packs |
| `validate-pack` | Validate pack YAML schema |
| `test-rule` | Test single rule against file |
| `test-pack` | Test pack against fixtures (dirty/clean) |

Each command:
1. Validates inputs
2. Loads configuration
3. Calls engine logic
4. Formats output with Rich
5. Sets appropriate exit codes

---

### 9. **Database Schema** (anaya/db.py)

Uses SQLAlchemy async with PostgreSQL.

**Tables:**
- `scan_runs` — Historical record of each scan
- `violations` — Violations found per scan
- `scan_summaries` — Aggregated statistics

**Used for:**
- Baseline comparison (only report new violations)
- Trend analysis
- Audit logging

---

## Data Flow Examples

### Example 1: PR Webhook → Scan Result

```
1. GitHub pushes commit to PR
   ↓
2. GitHub sends webhook POST /webhooks/github
   ↓
3. Middleware verifies HMAC-SHA256 signature
   ↓
4. Endpoint parses PullRequestEvent
   ↓
5. Enqueues Celery task: scan_pr(installation_id=123, repo="owner/repo", pr_number=42, head_sha="abc123")
   ↓
6. Worker receives task
   ↓
7. run_pr_scan() orchestrates:
   a. Create in-progress Check Run
   b. Fetch anaya.yml from repo
   c. Get list of changed files (src/app.py, src/utils.py)
   d. Load packs (generic/secrets-detection, generic/owasp-top10)
   e. For each file:
      - Fetch content
      - Run PatternScanner (regex patterns)
      - Run ASTScanner (tree-sitter queries)
      - Collect violations
   f. Generate ScanResult with 3 violations
   ↓
8. Reporters convert ScanResult:
   - CheckRunReporter → 3 annotations
   - SARIFBuilder → SARIF JSON
   - PRCommentBuilder → Markdown
   ↓
9. GitHub client:
   - Complete Check Run with annotations
   - Upload SARIF
   - Post PR comment
   ↓
10. Database records scan_run + violations
```

### Example 2: Local CLI Scan

```
$ anaya scan ./src --pack generic/secrets-detection

1. CLI parses arguments
   ↓
2. load_pack("anaya/packs/generic/secrets-detection.yml")
   ↓
3. Collect Python files in ./src (recursively)
   ↓
4. For each file:
   a. Read content
   b. PatternScanner.scan(content, rules, "python")
      - Run each rule's regex pattern
      - Check for noqa suppression
      - Collect violations
   c. ASTScanner.scan(content, rules, "python")
      - Parse with tree-sitter
      - Run S-expression queries
      - Collect violations
   ↓
5. Merge + deduplicate violations
   ↓
6. Table renderer creates Rich table
   ↓
7. Print to stdout
   ↓
8. Exit code based on severity (0 if no critical, 1 if critical)
```

---

## Extension Points

### Adding a New Scanner Type

1. Create `anaya/engine/scanners/my_scanner.py`
2. Subclass `BaseScanner`
3. Implement `async def scan(...) -> list[Violation]`
4. Add rule type class to `anaya/engine/models.py`
5. Add tests in `tests/test_my_scanner.py`
6. Register in orchestrator

### Adding a New Reporter

1. Create `anaya/reporters/my_reporter.py`
2. Create report function or class
3. Call from orchestrator after scan
4. Can output to file, API, webhook, etc.

### Adding a New Rule Pack

1. Create YAML file in `anaya/packs/generic/` or `anaya/packs/myorg/`
2. Define rules following schema (see [CONTRIBUTING.md](CONTRIBUTING.md#rule-packs))
3. Test with `anaya test-pack`
4. Add to default anaya.yml
5. Document in README

### Adding a New CLI Command

1. Add function to `cli/main.py` with `@app.command()`
2. Use Typer decorators for arguments/options
3. Use Rich for output
4. Add tests

---

## Configuration

All configuration via environment variables or `.env` file (see [.env.example](.env.example)).

**Key settings:**
- `GITHUB_*` — GitHub App credentials
- `DATABASE_URL` — PostgreSQL connection
- `REDIS_URL` — Redis broker
- `APP_ENV` — development/staging/production
- `PACKS_DIR` — Path to rule packs directory
- `OPENAI_API_KEY` — (Optional) for LLM scanner

See [anaya/config.py](anaya/config.py) for all options.

---

## Performance Considerations

### Scanning

- **Pattern scanner:** O(n × p) where n = file size, p = number of patterns. Very fast (~10 ms per pattern per file).
- **AST scanner:** O(n) with tree-sitter (highly optimized). Typically faster than pattern scanning.
- **LLM scanner:** O(1) per batch of violations (1 API call per 50 violations). Slowest, but optional.

### Caching

- **GitHub installation tokens:** Cached until 1 min before expiration (reduces JWT generation)
- **Rule packs:** Loaded at startup, cached in memory
- **Database connections:** Connection pooling (SQLAlchemy + asyncpg)

### Concurrency

- **Async/await:** All I/O is non-blocking (GitHub API, database, file reading)
- **Multiple scanners:** Pattern + AST run concurrently per file
- **Worker scaling:** Horizontal scaling via additional Celery workers

---

## Testing

See [CONTRIBUTING.md](CONTRIBUTING.md#testing) for test structure.

**Key test files:**
- `tests/test_pattern_scanner.py` — Pattern matching, noqa, redaction
- `tests/test_ast_scanner.py` — Tree-sitter queries, filters
- `tests/test_rule_loader.py` — YAML validation, error handling
- `tests/test_github_orchestrator.py` — End-to-end scans
- `tests/test_api.py` — Webhook endpoint, HMAC verification

**Fixtures:**
- `tests/fixtures/python/dirty/` — Code that SHOULD trigger violations
- `tests/fixtures/python/clean/` — Code that SHOULD NOT trigger violations
- Same structure for JavaScript

---

## Troubleshooting

### Scan is slow

- Check API rate limits (GitHub → Settings → Developer settings → Monitor)
- Verify database connection is fast: `psql $DATABASE_URL -c "SELECT 1;"`
- Ensure Redis is running (Celery queuing bottleneck)

### Violations not showing up

- Verify rule is in enabled pack
- Check severity threshold (fail_on, warn_on)
- Test rule in isolation: `anaya test-rule <pack-path> <rule-id> <file-path>`

### GitHub App not receiving webhooks

- Verify webhook URL is publicly accessible (`curl https://your-domain/webhooks/github`)
- Check GitHub App settings → Recent Deliveries
- Verify webhook secret matches `GITHUB_WEBHOOK_SECRET`

### LLM scanning errors

- Verify `OPENAI_API_KEY` is set and valid
- Check OpenAI account has credits
- Monitor token usage (`tiktoken` counting)

---

## Contributing to Architecture

Updates to architecture should:
1. Match the existing patterns (Scanner ABC, Reporter interface, etc.)
2. Use async/await for I/O
3. Validate inputs with Pydantic
4. Include comprehensive tests
5. Update [ARCHITECTURE.md](ARCHITECTURE.md) if you add/change major modules

Questions? Open a GitHub Discussion or check [CONTRIBUTING.md](CONTRIBUTING.md).
