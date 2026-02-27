# Configuration Reference

Complete reference for `anaya.yml` and environment variables.

## `anaya.yml` Schema

### Basic Structure

```yaml
version: "1"

# Rule packs to run
packs:
  - id: generic/secrets-detection
  - id: generic/owasp-top10

# Severity thresholds
thresholds:
  fail_on: CRITICAL      # Fail on this severity or higher
  warn_on: HIGH          # Warn on this severity or higher

# Paths to ignore
ignore:
  paths:
    - "tests/**"
    - "vendor/**"
    - "*.min.js"

# LLM-powered suggestions (optional)
enable_llm: false
```

### `packs`

List of rule packs to run.

**Format:** `id: org/pack-name`

**Built-in packs:**
- `generic/secrets-detection` — Hardcoded keys, tokens, passwords
- `generic/owasp-top10` — SQL injection, XSS, SSRF, etc.
- `generic/pii-handling` — Email, SSN, credit card exposure
- `generic/audit-logging` — Missing audit logs
- `generic/tls-encryption` — Insecure TLS, weak ciphers

**Custom packs:**
```yaml
packs:
  - id: myorg/security-baseline
```

### `thresholds`

Control which violations block or warn.

| Field | Options | Effect |
|---|---|---|
| `fail_on` | CRITICAL, HIGH, MEDIUM, LOW, INFO | PR fails if violation found at this severity or higher |
| `warn_on` | CRITICAL, HIGH, MEDIUM, LOW, INFO | Display warning but don't block if violation found |

**Examples:**

```yaml
# Strict: fail on anything critical
thresholds:
  fail_on: CRITICAL

# Moderate: fail on high/critical, warn on medium
thresholds:
  fail_on: HIGH
  warn_on: MEDIUM

# Relaxed: only fail on critical, warn on high
thresholds:
  fail_on: CRITICAL
  warn_on: HIGH
```

### `ignore.paths`

Glob patterns for paths to ignore.

**Examples:**

```yaml
ignore:
  paths:
    - "tests/**"           # Ignore all test files
    - "vendor/**"          # Ignore vendor directories
    - "*.min.js"           # Ignore minified JS
    - "docs/**"            # Ignore documentation
    - "*generated*"        # Ignore generated code
    - ".git/**"            # Ignore git metadata
    - "node_modules/**"    # Ignore npm packages
```

### `enable_llm`

Enable LLM-powered compliance analysis (experimental).

**Prerequisites:**
- `OPENAI_API_KEY` environment variable set
- OpenAI account with credits

**Examples:**

```yaml
# Disable LLM scanning
enable_llm: false

# Enable LLM scanning
enable_llm: true
```

---

## Environment Variables

All configuration via environment variables or `.env` file.

### GitHub App

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_APP_ID` | Yes (API/worker) | — | GitHub App ID from app settings |
| `GITHUB_PRIVATE_KEY_PATH` | No | `./private-key.pem` | Path to GitHub App private key `.pem` file |
| `GITHUB_PRIVATE_KEY_CONTENT` | No | — | Direct PEM content (alternative for cloud deployments) |
| `GITHUB_WEBHOOK_SECRET` | Yes (API/worker) | — | Webhook secret for signature verification |

**Example:** `.env`
```env
GITHUB_APP_ID=123456789
GITHUB_PRIVATE_KEY_PATH=./private-key.pem
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
```

**For cloud deployments** (Railway, Heroku, etc.) without file mounting:
```env
GITHUB_PRIVATE_KEY_CONTENT=-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2...
-----END RSA PRIVATE KEY-----
```

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | No | `postgresql+asyncpg://anaya:anaya@localhost:5432/anaya` | PostgreSQL connection string |

**Format:** `postgresql+asyncpg://USER:PASSWORD@HOST:PORT/DATABASE`

**Auto-conversion:** `postgresql://` is automatically converted to `postgresql+asyncpg://`

**Example:**
```env
DATABASE_URL=postgresql+asyncpg://anaya:mypassword@db.example.com:5432/anaya
```

### Redis

| Variable | Required | Default | Description |
|---|---|---|---|
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis connection string |

**Format:** `redis://[PASSWORD@]HOST:PORT/DATABASE`

**Example:**
```env
REDIS_URL=redis://redis.example.com:6379/0
```

### Application

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_ENV` | No | `development` | Environment: `development`, `staging`, `production` |
| `APP_PORT` | No | `8000` | API server port |
| `APP_SECRET_KEY` | No | `change-me-to-a-random-string` | Secret key for sessions (change in production!) |
| `PACKS_DIR` | No | `./anaya/packs` | Directory containing rule packs |

**Example:**
```env
APP_ENV=production
APP_PORT=8000
APP_SECRET_KEY=your-secure-random-key-here
PACKS_DIR=./anaya/packs
```

### LLM (OpenAI)

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | No (unless `enable_llm: true`) | — | OpenAI API key |
| `OPENAI_MODEL` | No | `gpt-4o-mini` | Model to use (gpt-4, gpt-4o, etc.) |
| `OPENAI_BASE_URL` | No | `https://api.openai.com/v1` | Custom OpenAI endpoint (for Azure, etc.) |

**Example:**
```env
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini
```

**For Azure OpenAI:**
```env
OPENAI_API_KEY=your-azure-key
OPENAI_BASE_URL=https://your-instance.openai.azure.com/
OPENAI_MODEL=gpt-4
```

### Logging

| Variable | Required | Default | Description |
|---|---|---|---|
| `LOG_LEVEL` | No | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL |

---

## Examples

### Development Setup

```env
APP_ENV=development
GITHUB_APP_ID=123456789
GITHUB_WEBHOOK_SECRET=dev-webhook-secret
GITHUB_PRIVATE_KEY_PATH=./private-key.pem
DATABASE_URL=postgresql+asyncpg://anaya:anaya@localhost:5432/anaya
REDIS_URL=redis://localhost:6379/0
```

### Production on Azure

```env
APP_ENV=production
APP_PORT=8000
APP_SECRET_KEY=your-secure-random-key-here
GITHUB_APP_ID=123456789
GITHUB_WEBHOOK_SECRET=prod-webhook-secret
GITHUB_PRIVATE_KEY_CONTENT=-----BEGIN RSA PRIVATE KEY-----\n...
DATABASE_URL=postgresql+asyncpg://anaya:super_strong_password@postgres.database.azure.com:5432/anaya
REDIS_URL=redis://:password@redis.cache.windows.net:6379/0
OPENAI_API_KEY=sk-proj-...
```

### CI/CD (GitHub Actions)

```env
APP_ENV=staging
GITHUB_APP_ID=${{ secrets.GITHUB_APP_ID }}
GITHUB_WEBHOOK_SECRET=${{ secrets.GITHUB_WEBHOOK_SECRET }}
GITHUB_PRIVATE_KEY_CONTENT=${{ secrets.GITHUB_PRIVATE_KEY }}
DATABASE_URL=${{ secrets.DATABASE_URL }}
REDIS_URL=${{ secrets.REDIS_URL }}
```

---

## CLI Flags (Override `anaya.yml`)

```bash
anaya scan [OPTIONS] PATH

Options:
  --pack, -p        Rule packs to use (can specify multiple times)
  --format, -f      Output format: table, json, sarif
  --fail-on         Minimum severity to fail: CRITICAL, HIGH, MEDIUM, LOW, INFO
  --warn-on         Minimum severity to warn
  --config, -c      Path to anaya.yml
  --baseline, -b    Path to baseline JSON for comparison
  --enable-llm      Enable LLM scanning
  --compliance      Run DPDP compliance analysis
```

**Example:**
```bash
anaya scan ./src \
  --pack generic/secrets-detection \
  --pack generic/owasp-top10 \
  --fail-on HIGH \
  --format json \
  > results.json
```

---

## Validation

Validate configuration:

```bash
# Validate anaya.yml
anaya init  # Creates a default file

# Validate rule pack
anaya validate-pack ./my-pack.yml

# Test rule
anaya test-rule ./my-pack.yml rule-id ./file.py
```

---

## Secrets Management

⚠️ **Never commit secrets to git!**

### Gitignore Secrets

```gitignore
.env
private-key.pem
*.pem
```

### GitHub Secrets (for CI/CD)

Store in **Repo Settings → Secrets and variables → Actions**:

```
GITHUB_APP_ID=123456789
GITHUB_WEBHOOK_SECRET=...
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...
```

Reference in workflows:
```yaml
env:
  GITHUB_APP_ID: ${{ secrets.GITHUB_APP_ID }}
```

### Cloud Provider Secrets

- **Azure:** Key Vault
- **AWS:** Secrets Manager
- **Google Cloud:** Secret Manager
- **Railway:** Environment variables
- **Heroku:** Config vars

---

## Next Steps

- **[Getting Started](getting-started.md)** — Quick start
- **[Rule Authoring](rule-authoring.md)** — Write custom rules
- **[CI/CD Integration](ci-cd-integration.md)** — Run in pipelines
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — Development setup
