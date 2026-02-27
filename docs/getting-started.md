# Getting Started with AnaYa

AnaYa is a **compliance-as-code engine** that scans your GitHub pull requests against policy rule packs and reports violations in real-time.

## 5-Minute Quick Start

### What You'll Need

- A GitHub account with repository access
- Basic command line familiarity
- 5 minutes

### Step 1: Create a GitHub App

Go to **GitHub → Settings → Developer Settings → GitHub Apps → New GitHub App**

**Configuration:**
| Setting | Value |
|---|---|
| Name | `AnaYa` (or your preferred name) |
| Homepage URL | `https://github.com/anaya-scan/anaya` (or your instance URL) |
| Webhook URL | `https://your-domain.com/webhooks/github` |
| Webhook Secret | `openssl rand -hex 32` |

**Permissions:**
- Checks: Read & Write
- Contents: Read-only
- Pull Requests: Read & Write
- Code Scanning: Read & Write

**Subscribe to:**
- Pull request events
- Installation events

**After creating:**
1. Copy the **App ID**
2. Generate a **private key** (download `.pem` file)
3. Note your **webhook secret**

### Step 2: Install AnaYa in a Repository

1. Go to your App's installation page
2. Select your organization/account
3. Select the repository you want to scan
4. Click **Install**

### Step 3: Add `anaya.yml` to Your Repo

Create `anaya.yml` in your repository root:

```yaml
version: "1"

# Rule packs to run
packs:
  - id: generic/secrets-detection
  - id: generic/owasp-top10

# Severity thresholds
thresholds:
  fail_on: CRITICAL     # Block merge on critical findings
  warn_on: HIGH         # Warn (don't block) on high findings

# Ignore patterns
ignore:
  paths:
    - "tests/**"
    - "vendor/**"
    - "*.min.js"
```

Commit and push:
```bash
git add anaya.yml
git commit -m "Add AnaYa compliance configuration"
git push
```

### Step 4: Create Your First PR

Make any code change and open a pull request:

```bash
git checkout -b my-test
echo "# Hello" >> README.md
git add README.md
git commit -m "Test PR"
git push -u origin my-test
```

Go to GitHub and open a PR. **Within 30 seconds, AnaYa will scan the PR** and post a Check Run with results.

### Step 5: View Results

- **Check Runs** — See inline annotations on files
- **PR Comment** — Detailed violation breakdown
- **Code Scanning** — SARIF results in Security tab

---

## Understanding the Output

### Check Run (Inline Annotations)

Lines with violations are marked with red X. Hover to see the rule name and fix suggestion.

### PR Comment

Example:
```
🔍 AnaYa Compliance Scan

Found 2 violations:

🔴 CRITICAL (1)
- Hardcoded AWS Key in src/config.py:15
  → Move the key to environment variables

🟠 HIGH (1)
- Potential SQL Injection in src/db.py:42
  → Use parameterized queries
```

### Code Scanning (SARIF)

View results in **Security → Code Scanning Alerts**.

---

## Configuring Rules

### Default Rule Packs

AnaYa includes these built-in packs:

| Pack | Rules | Purpose |
|---|---|---|
| `generic/secrets-detection` | 12 | Hardcoded keys, tokens, passwords, private keys |
| `generic/owasp-top10` | 10 | SQL injection, XSS, SSRF, command injection |
| `generic/pii-handling` | 8 | Email, SSN, credit card exposure |
| `generic/audit-logging` | 7 | Missing audit logs in sensitive functions |
| `generic/tls-encryption` | 7 | Insecure TLS, weak ciphers |

### Customizing `anaya.yml`

**Enable specific packs:**
```yaml
packs:
  - id: generic/secrets-detection
  - id: generic/owasp-top10
  # Don't include pii-handling or audit-logging
```

**Adjust severity thresholds:**
```yaml
thresholds:
  fail_on: HIGH      # Fail on HIGH or CRITICAL (stricter)
  warn_on: MEDIUM    # Warn also on MEDIUM
```

**Ignore specific paths:**
```yaml
ignore:
  paths:
    - "tests/**"
    - "docs/**"
    - "vendor/**"
    - "*.min.js"
    - "*generated*"
```

**Enable LLM suggestions (experimental):**
```yaml
enable_llm: true   # Requires OPENAI_API_KEY environment variable
```

---

## Troubleshooting

### Check Run Not Appearing

1. **Verify webhook is enabled** — GitHub App settings → Recent Deliveries
2. **Check permissions** — App needs Checks: Read & Write permission
3. **Confirm webhook secret** — Must match `GITHUB_WEBHOOK_SECRET` environment variable
4. **Test connectivity** — `curl https://your-domain.com/webhooks/github` should return 400 (POST only)

### False Positives (Rule triggers but shouldn't)

1. **Add exclude patterns** to the rule in your custom pack
2. **Use `# noqa` comments** to suppress specific violations:
   ```python
   password = "test-password"  # noqa: hardcoded-password
   ```

### Custom Rules Not Working

1. Validate your rule pack: `anaya validate-pack ./my-pack.yml`
2. Test the rule locally: `anaya test-rule ./my-pack.yml my-rule-id ./test.py`
3. Check rule syntax in [Rule Authoring Guide](rule-authoring.md)

### LLM Scanner Errors

1. **Set `OPENAI_API_KEY`** in environment
2. **Use `enable_llm: true`** in `anaya.yml`
3. **Check OpenAI account credits** (billing)
4. **Monitor token usage** (large repos may exceed limits)

### Scanning is Very Slow

1. **Reduce pack count** — Only enable needed packs
2. **Ignore large directories** — Add to `ignore.paths` in anaya.yml
3. **Check GitHub API rate limits** — Dashboard → API rate limits usage

---

## Local Testing

### Test Without GitHub (CLI Mode)

Scan your local code using the CLI:

```bash
# Scan the current directory
anaya scan .

# Scan specific directory with specific pack
anaya scan ./src --pack generic/secrets-detection

# See all available packs
anaya packs list

# Validate your anaya.yml
anaya init   # Creates a default anaya.yml
```

### Create Custom Test Fixtures

Test your custom rules:

```bash
# Test a single rule
anaya test-rule ./my-pack.yml my-rule-id ./test-file.py

# Test entire pack
anaya test-pack ./my-pack.yml ./tests/fixtures/python/
```

Create fixture files:
- `tests/fixtures/python/dirty/` — Code that SHOULD trigger violations
- `tests/fixtures/python/clean/` — Code that should NOT trigger violations

---

## Local Deployment (Docker Compose)

To run AnaYa locally for testing:

```bash
# Clone and setup
git clone https://github.com/anaya-scan/anaya.git
cd anaya
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start services (PostgreSQL + Redis)
docker compose up -d

# Configure
cp .env.example .env
# Edit .env with GitHub App credentials

# Run API
uvicorn anaya.api.app:create_app --factory --reload

# In another terminal, run worker
celery -A anaya.worker.celery_app worker --loglevel=info
```

Then use **ngrok** or **localtunnel** to expose to the internet for webhook testing:

```bash
ngrok http 8000
# Or: npx localtunnel --port 8000
```

Update your GitHub App settings with the ngrok/localtunnel URL.

---

## Next Steps

- **[Rule Authoring](rule-authoring.md)** — Write custom rule packs
- **[CI/CD Integration](ci-cd-integration.md)** — Run AnaYa in GitHub Actions, GitLab CI, etc.
- **[Configuration Reference](configuration.md)** — All `anaya.yml` options
- **[Deployment Guide](../docs/azure-hosting.md)** — Production deployment
- **[ARCHITECTURE](../ARCHITECTURE.md)** — Deep dive into internals

---

## Support

- **Bugs/Features** — [GitHub Issues](https://github.com/anaya-scan/anaya/issues)
- **Questions** — [GitHub Discussions](https://github.com/anaya-scan/anaya/discussions)
- **Security Issues** — [security@anaya-scan.dev](mailto:security@anaya-scan.dev)

Happy scanning! 🚀
