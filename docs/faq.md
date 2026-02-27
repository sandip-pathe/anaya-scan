# FAQs

## General

### What is AnaYa?

AnaYa is a **compliance-as-code engine** that automatically scans your GitHub pull requests against policy rule packs. It detects violations in real-time and reports them via Check Runs, SARIF, and PR comments.

Think of it as a specialized linter for security and compliance policies, with built-in support for:
- Hardcoded secrets detection
- OWASP Top 10 vulnerabilities
- PII exposure
- Audit logging requirements
- TLS/encryption best practices

### How is AnaYa different from Semgrep, SonarQube, etc.?

| Feature | AnaYa | Semgrep | SonarQube |
|---|---|---|---|
| **Type** | Policy-as-code | SAST | Code quality + security |
| **Rules** | Custom YAML packs | SemGrep rules | Covers 40+ languages |
| **Deployment** | GitHub App or self-hosted | CI/CD focused | Enterprise platform |
| **LLM** | Built-in (OpenAI) | No | Via plugins |
| **Compliance** | DPDP (India) focus | Generic | Generic |
| **Cost** | Open-core | Open-source | Enterprise pricing |
| **Speed** | Ultra-fast (<100ms) | Fast (seconds) | Slow (minutes) |

**AnaYa is best for:**
- Organizations in India needing DPDP compliance
- Custom security policies (not industry standards)
- Real-time PR feedback
- Low operational overhead (webhook-based)

### Is AnaYa open source?

**Yes!** AnaYa is **open-core** under **AGPL-3.0**:
- ✅ Source code is public
- ✅ You can self-host for free
- ✅ Commercial use allowed (AGPL terms)
- ⚠️ Must contribute changes back to community

### How much does AnaYa cost?

**Free for:**
- Individual developers
- Open-source projects
- Evaluation/testing

**Commercial support (optional):**
- Hosted instance (SaaS)
- Premium support
- Custom features

---

## Getting Started

### Can I use AnaYa without a GitHub App?

**Yes,** in two ways:

1. **CLI mode** (local scanning):
   ```bash
   anaya scan ./src --pack generic/secrets-detection
   ```
   No GitHub App needed.

2. **CI/CD mode** (GitHub Actions, GitLab CI, etc.):
   ```yaml
   - run: anaya scan . --fail-on CRITICAL
   ```
   No GitHub App needed, but requires CI/CD setup.

**But for real-time GitHub PR feedback**, you need the GitHub App.

### What are the system requirements?

**Minimum:**
- Python 3.12+
- Docker (optional, for PostgreSQL + Redis)
- 1 GB RAM
- 100 MB disk

**Recommended (production):**
- Python 3.12 or 3.13
- PostgreSQL 16+
- Redis 7+
- 4 GB RAM
- 10 GB disk
- 2 CPU cores

### How do I deploy AnaYa?

**Options:**

1. **Docker Compose** (local dev):
   ```bash
   docker compose up -d
   ```

2. **Azure VM** (~$15/month):
   See [Azure Hosting Guide](../docs/azure-hosting.md)

3. **AWS** (EC2, ECS, Lambda):
   Similar to Azure setup

4. **Fly.io, Railway, Render** (PaaS):
   Simplest deployment, $5–10/month

5. **Kubernetes** (enterprise):
   Helm chart (coming soon)

---

## Rules & Configuration

### How do I write custom rules?

See [Rule Authoring Guide](rule-authoring.md).

**Quick example — detect hardcoded passwords:**

```yaml
id: no-hardcoded-password
name: Hardcoded Password
type: pattern
severity: critical
languages: [python, javascript]
pattern: 'password\s*=\s*["\'](.+?)["\']'
message: "Passwords must not be hardcoded"
fix_hint: "Use environment variables or a secrets manager"
```

### Can I disable specific rules?

**Option 1:** Remove pack from `anaya.yml`
```yaml
packs:
  - id: generic/secrets-detection
  # Don't include other packs
```

**Option 2:** Suppress on a line with `# noqa`
```python
password = "test"  # noqa: hardcoded-password
```

**Option 3:** Add to exclude patterns
```yaml
exclude_patterns:
  - ".*test.*"
```

### How do I create a baseline?

Generate baseline once (main branch is clean):

```bash
git checkout main
anaya scan . > baseline.json
git add baseline.json
git commit -m "Set compliance baseline"
```

Then on PRs, only report *new* violations:

```bash
anaya scan . --baseline ./baseline.json
```

### How accurate are the rules?

| Rule Type | Accuracy | False Positive Rate |
|---|---|---|
| Pattern (regex) | ~95% | ~5% (tune with exclude patterns) |
| AST (tree-sitter) | ~98% | ~2% (rare) |
| LLM (AI) | ~85% | ~15% (tune confidence threshold) |

**Tips to reduce false positives:**
1. Add `exclude_patterns` for known safe paths
2. Use `# noqa` comments
3. Use AST rules instead of regex (more accurate)
4. Increase LLM confidence threshold

---

## Performance & Scale

### Is AnaYa fast?

**Yes!** Typical scan times:

| Codebase Size | Time | Speed |
|---|---|---|
| Small (< 1K files) | 100–500ms | ⚡⚡⚡ |
| Medium (1K–10K files) | 1–5s | ⚡⚡ |
| Large (10K+ files) | 5–30s | ⚡ |

LLM scanning adds 2–5s per violation batch.

### Can AnaYa scale to large repos?

**Yes.**

**Optimization tips:**
1. Only enable needed rule packs
2. Add large directories to `ignore.paths` (node_modules, vendor, etc.)
3. Use baseline comparison (only scan diffs)
4. Deploy multiple Celery workers for parallel processing

### How much does AnaYa cost to run?

**Infrastructure costs (rough estimates):**
- **Small team (< 50 devs):** ~$15–25/month (AWS/Azure VM)
- **Medium team (50–500 devs):** ~$50–100/month (dedicated VM + managed services)
- **Enterprise:** Custom pricing (contact us)

**OpenAI API costs (if LLM enabled):**
- ~$0.0001 per scan (for typical repos)
- ~$3–10/month per team

---

## Security

### Is my code safe with AnaYa?

**Yes.**

- ✅ AnaYa doesn't store your code (scans in-memory)
- ✅ You control the deployment (self-hosted or GitHub App)
- ✅ All data encrypted in transit (TLS)
- ✅ Database is yours (you control PostgreSQL instance)
- ✅ LLM calls can be disabled (`enable_llm: false`)

### Does AnaYa send data to external services?

**By default:** No. AnaYa is self-contained.

**Optional:**
- **GitHub:** Webhook communication (you control this)
- **OpenAI:** If `enable_llm: true` is set (you can disable it)
- **Telemetry:** None. Zero telemetry collection.

### How do I report security vulnerabilities?

Email: **security@anaya-scan.dev**

See [SECURITY.md](../SECURITY.md) for responsible disclosure policy.

---

## Development & Contribution

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md).

**Quick steps:**
1. Fork repo
2. Create feature branch
3. Test thoroughly (`pytest`)
4. Submit PR with clear description
5. Maintainers review & merge

### Can I use AnaYa's code in my project?

**Under AGPL-3.0 license:**
- ✅ Yes, you can use and modify
- ✅ Yes, you can redistribute
- ⚠️ You must release source code (AGPL "copyleft")
- ⚠️ Any changes must be contributed back (recommended)

**For proprietary projects:** Contact us for commercial license.

### How do I run tests?

```bash
pytest tests/ -v
pytest tests/ --cov=anaya --cov=cli  # With coverage
pytest tests/test_pattern_scanner.py -v  # Specific file
```

---

## Troubleshooting

### GitHub App not receiving webhooks

1. Check GitHub App settings → Recent Deliveries (should see 202 responses)
2. Verify webhook URL is publicly accessible: `curl https://your-url/webhooks/github` (should return 400, POST only)
3. Verify webhook secret matches `GITHUB_WEBHOOK_SECRET`
4. Check firewall/proxy isn't blocking connections

### Scan results not appearing

1. Verify rule is in enabled pack (check `anaya.yml`)
2. Check severity threshold (`fail_on`, `warn_on`)
3. Test rule locally: `anaya test-rule ./my-pack.yml rule-id ./file.py`
4. Check scan logs (GitHub App server)

### False positives blocking PRs

1. Add `exclude_patterns` to suppress known safe patterns
2. Use `# noqa` comments in code
3. Lower severity threshold temporarily
4. Test rule with fixtures to verify accuracy

### Database connection errors

1. Verify PostgreSQL is running: `psql $DATABASE_URL -c "SELECT 1;"`
2. Check connection string format: `postgresql+asyncpg://user:pass@host:5432/db`
3. Verify firewall allows port 5432 (PostgreSQL)
4. Check database user has correct permissions

### High memory usage

1. Large codebases: Split into multiple workers
2. LLM scanning: Reduce batch size or disable LLM
3. Database: Use connection pooling
4. Tip: Monitor with `docker stats`

---

## Comparison Table

| Feature | AnaYa | Semgrep | SonarQube | Snyk |
|---|---|---|---|---|
| **Type** | Compliance | SAST + SCML | Quality + security | Secured dependencies |
| **Open source** | Yes (AGPL) | Yes (LGPL) | No (enterprise) | No (SaaS) |
| **Self-hosted** | ✅ | ✅ | ✅ | ❌ |
| **GitHub integration** | ✅ Native | Via CI/CD | Via CI/CD | ✅ Native |
| **Custom rules** | ✅ YAML | ✅ YAML | ✅ UI/plugins | ❌ No |
| **LLM-powered** | ✅ Optional | ❌ No | ❌ No | ❌ No |
| **DPDP focused** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Cost** | Free (open-core) | Free | Expensive | Expensive |
| **Speed** | Ultra-fast | Fast | Slow | Slow |

---

## More Questions?

- [GitHub Discussions](https://github.com/anaya-scan/anaya/discussions) — Ask the community
- [GitHub Issues](https://github.com/anaya-scan/anaya/issues) — Report bugs
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Development docs
- [ARCHITECTURE.md](../ARCHITECTURE.md) — System design

Happy scanning! 🚀
