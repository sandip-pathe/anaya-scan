# 🔍 AnaYa

[![PyPI version](https://badge.fury.io/py/anaya.svg)](https://badge.fury.io/py/anaya)
[![GitHub Workflow Status](https://github.com/sandip-pathe/anaya-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/sandip-pathe/anaya-scan/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://hub.docker.com/r/anayascan/anaya)

**Compliance-as-code engine** — Scan GitHub pull requests against security & compliance rule packs in real-time.

Detects hardcoded secrets, OWASP Top 10 vulnerabilities, PII exposure, missing audit logs, and more via GitHub Check Runs, SARIF, and PR comments.

**Open-core under AGPL-3.0** · Built by the community, for the community · [Join us on GitHub Discussions](https://github.com/sandip-pathe/anaya-scan/discussions)

## ⚡ Quick Start

### 1. Create GitHub App

[Go to GitHub App settings](https://github.com/settings/apps/new) and configure:

| Setting | Value |
|---|---|
| **Webhook URL** | `https://your-anaya-server.com/webhooks/github` |
| **Webhook Secret** | `openssl rand -hex 32` |
| **Permissions** | Checks, Contents (RO), Pull Requests, Code Scanning |
| **Subscribe to** | Pull request, Installation |

### 2. Install on Repository

1. Download the `.pem` private key
2. Note your **App ID** and **webhook secret**
3. Install the app on your repo

### 3. Add `anaya.yml` to Repository

```yaml
version: "1"

packs:
  - id: generic/secrets-detection
  - id: generic/owasp-top10

thresholds:
  fail_on: CRITICAL
  warn_on: HIGH

ignore:
  paths:
    - "tests/**"
    - "vendor/**"
```

### 4. Create a PR

Push a PR to your repo and **AnaYa will automatically scan it** ✨

View results in:
- **Check Runs** — Inline annotations
- **PR Comment** — Detailed violations
- **Code Scanning** — SARIF results

---

## 📚 Features

| Feature | Description |
|---|---|
| **Real-time PR Scanning** | Webhook-based, instant feedback |
| **44 Built-in Rules** | Secrets, OWASP Top 10, PII, audit logging, TLS |
| **Multiple Rule Types** | Pattern (regex), AST (tree-sitter), LLM (AI) |
| **Custom Rule Packs** | Write your own YAML rules |
| **3 Output Formats** | Check Run annotations, SARIF, PR comments |
| **CLI Tool** | Scan locally: `anaya scan ./src` |
| **DPDP Compliance** | Data Protection Act compliance analysis |
| **Zero Setup** | Works with any GitHub repo |

---

## 📊 Comparison

| Feature | AnaYa | Semgrep | SonarQube |
|---|---|---|---|
| **Type** | Compliance | SAST | Quality + Security |
| **Open Source** | ✅ AGPL | ✅ LGPL | ❌ No |
| **GitHub Integration** | ✅ Native | Via CI/CD | Via CI/CD |
| **Custom Rules** | ✅ YAML | ✅ YAML | ✅ UI/plugins |
| **LLM-Powered** | ✅ Optional | ❌ | ❌ |
| **Self-Hosted** | ✅ Easy | ✅ | ✅ Complex |
| **Cost** | Free | Free | $$$ |
| **Speed** | ⚡⚡⚡ | ⚡⚡ | ⚡ |

---

## 🛠️ How It Works

```
GitHub PR → Webhook → FastAPI → Celery Worker → Scanners → Reporters → GitHub
                                    ↓
                        ┌─────────────┼─────────────┐
                        ▼             ▼             ▼
                      Pattern       AST           LLM
                      (Regex)     (Queries)     (AI)
```

## 📖 Documentation

| Topic | Link |
|---|---|
| **Getting Started** | [5-minute quick start](docs/getting-started.md) |
| **Rule Authoring** | [Write custom YAML rules](docs/rule-authoring.md) |
| **Configuration** | [`anaya.yml` reference](docs/configuration.md) |
| **CI/CD Integration** | [Run in GitHub Actions, GitLab CI, etc.](docs/ci-cd-integration.md) |
| **Deployment** | [Azure hosting guide ($15/mo)](docs/azure-hosting.md) |
| **Architecture** | [Deep dive into internals](ARCHITECTURE.md) |
| **Contributing** | [Development setup, PR process](CONTRIBUTING.md) |
| **FAQs** | [Common questions answered](docs/faq.md) |

---

## 🖥️ Stack

| Layer | Technology |
|---|---|
| API | FastAPI + Uvicorn |
| Workers | Celery + Redis |
| Database | PostgreSQL + SQLAlchemy async |
| Scanning | Regex (Pattern) + tree-sitter (AST) + OpenAI (LLM) |
| Auth | PyJWT RS256 |
| CLI | Typer + Rich |
| Containers | Docker Compose |

---

## 📦 Built-in Rule Packs (44 Rules)

| Pack | Rules | Coverage |
|---|---|---|
| `generic/secrets-detection` | 12 | API keys, tokens, passwords, private keys |
| `generic/owasp-top10` | 10 | SQL injection, XSS, SSRF, command injection |
| `generic/pii-handling` | 8 | Email, SSN, credit card, phone exposure |
| `generic/audit-logging` | 7 | Missing audit logs in sensitive functions |
| `generic/tls-encryption` | 7 | Insecure TLS, weak ciphers, cert validation |

---

## ⚙️ Local Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start services
docker compose up -d postgres redis

# Run tests
pytest tests/ -v --cov=anaya --cov=cli

# Format code
ruff format anaya/ cli/ tests/
ruff check --fix anaya/

# Run API
uvicorn anaya.api.app:create_app --factory --reload
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed setup.

---

## 🚀 Deployment

### Option 1: GitHub App (Webhook-based, Recommended)

Deploy AnaYa as a GitHub App for **real-time PR scanning** (~$15–50/month on cloud):

1. Deploy container to cloud (Azure, AWS, Railway, etc.)
2. Create GitHub App with webhook URL
3. Install on repos
4. Done ✨

[Azure Hosting Guide](docs/azure-hosting.md) (cheapest option)

### Option 2: CI/CD Integration

Run AnaYa in your existing CI/CD pipeline (free, but slower feedback):

```yaml
# .github/workflows/anaya.yml
- name: Scan with AnaYa
  run: |
    pip install anaya
    anaya scan . --fail-on CRITICAL
```

### Option 3: Local CLI

Scan locally without setup:

```bash
pip install anaya
anaya scan ./src --pack generic/secrets-detection
```

---

## 🔐 Security

- ✅ HMAC-SHA256 webhook verification
- ✅ JWT RS256 GitHub App auth
- ✅ Automatic secret redaction in output
- ✅ Pydantic input validation
- ✅ PostgreSQL + TLS encryption
- ✅ No telemetry collection

See [SECURITY.md](SECURITY.md) for security best practices.

---

## 💬 Support & Community

- **[GitHub Discussions](https://github.com/anaya-scan/anaya/discussions)** — Ask questions, share ideas
- **[GitHub Issues](https://github.com/anaya-scan/anaya/issues)** — Report bugs, request features
- **[Security](SECURITY.md)** — Report vulnerabilities responsibly
- **[Contributing](CONTRIBUTING.md)** — Join the community

---

## 📄 License

**AGPL-3.0** — Open-core model. See [LICENSE](LICENSE) for details.

- ✅ Free for individuals, open-source projects
- ✅ Self-host for free
- ✅ Commercial use allowed (AGPL terms)
- ⚠️ Source changes must be contributed back

---

## 🤝 Contributing

AnaYa is **100% community-driven**. We welcome:

- 🐛 Bug reports
- ✨ Feature requests
- 📝 Documentation
- 🎯 New rule packs
- 🧪 Tests
- 🔍 Code reviews

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

Built with ❤️ by the AnaYa community. [Star us on GitHub!](https://github.com/sandip-pathe/anaya-scan)
