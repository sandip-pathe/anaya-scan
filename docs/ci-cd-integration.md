# CI/CD Integration

Run AnaYa in your CI/CD pipeline for continuous compliance scanning.

## GitHub Actions

### Basic Workflow

Create `.github/workflows/anaya-scan.yml`:

```yaml
name: AnaYa Compliance Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      checks: write
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for baseline comparison

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.12"

      - name: Install AnaYa
        run: pip install anaya

      - name: Run compliance scan
        run: |
          anaya scan . \
            --pack generic/secrets-detection \
            --pack generic/owasp-top10 \
            --format json \
            --fail-on CRITICAL
        continue-on-error: true

      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            // Parse scan results and post comment
            // (Example: read scan results from artifact)
```

### Using GitHub App Webhook (Recommended for Private Repos)

Deploy AnaYa as a GitHub App for real-time scanning:

1. **Deploy AnaYa** — Use Docker + cloud provider (see [Azure Hosting](azure-hosting.md))
2. **Create GitHub App** — See [Getting Started](getting-started.md#step-1-create-a-github-app)
3. **Install App** on your repositories
4. **Configure `anaya.yml`** in repo
5. **Push PR** — AnaYa automatically scans

**Advantages:**
- ✅ Real-time feedback
- ✅ Works in private repos
- ✅ Lower CI/CD costs (no GitHub Actions minutes)
- ✅ Can scan on any event

---

## GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - scan

anaya-scan:
  image: python:3.12-slim
  stage: scan
  before_script:
    - pip install anaya
    - cd $CI_PROJECT_DIR
  script:
    - |
      anaya scan . \
        --pack generic/secrets-detection \
        --pack generic/owasp-top10 \
        --format json \
        --fail-on CRITICAL
  artifacts:
    reports:
      sast: scan-results.json
    when: always
  allow_failure: true  # Don't block pipeline, but report results
```

---

## Jenkins

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'python -m venv venv'
                sh 'source venv/bin/activate && pip install anaya'
            }
        }
        
        stage('Scan') {
            steps {
                script {
                    sh '''
                        source venv/bin/activate
                        anaya scan . \\
                            --pack generic/secrets-detection \\
                            --pack generic/owasp-top10 \\
                            --format json \\
                            --fail-on CRITICAL \\
                            > scan-results.json || true
                    '''
                }
            }
        }
        
        stage('Report') {
            steps {
                script {
                    def results = readJSON(file: 'scan-results.json')
                    echo "Found ${results.violations.size()} violations"
                    
                    if (results.violations.size() > 0) {
                        unstable('Compliance issues found')
                    }
                }
            }
        }
    }
    
    post {
        always {
            junit 'scan-results.xml'
            archiveArtifacts 'scan-results.json'
        }
    }
}
```

---

## Azure Pipelines

Create `azure-pipelines.yml`:

```yaml
trigger:
  - main
  - develop

pr:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
    displayName: 'Use Python 3.12'

  - script: |
      python -m pip install --upgrade pip
      pip install anaya
    displayName: 'Install AnaYa'

  - script: |
      anaya scan . \
        --pack generic/secrets-detection \
        --pack generic/owasp-top10 \
        --format json \
        --fail-on CRITICAL > scan-results.json || true
    displayName: 'Run Compliance Scan'
    continueOnError: true

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'scan-results.json'
      artifactName: 'scan-results'
    condition: always()
```

---

## Automated Scanning with Webhooks

For maximum integration, **deploy AnaYa as a GitHub App** that:
- Listens for pull request webhooks
- Automatically scans changed files
- Posts inline Check Run annotations
- Uploads SARIF to Code Scanning

**Setup:**

1. **Deploy AnaYa server** (Docker container):
   ```bash
   docker build -t anaya .
   docker run -p 8000:8000 \
     -e GITHUB_APP_ID=... \
     -e GITHUB_WEBHOOK_SECRET=... \
     -e GITHUB_PRIVATE_KEY_CONTENT=... \
     anaya
   ```

2. **Create GitHub App**:
   - Webhook URL: `https://your-anaya-server.com/webhooks/github`
   - Webhook Secret: (same as `GITHUB_WEBHOOK_SECRET`)

3. **Install on repo** and push a PR

**Result:** ⚡ Instant feedback in PR with zero CI/CD configuration

---

## Performance & Scale

### Optimize for Speed

1. **Limit rule packs** — Only enable needed packs:
   ```bash
   anaya scan . --pack generic/secrets-detection  # Fast
   ```

2. **Exclude large directories**:
   ```yaml
   # anaya.yml
   ignore:
     paths:
       - "node_modules/**"
       - ".git/**"
       - "vendor/**"
   ```

3. **Run only on PR changes** — Use `git diff` to scan only changed files:
   ```bash
   git diff --name-only ${{ github.base_ref }}... \
     | xargs anaya scan --
   ```

### Parallel Scanning

Deploy multiple AnaYa workers for high-volume scanning:

```bash
# Worker 1
celery -A anaya.worker.celery_app worker --queue=scan_pr --concurrency=4

# Worker 2
celery -A anaya.worker.celery_app worker --queue=scan_pr --concurrency=4
```

---

## Baseline Comparison

Only report new violations (ignore pre-existing):

```bash
anaya scan . --baseline ./baseline.json > current.json
```

Generate baseline:
```bash
anaya scan . > baseline.json
git add baseline.json
git commit -m "Set compliance baseline"
```

---

## Policy Enforcement

### Fail on Severity

```bash
anaya scan . --fail-on CRITICAL  # Exit 1 if any CRITICAL
anaya scan . --fail-on HIGH      # Exit 1 if any HIGH or CRITICAL
```

### Custom Exit Codes

```bash
anaya scan . --format json > results.json

if grep -q '"severity": "CRITICAL"' results.json; then
    exit 1  # Block merge on critical
elif grep -q '"severity": "HIGH"' results.json; then
    exit 0  # Warn but don't block
fi
```

### Branch Protection

Add GitHub branch protection rule:

1. **Repo Settings → Branches → Branch protection rules**
2. **Require "AnaYa Compliance Scan" check to pass**
3. PRs with violations will be blocked

---

## Cost Considerations

| Method | Cost | Speed | Coverage |
|---|---|---|---|
| **GitHub Actions** | Billed per minute | Slow (1-5 min) | Only on trigger |
| **GitHub App** | Free | Fast (< 1 sec) | Real-time on PR |
| **Self-hosted** | Your infrastructure | Very fast | Always running |

**Recommendation:** Use **GitHub App** for best ROI (free + instant feedback).

---

## Troubleshooting

### Action Times Out

**Problem:** GitHub Actions job exceeds 6-hour limit

**Solution:**
- Reduce scanned files: add more `ignore` paths
- Use `fail-on CRITICAL` to speed up
- Split into multiple smaller jobs

### High CI/CD Costs

**Problem:** Running AnaYa in every CI/CD pipeline is expensive

**Solution:**
- Deploy GitHub App instead (webhook-based, free)
- Run only on PRs (not every push): `on: [pull_request]`
- Cache dependencies: `actions/setup-python` with caching

### False Positives Blocking Merges

**Problem:** Non-security violations block PRs

**Solution:**
- Adjust severity thresholds: `fail_on: CRITICAL` (not HIGH)
- Add `exclude_patterns` for known false positives
- Use `# noqa` comments in code

---

## Next Steps

- **[Deployment Guide](azure-hosting.md)** — Production deployment
- **[Configuration Reference](configuration.md)** — All `anaya.yml` options
- **[GitHub Issues](https://github.com/anaya-scan/anaya/issues)** — Report integration issues
