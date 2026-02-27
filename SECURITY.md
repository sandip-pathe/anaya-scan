# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AnaYa, please do **NOT** open a public GitHub issue. Instead, email your report to:

**security@anaya-scan.dev**

Please include:
1. Description of the vulnerability
2. Steps to reproduce (if possible)
3. Potential impact
4. Suggested fix (if you have one)

We take all security reports seriously and will respond within **48 hours** to confirm receipt.

## Responsible Disclosure

Please allow us a reasonable time to address the vulnerability before public disclosure. Typically:
- **Critical vulns:** We aim to patch and release within 30 days
- **High severity:** 60 days
- **Medium/Low:** 90 days

Once a patch is released, we will acknowledge the reporter (with permission) in the release notes and security advisory.

## Security Best Practices for Users

### GitHub App Security

1. **Private Key:** Keep your GitHub App private key secure
   - Never commit it to version control
   - Use secrets management (GitHub Secrets, HashiCorp Vault, etc.)
   - Consider using `GITHUB_PRIVATE_KEY_CONTENT` environment variable instead of file path

2. **Webhook Secret:** Use a strong, random webhook secret
   ```bash
   openssl rand -hex 32
   ```

3. **Permissions:** Grant only minimal required permissions to your GitHub App
   - Checks: Read & Write
   - Contents: Read-only
   - Pull Requests: Read & Write
   - Metadata: Read-only
   - Code Scanning: Read & Write

### Deployment Security

1. **Use HTTPS** for all webhook endpoints — use a reverse proxy (Caddy, Nginx) or cloud loadbalancer
2. **Verify webhook signatures** — AnaYa does this automatically with HMAC-SHA256
3. **Rotate secrets regularly** — especially `APP_SECRET_KEY` and database passwords
4. **Least privilege** — Run the API and worker with minimal database permissions
5. **Network isolation** — Use private networks, firewalls, or VPCs where possible
6. **Monitoring** — Log all webhook events and scan activities
7. **Rate limiting** — Use API rate limiting to detect abuse

### Rule Pack Security

1. **Custom rule packs:** Only load rule packs from trusted sources
2. **LLM rules:** Be cautious with LLM-powered rules — they make API calls to external services
3. **Regex patterns:** Complex regexes can cause denial-of-service (ReDoS) attacks
   - Use tools like [regex101.com](https://regex101.com) to test regex performance
   - Avoid nested quantifiers (e.g., `(a+)+`)

### Database Security

1. Use strong database passwords
2. Enable SSL/TLS for database connections
3. Restrict database access to application servers only
4. Regular backups with encryption
5. Use the principle of least privilege for database users

## Known Issues

None currently reported.

## Dependencies & Vulnerability Scanning

AnaYa's dependencies are scanned regularly using:
- GitHub Dependabot
- Safety (Python security database)
- Trivy (container scanning)

We update dependencies at least monthly, with security patches applied immediately.

## Security Features in AnaYa

1. **HMAC-SHA256 webhook verification** — All GitHub webhooks are cryptographically verified
2. **JWT RS256 authentication** — GitHub App installation tokens use RS256 signing
3. **No hardcoded secrets** — All secrets are environment variables or mounted files
4. **Async database connections** — Uses asyncpg with connection pooling
5. **Input validation** — All external inputs validated with Pydantic
6. **Rate limiting** — GitHub API client includes backoff and rate limit handling
7. **Redaction in output** — Secrets found by scanners are automatically redacted in reports

## Compliance & Standards

AnaYa follows best practices from:
- OWASP Top 10
- CWE Top 25
- GitHub security guidelines
- NIST cybersecurity framework

## Support for Older Versions

We support security patches for the **current release and one prior release**. After that, we recommend upgrading.

## Hall of Fame

Contributors who responsibly disclose security vulnerabilities will be acknowledged here (with permission):

*(None reported yet)*

---

Thank you for helping keep AnaYa secure!
