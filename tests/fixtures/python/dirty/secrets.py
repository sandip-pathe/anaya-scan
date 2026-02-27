# Dirty fixture: secrets-detection rules should trigger here

import requests

# Hardcoded API key — should trigger no-hardcoded-api-key
API_KEY = "test_sk_api_key_1234567890"

# Hardcoded AWS access key — should trigger no-hardcoded-aws-key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Hardcoded AWS secret key — should trigger no-hardcoded-aws-secret
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token — should trigger no-github-token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"

# PEM private key block — should trigger no-private-key-pem
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE3I+AoT
-----END RSA PRIVATE KEY-----"""

# Stripe key — should trigger no-stripe-key
STRIPE_KEY = "test_stripe_key_1234567890"

# Slack webhook — should trigger no-slack-webhook
SLACK_WEBHOOK = "https://example.com/webhook/test-slack-webhook-url"

# Database URL with inline password — should trigger no-database-url-password
DB_URL = "postgresql://admin:supersecretpassword@db.example.com:5432/mydb"

# JWT secret — should trigger no-jwt-secret
JWT_SECRET = "my-super-secret-jwt-key-that-is-long"

# Password in URL — should trigger no-password-in-url
SERVICE_URL = "https://user:p4ssw0rd@api.example.com/v1"

# Hardcoded password — should trigger no-hardcoded-password
PASSWORD = "my_super_secret_password_123"

def connect():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com", headers=headers)
