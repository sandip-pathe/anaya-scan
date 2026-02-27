# Clean fixture: tls-encryption rules should NOT trigger here

import ssl

import requests


def fetch_api_data(url):
    """HTTPS request with verification enabled (default)."""
    response = requests.get(url, verify=True)  # noqa: generic/owasp-top10/a10-ssrf-risk
    return response.json()


def create_secure_context():
    """Create a properly configured SSL context."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def create_tls13_context():
    """TLS 1.3 context — modern and secure."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


# HTTPS URLs are fine
API_ENDPOINT = "https://api.production.example.com/v2/data"
CALLBACK_URL = "https://payment-gateway.example.com/callback"


# HTTP in test files is acceptable (this file is in clean fixtures,
# but in the real scanner, test file paths are excluded)
