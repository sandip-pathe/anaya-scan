# Clean fixture: secrets-detection rules should NOT trigger here

import os

import requests


def get_api_key():
    """Load API key from environment — compliant."""
    return os.environ["API_KEY"]


def get_aws_credentials():
    """Load AWS credentials from environment — compliant."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    return access_key, secret_key


def get_github_token():
    """Token loaded from env — compliant."""
    return os.getenv("GITHUB_TOKEN", "")


def get_database_url():
    """DB URL from environment — compliant."""
    return os.environ["DATABASE_URL"]


def get_jwt_secret():
    """JWT secret from env — compliant."""
    return os.getenv("JWT_SECRET")


def connect_to_api():
    """Uses env-sourced credentials — compliant."""
    api_key = os.getenv("API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"}
    return requests.get("https://api.example.com", headers=headers)


# These string literals should not trigger (too short, not matching patterns)
placeholder = "changeme"
test_value = "test"
