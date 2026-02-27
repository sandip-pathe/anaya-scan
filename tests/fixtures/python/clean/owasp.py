# Clean fixture: owasp-top10 rules should NOT trigger here

import hashlib
import json
import logging

from flask import Flask, redirect, request, url_for

app = Flask(__name__)
logger = logging.getLogger(__name__)


# A01 - Safe redirect using url_for
@app.route("/redirect")
def safe_redirect():
    return redirect(url_for("home"))


# A02 - Strong hash
def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()


# A03 - Parameterized query
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# A05 - Debug disabled
app.config["DEBUG"] = False


# A07 - No hardcoded credentials
def authenticate(username, password):
    stored_hash = get_password_hash(username)
    return verify_hash(password, stored_hash)


# A08 - Safe deserialization
def load_data(data_bytes):
    return json.loads(data_bytes)


# A09 - Sanitized logging
def log_user_action(user, action):
    logger.info("User %s performed %s", user.id, action)


# A10 - Validated URL
ALLOWED_HOSTS = {"api.internal.com", "cdn.internal.com"}

def fetch_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    import urllib.request
    return urllib.request.urlopen(url).read()  # noqa: generic/owasp-top10/a10-ssrf-risk
