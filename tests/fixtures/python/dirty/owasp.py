# Dirty fixture: owasp-top10 rules should trigger here

import hashlib
import os
import pickle
import subprocess
import xml.etree.ElementTree as ET

from flask import Flask, redirect, request

app = Flask(__name__)


# A01 - Broken Access Control: open redirect
@app.route("/redirect")
def unsafe_redirect():
    url = request.args.get("url")
    return redirect(url)  # should trigger: unvalidated redirect


# A02 - Cryptographic Failures: weak hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # should trigger: weak hash md5


# A03 - Injection: SQL injection
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"  # should trigger: SQL injection
    return conn.execute(query).fetchone()


# A04 - Insecure Design: hardcoded admin check
def is_admin(user):
    return user.role == "admin"  # design issue, but scanner catches pattern below


# A05 - Security Misconfiguration: debug mode
app.config["DEBUG"] = True  # should trigger: debug mode enabled


# A06 - Vulnerable Components: (covered by dependency scanner, pattern fallback)
# Using known-vulnerable pattern
JQUERY_CDN = "https://code.jquery.com/jquery-1.6.0.min.js"


# A07 - Auth Failures: hardcoded credentials comparison
def authenticate(username, password):
    if username == "admin" and password == "admin123":  # should trigger: hardcoded credentials
        return True
    return False


# A08 - Software Integrity: pickle deserialization
def load_data(data_bytes):
    return pickle.loads(data_bytes)  # should trigger: unsafe deserialization


# A09 - Logging Failures: logging sensitive data
import logging
def log_user_action(user, action):
    logging.info(f"User {user.email} password={user.password} performed {action}")  # should trigger


# A10 - SSRF: unvalidated URL fetch
def fetch_url(url):
    import urllib.request
    return urllib.request.urlopen(url).read()  # should trigger: SSRF risk
