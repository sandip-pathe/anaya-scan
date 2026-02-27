# Dirty fixture: tls-encryption rules should trigger here

import ssl
import urllib3

import requests


# Should trigger: no-verify-false
def fetch_api_data(url):
    response = requests.get(url, verify=False)
    return response.json()


# Should trigger: no-cert-none
def create_insecure_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# Should trigger: no-deprecated-tls
def create_legacy_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx


# Should trigger: no-deprecated-tls (TLS 1.1)
def create_tls11_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    return ctx


# Should trigger: no-weak-cipher
def create_weak_cipher_context():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("DES-CBC3-SHA:RC4-SHA")
    return ctx


# Should trigger: no-http-url-hardcoded
API_ENDPOINT = "http://api.production.example.com/v2/data"
CALLBACK_URL = "http://payment-gateway.example.com/callback"


# Should trigger: no-urllib3-disable-warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
