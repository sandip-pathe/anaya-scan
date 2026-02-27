// Dirty fixture: tls-encryption rules should trigger here

const https = require("https");
const axios = require("axios");

// Should trigger: no-verify-false (Node.js variant)
const agent = new https.Agent({
  rejectUnauthorized: false,
});

// Should trigger: no-deprecated-tls
const tlsOptions = {
  secureProtocol: "TLSv1_method",
};

// Should trigger: no-deprecated-tls (TLS 1.1)
const tls11Options = {
  secureProtocol: "TLSv1_1_method",
};

// Should trigger: no-weak-cipher
const weakCipherOptions = {
  ciphers: "DES-CBC3-SHA:RC4-SHA",
};

// Should trigger: no-http-url-hardcoded
const API_ENDPOINT = "http://api.production.example.com/v2/data";
const CALLBACK_URL = "http://payment-gateway.example.com/callback";

// Should trigger: no-verify-false
async function fetchInsecure(url) {
  return axios.get(url, { httpsAgent: agent });
}
