// Clean fixture: tls-encryption rules should NOT trigger here

const https = require("https");

// Secure agent with proper verification
const agent = new https.Agent({
  rejectUnauthorized: true,
});

// TLS 1.2+ context
const tlsOptions = {
  secureProtocol: "TLS_method",
  minVersion: "TLSv1.2",
};

// Strong ciphers only
const cipherOptions = {
  ciphers: "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
};

// HTTPS URLs — compliant
const API_ENDPOINT = "https://api.production.example.com/v2/data";
const CALLBACK_URL = "https://payment-gateway.example.com/callback";

async function fetchSecure(url) {
  return fetch(url, { agent });
}

module.exports = { agent, fetchSecure };
