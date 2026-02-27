// Clean fixture: owasp-top10 rules should NOT trigger here

const express = require("express");
const crypto = require("crypto");

const app = express();

// A01 - Safe redirect
app.get("/redirect", (req, res) => {
  res.redirect("/home");
});

// A02 - Strong hash
function hashPassword(password, salt) {
  return crypto
    .createHash("sha256")
    .update(salt + password)
    .digest("hex");
}

// A03 - Parameterized query
function getUser(userId) {
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

// A07 - No hardcoded credentials
function authenticate(username, password) {
  const storedHash = getPasswordHash(username);
  return verifyHash(password, storedHash);
}

// A08 - Safe deserialization
function loadData(dataStr) {
  return JSON.parse(dataStr);
}

// A09 - Sanitized logging
function logUserAction(user, action) {
  console.log(`User ${user.id} performed ${action}`);
}

// A10 - Validated URL
const ALLOWED_HOSTS = new Set(["api.internal.com"]);
async function fetchUrl(url) {
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error("Host not allowed");
  }
  return fetch(url);
}

module.exports = { app };
