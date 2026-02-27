// Dirty fixture: owasp-top10 rules should trigger here

const express = require("express");
const crypto = require("crypto");
const { serialize, deserialize } = require("node-serialize");

const app = express();

// A01 - Open redirect
app.get("/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(url); // should trigger: unvalidated redirect
});

// A02 - Weak hash
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex"); // should trigger: weak hash
}

// A03 - SQL injection
function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'"; // should trigger: SQL injection
  return db.query(query);
}

// A05 - Debug mode
app.set("env", "development"); // for pattern purposes

// A07 - Hardcoded credentials
function authenticate(username, password) {
  if (username === "admin" && password === "admin123") {
    // should trigger
    return true;
  }
  return false;
}

// A08 - Unsafe deserialization
function loadData(dataStr) {
  return deserialize(dataStr); // should trigger: unsafe deserialization
}

// A09 - Logging sensitive data
function logUserAction(user, action) {
  console.log(`User ${user.email} password=${user.password} did ${action}`); // should trigger
}

// A10 - SSRF
const axios = require("axios");
async function fetchUrl(url) {
  return axios.get(url); // should trigger: SSRF risk
}

module.exports = { app };
