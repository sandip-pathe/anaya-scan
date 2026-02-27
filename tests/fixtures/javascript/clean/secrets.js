// Clean fixture: secrets-detection rules should NOT trigger here

// API key from environment — compliant
const API_KEY = process.env.API_KEY;

// AWS credentials from environment — compliant
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY;

// GitHub token from environment — compliant
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

// DB URL from environment — compliant
const DB_URL = process.env.DATABASE_URL;

// JWT secret from environment — compliant
const JWT_SECRET = process.env.JWT_SECRET;

async function fetchData() {
  const apiKey = process.env.API_KEY;
  const res = await fetch("https://api.example.com", {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  return res.json();
}

// Short placeholder strings should not trigger
const placeholder = "changeme";
const testValue = "test";
