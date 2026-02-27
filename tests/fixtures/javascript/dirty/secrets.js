// Dirty fixture: secrets-detection rules should trigger here

// Hardcoded API key — should trigger no-hardcoded-api-key
const API_KEY = "test_sk_api_key_1234567890";

// Hardcoded AWS access key — should trigger no-hardcoded-aws-key
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Hardcoded AWS secret key — should trigger no-hardcoded-aws-secret
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// GitHub token — should trigger no-github-token
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12";

// Stripe key — should trigger no-stripe-key
const STRIPE_KEY = "test_stripe_key_1234567890";

// Slack webhook — should trigger no-slack-webhook
const SLACK_WEBHOOK = "https://example.com/webhook/test-slack-webhook-url";

// Database URL with inline password — should trigger no-database-url-password
const DB_URL =
  "postgresql://admin:supersecretpassword@db.example.com:5432/mydb";

// JWT secret — should trigger no-jwt-secret
const JWT_SECRET = "my-super-secret-jwt-key-that-is-long";

// Password — should trigger no-hardcoded-password
const PASSWORD = "my_super_secret_password_123";

async function fetchData() {
  const res = await fetch("https://api.example.com", {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  return res.json();
}
