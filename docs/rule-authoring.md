# Rule Authoring Guide

Learn to write custom compliance rules for AnaYa.

## Overview

AnaYa supports three types of rules:

| Type | Best For | Speed | Accuracy |
|---|---|---|---|
| **Pattern** (regex) | Secrets, simple patterns, hardcoded values | ⚡⚡⚡ | ~95% |
| **AST** (tree-sitter) | Function calls, structural patterns, code structure | ⚡⚡ | ~98% |
| **LLM** (AI-powered) | Complex logic, semantic analysis, context-aware checks | ⚡ | ~85% (depends on prompt) |

## Pattern Rules (Regex)

Best for: API keys, passwords, hardcoded values

### Basic Syntax

```yaml
id: no-hardcoded-api-key
name: Hardcoded API Key
type: pattern
severity: critical
languages: [python, javascript, go]
pattern: 'api_key\s*=\s*["\']([a-zA-Z0-9_]+)["\']'
message: "API keys must not be hardcoded — use environment variables"
fix_hint: "Move the key to .env or a secrets manager"
```

### Pattern Regex Features

- **Lookahead/lookbehind** — Use `(?=...)` and `(?<=...)`
- **Negation** — Use `(?!...)`
- **Character classes** — `[a-z]`, `\w`, `\d`, `.`
- **Quantifiers** — `+`, `*`, `{n,m}`

### Example Patterns

**Hardcoded AWS credentials:**
```yaml
pattern: 'AKIA[0-9A-Z]{16}'  # AWS Access Key format
```

**Hardcoded Slack webhook:**
```yaml
pattern: 'https://hooks\.slack\.com/services/[A-Z0-9]{9,12}/[A-Z0-9]{9,12}/[A-Za-z0-9_]{24,32}'
```

**Private key in code:**
```yaml
pattern: '-----BEGIN (RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY'
```

### Exclude Patterns

Skip false positives:

```yaml
id: hardcoded-password
pattern: 'password\s*=\s*["\'](.+?)["\']'
exclude_patterns:
  - '.*test.*'         # Skip test files
  - '.*fixture.*'      # Skip test fixtures
  - 'default.*pass'    # Skip default passwords docs
```

### Suppression with `# noqa`

Allow developers to suppress violations:

```python
password = "test-password"  # noqa: hardcoded-password
api_key = "sk-1234"         # noqa  (suppress all violations on this line)
```

### Redaction

Patterns are automatically redacted in reports:

```python
# In code:
api_key = "sk-1234567890"

# In report:
🔴 CRITICAL: Hardcoded API Key
   api_key = "[REDACTED]"
```

---

## AST Rules (Tree-sitter)

Best for: Function calls, control flow, structural patterns

### Supported Languages

- `python`
- `javascript` (including TypeScript, JSX)
- More can be added via tree-sitter parser installation

### Basic Syntax

```yaml
id: missing-audit-log
name: Missing Audit Logging
type: ast
languages: [python]
severity: high
query: |
  (function_definition
    name: (identifier) @func_name)
name_regex: "^(payment_|admin_)"  # Only functions matching this
must_not_contain: ["audit_log", "logger"]
message: "Sensitive functions must include audit logging"
```

### Tree-sitter Query Syntax

Queries use S-expressions to match code structure. Examples:

**Match a function definition:**
```
(function_definition name: (identifier) @func_name)
```

**Match a function call:**
```
(call_expression
  function: (identifier) @func)
```

**Match method calls:**
```
(call_expression
  function: (member_expression
    property: (identifier) @method))
```

**Match assignment:**
```
(assignment
  left: (identifier) @var
  right: (string) @value)
```

### Named Captures

`@capture_name` extracts parts of the matched code:

```yaml
query: |
  (function_definition
    name: (identifier) @func_name
    parameters: (parameters
      parameter: (identifier) @param_name))
```

You can then filter using `name_regex`:

```yaml
name_regex: "^process_"  # Only match @func_name starting with "process_"
```

### `must_not_contain` — Absence Detection

Flag functions that DON'T contain certain patterns:

```yaml
id: missing-permission-check
query: |
  (function_definition
    name: (identifier) @func_name)
must_not_contain:
  - "check_permission"
  - "assert_authorized"
message: "Admin functions must check permissions"
```

### `must_contain` — Presence Detection

Flag functions missing required code (alternative to `must_not_contain`):

```yaml
must_contain:
  - "error_handling"   # Must contain this pattern
```

### Count Ranges

Ensure a pattern appears an expected number of times:

```yaml
query: |
  (function_definition
    body: (block
      statement: (try_statement) @try))
min_count: 1  # At least 1 try block
max_count: 3  # At most 3 try blocks
```

### Python Example — Detect Functions Missing Type Hints

```yaml
id: missing-type-hints
name: Function Missing Type Hints
type: ast
languages: [python]
severity: medium
query: |
  (function_definition
    name: (identifier) @func_name
    parameters: (parameters) @params)
must_not_contain: ["type_comment"]
message: "Function must include type hints or type comments"
fix_hint: |
  def my_func(x: int, y: str) -> bool:
      return True
```

### JavaScript Example — Detect Insecure HTTP

```yaml
id: insecure-http-request
name: Insecure HTTP Request
type: ast
languages: [javascript]
severity: high
query: |
  (call_expression
    function: (identifier) @func
    arguments: (arguments
      [(string) @url
       (template_string) @url]))
name_regex: "^(http|fetch|request)$"
message: "HTTPS must be used — HTTP is insecure"
fix_hint: "Change http:// to https://"
```

### How to Learn XPath

1. **Use [tree-sitter playground](https://tree-sitter.github.io/tree-sitter/playground)**
2. **Paste your code** and explore the syntax tree
3. **Copy/modify queries** from examples
4. **Test locally** with `anaya test-rule`

---

## LLM Rules (AI-Powered)

Best for: Complex logic, semantic violations, context-aware analysis

⚠️ **Requires:**
- `OPENAI_API_KEY` environment variable
- `enable_llm: true` in `anaya.yml`

### Basic Syntax

```yaml
id: secure-crypto-usage
name: Non-Compliant Cryptographic Usage
type: llm
languages: [python, javascript]
severity: high
system_prompt: |
  You are a security expert reviewing code for cryptographic best practices.
  Identify instances where:
  1. Weak algorithms are used (MD5, SHA1, DES)
  2. Insufficient key sizes
  3. Mode misuse (ECB instead of CBC)
user_prompt_template: |
  Review this code for insecure cryptography:
  
  {snippet}
  
  Does it use weak algorithms or improper modes?
confidence_threshold: 0.8  # Only report if confidence >= 0.8
```

### How LLM Rules Work

1. Scanner identifies relevant code (e.g., `crypto.` calls)
2. Extracts snippets
3. Sends to LLM with system + user prompts
4. LLM returns:
   - **Yes/No** — Violation found?
   - **Confidence** (0–1) — How confident?
   - **Explanation** — Why?
5. Filter by confidence threshold
6. Report violations

### Prompt Engineering Tips

**Good system prompt:**
- Clear role ("You are a security expert...")
- Specific criteria ("Look for these 3 things...")
- Expected output format ("Answer Yes/No with confidence")

**Good user prompt:**
- Code snippet
- Context (what are we checking?)
- Specific questions

**Example —find hardcoded secrets missed by regex:**

```yaml
system_prompt: |
  You are a security expert. Review code for any hardcoded secrets.
  Look for:
  - Suspicious variable names (password, token, secret, key, credential)
  - Base64 or hex strings that look like credentials
  - Obvious test/fake credentials (test123, demo, placeholder)
  
  Return: "Yes" if likely a hardcoded secret, "No" otherwise.
  Confidence: 0.0–1.0
  
user_prompt_template: |
  Is this a hardcoded credential?
  
  {snippet}
```

### Cost & Performance

- **Cost:** ~$0.0001 per API call (depends on snippet size)
- **Speed:** 2–5 seconds per violation batch
- **Rate:** Best for 1–100 violations. Not for scanning 10K lines.

### Recommendations

- **Combine LLM + Pattern/AST** — Use regex/AST for fast filtering, LLM for complex cases
- **Set high confidence thresholds** — (0.8+) to avoid false positives
- **Test extensively** — LLMs can be unpredictable
- **Use for organization-specific policies** — Not general security (use Pattern/AST for that)

---

## Rule Pack Structure

Complete rule pack file:

```yaml
id: myorg/security-baseline
name: My Organization Security Standard
version: "1.0.0"
description: Organization-specific compliance rules

rules:
  - id: rule-1
    name: Rule One
    type: pattern
    severity: critical
    languages: [python]
    pattern: '...'
    message: "..."
    
  - id: rule-2
    name: Rule Two
    type: ast
    severity: high
    languages: [javascript]
    query: |
      ...
    message: "..."

  - id: rule-3
    name: Rule Three
    type: llm
    severity: medium
    languages: [python, javascript]
    system_prompt: "..."
    message: "..."
```

## Rule Fields Reference

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | Yes | string | Unique rule identifier (lowercase, hyphens) |
| `name` | Yes | string | Human-readable rule name |
| `type` | Yes | string | `pattern`, `ast`, or `llm` |
| `severity` | Yes | string | `info`, `medium`, `high`, `critical` |
| `languages` | Yes | array | `python`, `javascript`, `go`, etc. |
| `message` | Yes | string | Violation message shown to user |
| `pattern` / `query` / `system_prompt` | Yes | string | Rule definition (depends on type) |
| `fix_hint` | No | string | How to fix the violation |
| `references` | No | array | Links to CWE, OWASP, docs |
| `exclude_patterns` | No (pattern only) | array | Patterns to exclude |
| `name_regex` | No (AST only) | string | Filter captures by name |
| `must_not_contain` | No (AST only) | array | Absence detection |
| `confidence_threshold` | No (LLM only) | float (0–1) | Minimum confidence to report |

---

## Testing Your Rules

### Local Testing

```bash
# Validate rule pack syntax
anaya validate-pack ./my-pack.yml

# Test single rule against a file
anaya test-rule ./my-pack.yml my-rule-id ./test-file.py

# Test entire pack
anaya test-pack ./my-pack.yml ./tests/fixtures/python/
```

### Create Test Fixtures

Directory structure:
```
tests/fixtures/python/
├── dirty/              # Should trigger violations
│   ├── hardcoded_key.py
│   ├── sql_injection.py
│   └── ...
└── clean/              # Should NOT trigger violations
    ├── safe_example.py
    └── ...
```

### Example Fixture

**dirty/hardcoded_key.py —** Should trigger:
```python
api_key = "sk-1234567890"
database_password = "prod-secret"
```

**clean/hardcoded_key.py —** Should NOT trigger:
```python
api_key = os.getenv("API_KEY")
database_password = config.get("db_password")
```

Run test:
```bash
anaya test-pack ./my-pack.yml ./tests/fixtures/python/
```

---

## Publishing Rules

### Contributing to AnaYa

1. Create your rule in a new file or existing pack in `anaya/packs/generic/` or `anaya/packs/myorg/`
2. Add test fixtures to `tests/fixtures/python/dirty` and `tests/fixtures/python/clean`
3. Test thoroughly: `anaya test-pack`
4. Open a PR with:
   - Rule(s) added
   - Test fixtures
   - Documentation update
5. Maintainers review and merge

### Using Your Own Rules

Add your custom pack to `anaya.yml`:

```yaml
packs:
  - id: generic/secrets-detection      # Built-in
  - id: myorg/security-baseline        # Custom
```

Place custom packs in:
- `anaya/packs/myorg/my-pack.yml` (if contributing to AnaYa)
- Or any directory, then use `--packs-dir` flag

---

## Common Pitfalls

❌ **Regex with ReDoS vulnerability:**
```yaml
pattern: '(a+)+b'  # ❌ Nested quantifiers cause performance issues
```
✅ **Use atomic grouping or possessive quantifiers:**
```yaml
pattern: 'a+b'     # ✅ Simplified pattern
```

❌ **AST query too broad:**
```yaml
query: '(function_definition)'  # ❌ Matches ALL functions
```
✅ **Add filtering:**
```yaml
query: |
  (function_definition
    name: (identifier) @func)
name_regex: "^admin_"  # ✅ Only admin_ functions
```

❌ **LLM rule with no confidence threshold:**
```yaml
type: llm
# ❌ Reports all LLM outputs, including low-confidence ones
```
✅ **Set reasonable threshold:**
```yaml
type: llm
confidence_threshold: 0.85  # ✅ Only high-confidence violations
```

❌ **Pattern matching secret in test code:**
```yaml
pattern: 'password\s*=\s*["\'](.+?)["\']'
# ❌ Triggers on test fixtures, docs examples
```
✅ **Exclude test paths:**
```yaml
exclude_patterns:
  - '.*test.*'
  - '.*fixture.*'
```

---

## Resources

- **[Tree-sitter Playground](https://tree-sitter.github.io/tree-sitter/playground)** — Learn AST queries
- **[Regex101](https://regex101.com)** — Test and explain regex patterns
- **[Awesome Regex](https://github.com/aloisdg/awesome-regex)** — Regex tips and tricks
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)** — Security baseline
- **[CWE Top 25](https://cwe.mitre.org/top25/)** — Common weaknesses

---

## Getting Help

- **[GitHub Discussions](https://github.com/anaya-scan/anaya/discussions)** — Ask questions
- **[GitHub Issues](https://github.com/anaya-scan/anaya/issues)** — Report bugs
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — Contribution guidelines

Happy rule authoring! 🚀
