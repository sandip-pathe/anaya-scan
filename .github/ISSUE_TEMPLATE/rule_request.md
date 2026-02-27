---
name: Rule Request
about: Suggest a new rule or check
title: "[RULE] "
labels: "type: rule"
assignees: ""
---

## Rule Description
<!-- What vulnerability or compliance issue should this rule detect? -->

## Rule Type
- [ ] Pattern (regex-based)
- [ ] AST (structural/code-based)
- [ ] LLM (AI-powered)

## Severity
- [ ] CRITICAL
- [ ] HIGH
- [ ] MEDIUM
- [ ] LOW

## Languages
- [ ] Python
- [ ] JavaScript
- [ ] Go
- [ ] Other: ___

## Example Code (Should Flag)
```python
# Code that SHOULD trigger this rule
```

## Example Code (Clean)
```python
# Code that SHOULD NOT trigger this rule
```

## References
- CWE: https://cwe.mitre.org/data/definitions/XXX.html
- OWASP: https://owasp.org/...
- Other: 

## Rule Pattern/Query (Optional)
<!-- If you have a regex or query ready, paste it here -->
```regex

```

## Additional Context
<!-- Any other information? -->
