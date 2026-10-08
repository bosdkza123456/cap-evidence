# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 25. Whole-bundle rejection

Core rule:

> Invalid evidence must not silently disappear.

Pipeline:

```text
Raw Evidence
    ↓
Parse
    ↓
Schema Validation
    ↓
Semantic Validation
    ↓
Canonicalization
    ↓
Evidence Identity
    ↓
Trust Derivation
    ↓
Artifact Binding
    ↓
Freshness
    ↓
Coverage
    ↓
Applicability
    ↓
Rule Matching
    ↓
Implication
    ↓
Aggregation
    ↓
Diagnostics / Trace
    ↓
Output
```

If an evidence record is invalid:

```text
→ invalid_evidence
```

in enforce evaluation.

Do NOT:

```text
invalid record
↓
drop it
↓
evaluate remaining evidence
↓
accidentally ALLOW
```

---

# 26. Error handling

Errors must be structured.

Where possible include:

```text
record_index
json_pointer
reason_code
```

Example:

```json
{
  "reason_code": "invalid_evidence",
  "record_index": 4,
  "json_pointer": "/evidence/4/target/host"
}
```

Do not allow untrusted input strings to become arbitrary terminal/Markdown output.

Error output must be bounded.

Untrusted strings must not control:

* terminal escape sequences
* log formatting
* Markdown structure
* shell execution
* arbitrary file paths

---

# 27. Privacy / redaction

Potentially sensitive evidence may include:

* URLs
* credentials embedded in URLs
* usernames
* filesystem paths
* environment names
* internal hostnames

Redaction must happen at the output/presentation layer.

Do NOT mutate canonical stored evidence merely to redact it.

Otherwise:

```text
redaction
→ changed bytes
→ changed identity
→ changed semantics
```

The evaluator should keep canonical evidence and presentation output separate.

Add tests to ensure sensitive target strings do not accidentally leak through:

* compact output
* inspect output
* diff output
* error messages

---

# 47. Threat model implementation requirements

Tests must cover at least:

```text
malicious evidence modification
policy modification
trust-context modification
registry modification
duplicate-key parsing
parser differential behavior
resource exhaustion
output injection
stale/replayed evidence
rollback
compromised analyzer
false-positive evidence poisoning
artifact TOCTOU
adapter corruption
extension abuse
```

Important:

Replay/rollback are accepted v0.1 risks.

Do NOT claim that v0.1 has solved replay/rollback.

There is currently no:

* nonce
* revocation system
* supersession protocol
* custom transparency log

for v0.1.

---

# 49. Resource limits

The parser/evaluator must have explicit limits for:

* input size
* number of evidence records
* extension size
* nesting depth
* key count
* array count
* implication expansion
* policy rules
* target pattern length

Avoid unbounded recursion.

Avoid regex-based target matching.

The current hostname glob dialect should be implementable with simple bounded matching.

---

