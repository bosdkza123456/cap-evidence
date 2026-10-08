# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 6. Evidence model that is already decided

Evidence has an outcome.

Wire-format values MUST use lower_snake_case.

Use these values:

```text
present
not_observed
absent
unknown
```

Do not use uppercase values on the wire.

Uppercase forms such as PRESENT or UNKNOWN may be used in prose only as explanatory names.

---

# 7. Evidence basis

The supported evidence bases are:

```text
declared
observed
inferred
```

Do NOT implement an unrestricted basis × outcome cross-product.

Evidence forms are semantically constrained.

### observed + present

Requires:

* target scope
* analysis run context
* action

Must NOT use `derived_from`.

### observed + not_observed

Requires:

* target scope
* coverage covering that scope
* completed run

This does NOT prove absence.

### declared + present

Requires:

* declaration source

Does not require observation coverage.

### declared + absent

Requires:

* declaration source

Does not grant authorization.

### inferred + present

Requires:

* `derived_from`
* analyzer/method metadata

### inferred + absent

Requires:

* `derived_from`
* registered proof rule
* completeness

However:

> inferred.absent is not part of the active v0.1 authorization path unless explicitly enabled by a later decision.

### unknown

`unknown` is a knowledge state.

It must have a reason.

Examples:

```text
not_covered
run_incomplete
analyzer_error
target_unresolvable
evasion_suspected
```

Evaluator-generated:

```text
no_data
```

may also exist where appropriate.

Do not silently convert `not_observed` into `unknown`.

---

# 10. Trust model

Trust levels:

```text
unverified
pipeline_local
authenticated
```

`authenticated` is reserved for a future version.

v0.1 does NOT implement cryptographic authenticated evidence.

IMPORTANT:

`trust` is evaluator-owned.

A producer MUST NOT submit evaluator-owned trust fields as if they were evidence.

If producer input contains evaluator-owned trust information:

```text
→ invalid_evidence
```

Do not silently ignore it.

The evaluator derives trust from protected evaluator context.

Producer-written:

```text
analyzer.name
analyzer.version
```

must NOT automatically be treated as trustworthy merely because they are present.

---

# 21. Artifact binding

v0.1 supports one artifact per evidence bundle.

Multiple artifacts in one bundle should be rejected unless the future specification explicitly defines multi-artifact semantics.

CLI concept:

```bash
capevidence policy check \
  --evidence evidence.json \
  --policy policy.yaml \
  --artifact ./package.tgz
```

or:

```bash
capevidence policy check \
  --evidence evidence.json \
  --policy policy.yaml \
  --artifact-digest sha256:...
```

When `--artifact` is provided:

* hash raw bytes
* stream the file
* do not unpack it
* do not execute it
* compare against the evidence artifact digest

Mismatch:

```text
artifact_mismatch
```

and MUST NEVER result in ALLOW.

Weak hashes such as MD5/SHA-1 are not acceptable for enforce-mode artifact binding.

Important limitation:

A matching digest proves artifact byte identity.

It does NOT prove that the analyzer actually analyzed that exact artifact.

---

# 22. Evidence identity

Current design:

```text
evidence_id =
    hash(canonical form of evidence record
         excluding evidence_id itself)
```

Identity-bearing fields include:

* run_id
* observed_at
* target
* scope
* outcome
* basis
* action
* relevant metadata
* retained extensions

`created_at` is not identity-bearing.

`derived_from` is identity-bearing where present.

Do not implement Merkle-DAG terminology yet.

The bundle canonicalization/order specification is not sufficiently frozen for that terminology.

---

# 24. Extensions

Extensions must be bounded.

Unknown critical extensions:

```text
→ reject
```

Unknown non-critical extensions may be preserved according to the eventual specification.

All retained extension content participates in canonical identity.

Extensions must have limits on:

* size
* nesting depth
* key count
* item count

Reserved evaluator-owned names cannot be shadowed by extensions.

For example, an extension must not redefine:

```text
trust
derived
contains_parent_reference
```

or any future evaluator-owned field.

Reserved-name collision:

```text
→ invalid_evidence
```

---

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

