# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 9. Positive authorization boundary

v0.1 is a **positive authorization engine**.

It is NOT a "prove this package is clean" engine.

ALLOW requires positive applicable evidence and an explicit authorization path.

The following MUST NOT independently produce ALLOW:

```text
no evidence
unknown
not_observed
absent
empty decision scope
no_match
require alone
```

In particular:

```text
NOT_OBSERVED → ALLOW
```

is forbidden in v0.1 enforce mode.

Likewise:

```text
ABSENT → ALLOW
```

is forbidden.

---

# 15. Applicability / decision scope

This distinction is critical.

Evidence coverage answers:

> What did the analyzer observe or cover?

Policy decision scope answers:

> What capabilities does this policy make a decision about?

An assertion is applicable when its capability belongs to the policy's:

```text
decision_scope
```

Then:

```text
in scope + matching rule
    → rule result

in scope + no matching rule
    → no_match

out of scope
    → policy-defined handling
```

Do NOT make an in-scope assertion disappear merely because there is no matching allowlist entry.

---

# 16. NO_MATCH

`no_match` is currently an evaluator classification.

It is NOT yet a final severity.

Decision:

```text
DEC-NOMATCH-001
```

is OPEN.

Possible future semantics:

```text
REVIEW
```

or:

```text
DENY
```

Do NOT silently choose one as the final v0.1 semantic.

For now:

* represent `no_match` explicitly in internal evaluation results
* expose it in trace/diagnostics
* ensure it cannot produce ALLOW
* isolate final aggregation behavior behind a decision point

---

# 17. Review gate

The evaluator's decision remains:

```text
allow
review
deny
```

Do NOT introduce:

```text
review_blocks
```

into the policy model.

Enforce mode:

```text
ALLOW  → success
REVIEW → blocking failure
DENY   → blocking failure
FAILURE → failure
```

Audit/inform are non-gating modes.

Do not use GitHub `continue-on-error` as the semantic implementation of review.

---

# 18. Audit / inform

These modes do not authorize anything.

For audit/inform:

```text
ALLOW / REVIEW / DENY
```

may return process exit code 0 if evaluation completed successfully.

Evaluation failure must still return non-zero.

Therefore:

> Exit code 0 in audit/inform means "evaluation completed", not "authorization passed".

Do not use audit/inform exit status as an authorization gate.

---

# 37. Universal ALLOW

Universal target patterns must not produce ALLOW.

Examples:

```text
*
*.*
within("/")
within("com")
```

are not valid positive authorization patterns where they cover universal/broad target space.

DNS ALLOW wildcard baseline:

A wildcard ALLOW should contain a sufficiently specific literal suffix.

For example:

```text
*.example.com
```

is allowed.

Patterns such as:

```text
*.com
*
*.*
```

are not valid ALLOW patterns.

---

# 50. CLI foundation

Create the CLI skeleton.

Conceptual command:

```bash
capevidence policy check \
  --evidence evidence.json \
  --policy policy.yaml
```

Optional artifact:

```bash
--artifact ./package.tgz
```

or:

```bash
--artifact-digest sha256:...
```

The CLI should separate:

```text
parse errors
validation errors
evaluation result
```

Do not yet expose unresolved semantics as fake CLI flags.

Do NOT add:

```text
--allow-not-observed
```

Do NOT add a flag that lets operators bypass the positive authorization boundary.

---

# 51. Output model

The output should clearly separate:

```text
decision
failure
diagnostics
trace
```

Suggested conceptual structure:

```json
{
  "decision": "review",
  "gating": true,
  "diagnostics": [],
  "trace": []
}
```

Do not mix:

```text
failure
```

with:

```text
deny
```

They are semantically different.

---

# 52. Failure vs decision

Possible semantic result categories:

```text
allow
review
deny
failure
```

Where:

```text
allow/review/deny
```

are evaluation decisions.

```text
failure
```

means evaluation could not safely produce a decision.

Examples:

```text
invalid_evidence
invalid_policy
unsupported_version
artifact_mismatch
resource_limit
```

A failure must never be converted to ALLOW.

---

