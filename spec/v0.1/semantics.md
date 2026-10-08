# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 8. Action semantics

The wire values must be:

```text
succeeded
attempted_failed
action_unknown
```

Do NOT use `unknown` for action because it collides conceptually with the evidence outcome `unknown`.

Current authorization rule:

```text
succeeded
    → may satisfy ALLOW requirements

attempted_failed
    → cannot satisfy ALLOW

action_unknown
    → cannot satisfy ALLOW
```

However, the external source may not actually provide reliable success/failure semantics.

Therefore:

> Do not infer action status from an external analyzer unless the source explicitly supports that interpretation.

If an adapter cannot determine action status, it must use:

```text
action_unknown
```

or an explicitly unresolved adapter representation rather than guessing `succeeded`.

---

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

# 11. UNVERIFIED + ALLOW

This is explicitly decided:

```text
unverified + matching ALLOW rule
        ↓
REVIEW
```

It must NOT become ALLOW merely because the target matches the policy.

Example:

```text
Evidence:
network.outbound = api.example.com
trust = unverified

Policy:
ALLOW api.example.com
```

Result:

```text
REVIEW
```

If the matching policy is DENY:

```text
unverified + matching DENY
        ↓
DENY
```

UNVERIFIED evidence can therefore still be security-relevant.

---

# 12. Derived assertions

Implication rules may derive an internal assertion.

Example:

```text
A implies B
```

If A is established:

```text
A = present
```

the evaluator may internally derive:

```text
B = present
```

But:

> Derived assertions are evaluator-internal.

They are NOT persisted as ordinary evidence records.

They must not receive their own evidence ID.

They must not be included as independent evidence records in the canonical evidence bundle.

They may appear in the decision trace as:

```text
kind: derived
```

and may reference:

```text
derived_from: [evidence_id...]
```

If an input bundle itself contains a record pretending to be:

```text
kind: derived
```

reject the entire bundle:

```text
invalid_evidence
```

Do not silently accept or normalize it.

---

# 13. Implication security rule

Implication MUST NOT create or satisfy positive ALLOW on its own.

It can contribute to:

```text
DENY
REVIEW
diagnostics
trace
```

but it cannot bypass the positive authorization boundary.

Also:

> Do not automatically expand `decision_scope` because of implications.

If A is in scope and implies B, but B is outside the policy's decision scope, B has no policy effect.

The evaluator may still expose:

```text
derived_out_of_scope
```

in the trace.

Implication evaluation must eventually be:

* deterministic
* cycle-safe
* finite
* resource-bounded

---

# 14. NOT_OBSERVED semantics

`not_observed` has no independent authorization effect in v0.1.

Therefore:

```text
adding irrelevant not_observed
removing irrelevant not_observed
```

must not change the final decision.

Exception:

A policy `require` may explicitly depend on observability / negative evidence.

If such a requirement fails:

```text
→ at least REVIEW
```

But:

```text
require failure
```

must never weaken:

```text
DENY → REVIEW
```

Severity must remain monotonic:

```text
DENY > REVIEW > ALLOW
```

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

# 19. Freshness

Freshness does NOT erase or downgrade positive evidence.

If evidence is stale:

```text
present + stale
```

must remain:

```text
present
```

with a diagnostic such as:

```text
stale_evidence
```

Freshness may affect:

* negative evidence
* freshness-sensitive requirements
* diagnostics

Known v0.1 limitation:

A stale false-positive PRESENT may continue causing DENY/REVIEW.

Do not mutate old evidence to fix this.

The remediation is:

```text
new analyzer run
→ new evidence
→ replace active pipeline input
```

Supersession/retraction/revocation are deferred.

---

# 20. evaluation_time

`evaluation_time` MUST be an explicit evaluator input whenever deterministic/replayable evaluation is required.

Do NOT silently call the system clock and claim the evaluation is deterministic.

The evaluator should support:

```text
evaluation_time = explicit value
```

and use it consistently for freshness calculations.

Do not silently substitute:

```text
time.Now()
```

for replayable evaluation.

Future `observed_at` handling remains an OPEN decision.

---

# 48. Determinism requirements

Core evaluation must be deterministic given:

```text
evidence
policy
registry
trust context
artifact context
evaluation_time
semantic state version
registry digest
```

Do not use hidden runtime state.

Do not use:

```go
time.Now()
```

inside semantic evaluation unless explicitly passed through evaluator context.

Do not rely on:

* map iteration order
* locale
* host OS behavior
* DNS
* filesystem state
* environment variables
* network access

for deterministic policy evaluation.

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

# 53. Semantic versioning

Every evidence/bundle/policy object must carry a schema/semantic version as required by the specification.

Evaluator must have its own semantic-state registry/version.

Policy cannot define a smaller state universe.

If policy requires an unsupported semantic version:

```text
unsupported_version
```

Do NOT silently fall back to another semantic version.

A new semantic state must not silently fall through to old defaults.

---

# 54. Registry behavior

Registry version and digest must be recorded.

PATCH changes must NOT:

* add/remove capabilities
* change implication semantics
* change target semantics
* change matcher semantics
* change policy-relevant defaults

MINOR may add capabilities and requires explicit re-pin/migration.

Registry growth must not silently weaken policy.

---

# 64. Important distinction

The following are different:

```text
Evidence coverage
```

vs

```text
Policy decision scope
```

vs

```text
Trust
```

vs

```text
Artifact identity
```

vs

```text
Target matching
```

Do not collapse them into one "confidence" or "security score."

There is intentionally no generic:

```text
security_score = 95
```

model.

---

# 65. Core security philosophy

The implementation should follow these principles:

### Principle 1

> Presence is evidence-producing.

### Principle 2

> Absence is coverage-dependent.

### Principle 3

> Positive authorization requires positive applicable evidence.

### Principle 4

> Unknown must not become safe by default.

### Principle 5

> Trust is evaluator context, not producer decoration.

### Principle 6

> Canonical identity and security equivalence are separate.

### Principle 7

> Invalid evidence must not silently disappear.

### Principle 8

> Adapters must preserve uncertainty instead of guessing.

### Principle 9

> Deterministic evaluation requires explicit evaluator inputs.

### Principle 10

> v0.1 should be small enough to audit.

---

