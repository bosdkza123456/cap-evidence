# CAP-Evidence v0.1

## Codex Implementation Brief — Pre-Implementation Scope

**Project status:** Semantic Design Baseline — Pre-Spike Validation
**Implementation phase:** Pre-Implementation / Foundation
**Current goal:** Build the parts that are semantically safe to implement now, while explicitly preventing Codex from inventing unresolved semantics.

---

# 1. What this project is

CAP-Evidence is an open-source, machine-readable **capability evidence exchange and policy evaluation layer**.

The system is intended to turn software-behavior evidence into a portable representation that downstream policy engines can evaluate deterministically.

The conceptual pipeline is:

```text
Software / Analyzer
        ↓
Behavior Evidence
        ↓
CAP-Evidence Evidence Model
        ↓
Validation
        ↓
Canonicalization / Identity
        ↓
Trust / Artifact Context
        ↓
Policy Evaluation
        ↓
ALLOW / REVIEW / DENY / FAILURE
```

The project is NOT primarily a malware scanner.

It does not attempt to independently determine whether software is "safe."

Its purpose is to represent and evaluate evidence such as:

```text
"this artifact was observed attempting an outbound network connection
to this target within this analysis scope"
```

and allow an operator-defined policy to answer:

```text
Is this positive capability evidence authorized by this policy?
```

---

# 2. Why this project exists

Existing ecosystem systems already cover related dimensions:

* SBOM → what components exist
* provenance / build systems → how an artifact was produced
* behavioral analysis → what behavior was observed
* vulnerability systems → known security issues
* this project → portable evidence representation + deterministic policy evaluation around observed/declared/inferred capabilities

CAP-Evidence should therefore complement those systems rather than replace them.

The first intended external evidence adapter is OpenSSF Package Analysis.

IMPORTANT:

Do NOT assume undocumented OpenSSF fields or semantics.

OpenSSF integration is currently a real-data spike.

The implementation must not invent:

* action success/failure
* run completeness
* coverage semantics
* network port semantics
* filesystem semantics
* executable semantics

until verified from actual source/output data.

---

# 3. Current implementation principle

The most important rule for this implementation:

> Do not turn an unresolved semantic decision into an implementation assumption.

If a behavior is explicitly decided below, implement it.

If it is marked OPEN / PENDING_SPIKE, do not silently choose an interpretation.

Instead:

1. isolate the behavior behind an interface,
2. add a TODO with the exact decision ID,
3. add a failing/blocked conformance test if appropriate,
4. document the dependency,
5. do not expose the unresolved behavior as stable v0.1 semantics.

---

# 4. What is in scope NOW

The following work is approved for implementation now.

## 4.1 Repository foundation

Create/maintain this structure:

```text
capevidence/
├── spec/
│   └── v0.1/
│       ├── scope.md
│       ├── decision-register.md
│       ├── semantics.md
│       ├── evidence.md
│       ├── policy.md
│       ├── target-model.md
│       ├── canonicalization.md
│       ├── threat-model.md
│       └── examples/
│
├── test-vectors/
│   ├── evidence/
│   ├── policy/
│   ├── targets/
│   ├── canonicalization/
│   ├── security/
│   └── expected/
│
├── internal/
│   ├── model/
│   ├── parse/
│   ├── validate/
│   ├── canonical/
│   ├── identity/
│   ├── target/
│   ├── trust/
│   ├── artifact/
│   ├── policy/
│   ├── evaluate/
│   ├── trace/
│   └── cli/
│
├── adapters/
│   ├── generic-json/
│   └── ossf-package-analysis/
│
├── docs/
│
├── SECURITY.md
├── CONTRIBUTING.md
├── GOVERNANCE.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
└── go.mod
```

Do not create unnecessary public Go APIs.

For v0.1, prefer:

```text
internal/
```

over:

```text
pkg/
```

because the public contract is the specification/schema/conformance behavior, not an already-stable Go API.

---

# 5. Language / implementation

Use Go unless the existing repository already establishes another implementation language.

Recommended implementation characteristics:

* deterministic
* strongly typed
* explicit validation
* explicit errors
* bounded resource consumption
* testable without network access
* no hidden global state
* no dependence on current system time for deterministic evaluation
* no network access required by the core evaluator

Core evaluation must be a pure/deterministic operation given explicit inputs.

---

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

# 23. Canonicalization

The implementation must have a dedicated canonicalization layer.

Do not mix canonicalization with policy evaluation.

Pipeline:

```text
input
 ↓
parse
 ↓
typed model
 ↓
semantic validation
 ↓
canonical representation
 ↓
hash / identity
```

YAML is an authoring format only.

Do not use YAML serialization itself as evidence identity.

Strict YAML parsing should reject or safely handle:

* duplicate keys
* aliases/anchors
* custom tags
* dangerous implicit conversions

The exact canonical JSON / hashing profile is still subject to final decision.

Therefore:

> Build the canonicalization interface and conformance harness now, but do not claim the exact final canonical wire profile is frozen.

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

# 28. Target model — what can be implemented now

Some target semantics are sufficiently defined to create interfaces and conformance tests.

## Network

Current baseline:

```text
network.outbound
target = host
```

This is a current normative baseline, NOT an irrevocably frozen decision.

The OpenSSF spike may invalidate it.

Do not silently strip a port from source data and authorize only the host.

If input contains unsupported granularity such as:

```text
example.com:443
```

the adapter/evaluator must not truncate it to:

```text
example.com
```

for authorization.

Exact handling is subject to:

```text
DEC-PORT-001
```

---

# 29. Hostname glob

v0.1 baseline:

```text
*
```

means exactly one complete DNS label.

Examples:

```text
*.example.com
```

matches:

```text
api.example.com
www.example.com
```

does not match:

```text
example.com
a.b.example.com
```

No substring wildcard.

No:

```text
ab*
*a
a*b
```

No regex.

No character classes.

No brace expansion.

Invalid/unsupported pattern:

```text
→ invalid_policy
```

Never best-effort.

Matching must be resource-bounded.

---

# 30. DNS / IDNA

Current baseline:

* ASCII hostnames supported
* IDNA A-labels supported
* raw Unicode hostnames rejected

Do not implement a custom IDNA interpretation without a dedicated decision.

DNS identity rules must remain deterministic.

---

# 31. DNS underscore baseline

Current baseline:

```text
_dmarc.example.com
```

may be accepted.

But:

```text
_sip._tcp.example.com
```

is not accepted under the current v0.1 baseline.

Likewise:

```text
a_b.example.com
```

is invalid.

Wildcard ALLOW must not unintentionally cover underscore labels.

This remains a source/target-model area that may be refined before semantic freeze.

---

# 32. IPv4

Use canonical dotted-decimal IPv4.

Reject ambiguous forms such as:

```text
127.1
0x7f.1
octal-style representations
```

Do not interpret ambiguous numeric host forms differently depending on platform/library.

---

# 33. IPv6

Use deterministic canonical IPv6 representation.

Zone identifiers such as:

```text
fe80::1%eth0
```

are rejected in v0.1.

IPv4-mapped IPv6 remains a distinct canonical identity:

```text
::ffff:127.0.0.1
```

is NOT the same evidence identity as:

```text
127.0.0.1
```

However, a future/security-equivalence matcher may use:

```text
IPv4-mapped IPv6 ↔ IPv4
```

for DENY/REVIEW matching.

It must NOT change evidence identity.

---

# 34. Path model

Current baseline:

* lexical normalization only
* no filesystem resolution
* no symlink resolution
* no bind-mount inference
* no cwd inference
* no `~` expansion
* relative paths are invalid evidence in the core baseline
* NUL/control characters are invalid

Raw path must be preserved.

Canonical path is evaluator-derived.

`contains_parent_reference` is evaluator-derived from raw input.

Producer MUST NOT set it.

If raw input contains:

```text
..
```

it cannot be used as the basis for ALLOW.

DENY/REVIEW may inspect both raw and canonical representation.

The exact equivalence rules for:

```text
/tmp/a
/tmp/./a
/tmp//a
/tmp/a/
```

remain subject to the path decisions.

Do not silently invent extra equivalence rules.

---

# 35. Path authorization asymmetry

The intended security principle is:

```text
ALLOW:
    raw semantics must be safe
    AND
    canonical semantics must match

DENY / REVIEW:
    may inspect raw OR canonical forms
```

This is deliberately conservative.

Do not weaken ALLOW by adding broad normalization.

---

# 36. Windows path security

Do not authorize the following in v0.1 ALLOW semantics unless explicitly covered by a future target decision:

```text
UNC paths
\\?\ paths
\\.\ paths
alternate data streams
drive-relative paths such as C:foo
short-name forms such as PROGRA~1
```

Windows-specific normalization is an open area.

Do not create fake portability by simply replacing `\` with `/`.

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

# 38. Security equivalence

Canonical identity and security matching are separate.

Canonical identity determines:

* evidence_id
* digest
* audit identity
* conflict identity

Security equivalence may be used only where explicitly registered.

Current intended example:

```text
IPv4-mapped IPv6 ↔ IPv4
```

for:

```text
DENY / REVIEW
```

It must NOT:

* change evidence identity
* create ALLOW
* broaden positive authorization

Adding/removing/changing security equivalence must be versioned.

---

# 39. Capability taxonomy

Keep capability names separate from target families.

For example:

```text
process.spawn
system.command
```

are capabilities.

They are not automatically target families.

Candidate capability taxonomy:

```text
network.outbound
network.inbound
filesystem.read
filesystem.write
process.spawn
system.command
environment.read
credential.access
```

IMPORTANT:

Do not assume every candidate capability belongs in v0.1.

Capability mappings must be supported by real source evidence.

Unsupported capabilities must be removed or marked unavailable rather than guessed.

---

# 40. Executables / commands

Do NOT assume:

```text
executable.name
```

alone can create ALLOW.

No PATH lookup.

No symlink resolution.

No command-intent inference.

Arguments are not currently a target representation.

The exact positive authorization semantics for executable paths remain OPEN.

Therefore create interfaces and tests around executable targets, but do not finalize a path-only ALLOW model.

---

# 41. Platform

Platform is derived from evidence scope:

```text
scope.os
```

It is not a producer-controlled target attribute.

`scope.os` participates in evidence identity.

Policy may specify platform requirements.

If policy omits platform:

> Do not allow unknown platform information to broaden ALLOW.

If policy specifies a platform:

```text
evidence.scope.os
```

must satisfy that requirement.

The exact allowed `scope.os` vocabulary is still subject to formalization.

---

# 42. Required invariants / tests

Create a property/conformance test skeleton for at least:

```text
PROP-001
Evaluation is order-independent.

PROP-002
Canonicalization is idempotent.

PROP-003
Unverified present cannot become ALLOW.

PROP-004
Not_observed cannot become ALLOW in enforce v0.1.

PROP-005
Empty decision scope cannot become ALLOW.

PROP-006
No_match cannot become ALLOW.

PROP-007
Reducing trust cannot make a decision less restrictive.

PROP-008
Implication cannot create ALLOW.

PROP-009
Derived assertions are not persisted as evidence.

PROP-010
Derived out-of-scope assertions have no policy effect.

PROP-011
Stale present remains present.

PROP-012
Incomplete runs cannot produce not_observed.

PROP-013
Invalid evidence cannot silently disappear.

PROP-014
A new semantic state cannot silently use an old default.

PROP-015
Review cannot be weakened into ALLOW.

PROP-016
Audit cannot become an authorization gate.

PROP-017
Registry PATCH cannot alter policy semantics.

PROP-018
Same evidence may produce different trust under different evaluator contexts.

PROP-019
Same analyzer does not imply same run/target identity.

PROP-020
Artifact mismatch never produces ALLOW.

PROP-021
Irrelevant not_observed does not change decision.

PROP-022
Input derived records are rejected.

PROP-023
Producer cannot control evaluator-owned trust.

PROP-024
Producer cannot control contains_parent_reference.

PROP-025
Security equivalence does not change evidence identity.

PROP-026
Unknown platform cannot broaden ALLOW.

PROP-027
Raw parent reference cannot produce ALLOW.

PROP-028
Universal ALLOW patterns are rejected.

PROP-029
Unsupported glob syntax is rejected.

PROP-030
IPv4-mapped IPv6 equivalence cannot create ALLOW.

PROP-031
Invalid target cannot silently downgrade into harmless unknown.

PROP-032
Failed/unknown action cannot satisfy ALLOW.

PROP-033
Executable name alone cannot satisfy ALLOW.

PROP-034
Adding an irrelevant in-scope assertion cannot preserve ALLOW if it violates an explicit restrictive policy.

PROP-035
Reserved extension names cannot shadow evaluator-owned fields.
```

Do not implement a property in a way that assumes unresolved semantics.

Where necessary, mark a test:

```text
blocked_by: DEC-XXXX
```

---

# 43. Required conformance vectors

Create examples for:

## Valid

```text
valid observed present
valid declared present
valid declared absent
valid unknown
valid observed not_observed with complete coverage
valid inferred present
```

## Invalid

```text
producer-supplied trust
producer-supplied derived assertion
reserved extension collision
invalid target
relative filesystem path
path containing unsafe parent reference for ALLOW
unsupported glob
ambiguous IPv4
IPv6 zone ID
universal ALLOW
duplicate YAML keys
invalid extension
invalid action
```

---

# 44. Adapter safety

Create a generic adapter interface.

Conceptually:

```go
type Adapter interface {
    Parse(input []byte) ([]EvidenceRecord, []Diagnostic, error)
}
```

The exact API may differ.

Adapter responsibilities:

* translate source format
* preserve source information
* never invent unsupported semantics
* never fabricate successful actions
* never fabricate coverage
* never fabricate completeness
* never silently drop unsupported security-relevant events

If a source event cannot be represented accurately:

```text
unknown
```

with a reason such as:

```text
unsupported_source_event
```

may be appropriate.

Do NOT silently drop it.

---

# 45. OpenSSF adapter — CURRENTLY LIMITED

Create the adapter boundary and fixture-based tests.

Do NOT claim full OpenSSF compatibility yet.

Do NOT hard-code assumptions such as:

```text
OpenSSF action succeeded
OpenSSF run complete
OpenSSF port semantics
OpenSSF coverage semantics
OpenSSF artifact identity semantics
```

unless verified by the real-data spike.

Use fixtures.

The adapter should be structured so that real source findings can be mapped later without rewriting the core evaluator.

---

# 46. OpenSSF spike boundary

The following are explicitly NOT resolved by this implementation brief:

```text
SPIKE-NET-001
network target granularity

SPIKE-PATH-001
filesystem path representation

SPIKE-CMD-001
command/executable representation

SPIKE-ACTION-001
success/failure semantics

SPIKE-RUN-001
run completeness

SPIKE-COVERAGE-001
coverage semantics

SPIKE-ARTIFACT-001
artifact identity

SPIKE-UNKNOWN-001
failure/unsupported event representation
```

The adapter must remain modular until these are resolved.

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

# 55. What Codex MUST NOT implement yet

Do NOT implement or freeze the following:

## Semantic decisions still open

```text
DEC-NOMATCH-001
final no_match → review or deny

DEC-PORT-001
host-only vs host+port / unsupported granularity

DEC-FUTURE-001
future observed_at behavior

DEC-PATH-001
exact raw/canonical equivalence rules

DEC-PATH-002
path trailing slash / dot / duplicate slash semantics

DEC-ROOT-001
exact broad-root ALLOW threshold

DEC-UNICODE-001
canonical Unicode normalization profile

DEC-CMD-001
executable positive authorization semantics

DEC-OS-001
final scope.os vocabulary

DEC-CAP-001
final capability taxonomy supported by real data

DEC-HASH-001
final canonical hashing profile

DEC-BUNDLE-001
final bundle canonical ordering

DEC-CONFLICT-001
final aggregate escalation semantics

DEC-DECLARATION-001
final declaration mismatch behavior

DEC-FUTURE-002
final future timestamp treatment
```

The actual decision IDs may be consolidated later, but do not invent a different semantic decision silently.

---

# 56. Do NOT implement these product features

Out of scope:

```text
dashboard
SaaS
web application
malware scanner
security score
AI security judge
blockchain
custom transparency log
custom signature protocol
full dependency graph engine
MCP as core protocol
automatic package trust ranking
automatic "safe package" certification
```

These are intentionally excluded from v0.1.

---

# 57. Do NOT implement negative authorization yet

v0.1 is:

```text
positive authorization
```

not:

```text
absence-based authorization
```

Therefore do NOT implement:

```text
not_observed → allow
absent → allow
all-target negative authorization
```

Future negative authorization is a separate milestone.

---

# 58. Do NOT overbuild the taxonomy

Do not create a giant capability catalog.

Only implement capabilities that can be justified by:

1. the semantic model
2. the actual source evidence
3. a policy use case
4. a conformance test

If a capability cannot be mapped without guessing:

```text
do not include it in active v0.1 mapping
```

---

# 59. Recommended implementation order

Implement in this order:

```text
STEP 1
Repository / Go module
        ↓
STEP 2
Typed evidence model
        ↓
STEP 3
Strict parsing
        ↓
STEP 4
Schema validation
        ↓
STEP 5
Semantic validation
        ↓
STEP 6
Canonicalization interface
        ↓
STEP 7
Evidence identity
        ↓
STEP 8
Target matcher primitives
        ↓
STEP 9
Trust context
        ↓
STEP 10
Artifact binding
        ↓
STEP 11
Policy parser
        ↓
STEP 12
Applicability
        ↓
STEP 13
Rule matching
        ↓
STEP 14
Decision result model
        ↓
STEP 15
Diagnostics / trace
        ↓
STEP 16
Conformance harness
        ↓
STEP 17
CLI
        ↓
STEP 18
Generic JSON adapter
        ↓
STEP 19
OpenSSF adapter boundary + fixtures
```

Do not jump directly to a large evaluator.

---

# 60. Definition of Done — Spec / Semantic

For this phase, the semantic DoD is NOT "everything is frozen."

It is:

* all currently decided semantics are represented in code/tests
* all unresolved decisions have explicit IDs
* unresolved decisions are not silently implemented
* wire values use lower_snake_case
* evaluator-owned fields cannot be producer-controlled
* invalid evidence cannot disappear
* ALLOW cannot originate from negative/unknown/no-data states
* deterministic inputs are explicit
* OpenSSF assumptions are not fabricated
* test vectors exist for decided security invariants

---

# 61. Definition of Done — Implementation

The implementation phase is complete when:

```text
go test ./...
```

passes for all currently enabled conformance tests.

Additionally:

* `go vet` passes
* formatting is clean
* race-sensitive code is reviewed where relevant
* parser limits are tested
* malformed inputs do not panic
* core evaluator does not access network
* core evaluator does not access filesystem implicitly
* deterministic evaluation tests pass
* property tests cover the critical invariants
* CLI returns the correct failure/decision class
* artifact mismatch cannot ALLOW

---

# 62. Definition of Done — OSS hygiene

Separate from semantic correctness:

* README explains the project accurately
* SECURITY.md exists
* CONTRIBUTING.md exists
* GOVERNANCE.md exists
* CODE_OF_CONDUCT.md exists
* LICENSE exists
* examples do not claim unsupported semantics
* no secrets in repository
* no generated credential files
* no unsafe shell examples
* CI runs tests
* dependency versions are pinned/managed appropriately

OSS hygiene must NOT be used as a reason to prematurely freeze unresolved semantic decisions.

---

# 63. Required engineering discipline

Every non-trivial semantic behavior must be traceable.

Use IDs:

```text
ADR-*       architecture decisions
DEC-*       semantic decisions
PROP-*      properties/invariants
TEST-*      concrete conformance tests
SPIKE-*     empirical findings
```

Example:

```text
DEC-TRUST-001
    ↓
PROP-023
    ↓
TEST-TRUST-001
    ↓
implementation
```

Do not create multiple IDs for the same semantic decision without a reason.

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

# 66. Final instruction to Codex

Before changing code:

1. Inspect the repository.
2. Identify what already exists.
3. Do not overwrite working code unnecessarily.
4. Map current code to this scope.
5. Create an implementation plan.
6. Implement only the currently approved scope.
7. For unresolved semantics, create explicit TODO/decision references rather than guessing.
8. Add tests with the semantic decision/property IDs.
9. Run the full test suite.
10. Report:

* what was implemented
* what was intentionally not implemented
* what decisions remain open
* what tests were added
* what assumptions were avoided
* what blocks the next implementation phase

Most importantly:

> Do not optimize for the largest amount of code written.

Optimize for:

> the smallest amount of implementation that establishes a trustworthy, deterministic, testable foundation without prematurely freezing unresolved security semantics.

The project must remain in:

```text
Semantic Design Baseline — Pre-Spike Validation
```

until the OpenSSF real-data spike and remaining blocking decisions are resolved.

Do not label v0.1 semantics as final/frozen yet.
