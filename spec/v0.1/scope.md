# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

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
