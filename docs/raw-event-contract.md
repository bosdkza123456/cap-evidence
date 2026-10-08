# Proposed raw event contract 0.1

Status: **PROPOSED — pending owner approval**. Approver: 

This is a research contract, not an OpenSSF wire format, finalized capability registry or production authorization protocol. Existing DEC statuses are unchanged. Implementation is isolated in `adapters/raw-event-preview`; it returns candidates and fixed reason codes, never `model.Bundle`, evidence, trust, negative assertions or authorization. `AuthorizationReady` is always false.

## Proposed decisions

| Proposal ID | Rule | Rationale | Tests |
|---|---|---|---|
| RAW-CONTRACT-001 | Explicit operation and result per event; connect and bind distinct; stat does not imply content read | Summary erases direction and per-event success | TestOperationAndResultBoundaries |
| RAW-BINDING-001 | Protected caller supplies run ID, artifact digest, analyzer name/version and digest of original payload bytes | Producer metadata cannot authenticate itself; complete payload pin prevents substitution | TestProtectedBinding |
| RAW-COVERAGE-001 | Explicit requested phases/status and complete/dropped/parse_failures required; incomplete state remains visible; not_run phase cannot contain events | Empty records or completed phase cannot prove absence | TestIncompleteCoverageAndUnknownRemainVisible, TestEventInNotRunPhaseRejected |
| RAW-UNKNOWN-001 | Unsupported operation retained as candidate with diagnostics; unknown schema fields reject whole input | No silent drop and no guessed semantics | TestOperationAndResultBoundaries, TestStrictAndSecretSafeFailures |
| RAW-PRIVACY-001 | Do not accept environment/argv fields in prototype; errors contain fixed codes, not payload values | Avoid exporting credentials while preserving original-byte binding | TestStrictAndSecretSafeFailures |

Every proposal has status PROPOSED — pending owner approval and no approver. These are proposal IDs in this document, not changes to the existing decision register.

## Input

Byte-bounded strict JSON only; duplicate keys, malformed Unicode, trailing values, unknown fields and incompatible types reject the entire input through the existing parser. Required metadata: version `raw-event-proposed-0.1`, nonempty run_id, lowercase 64-hex artifact_digest, analyzer name/version. Digest notation is raw SHA-256 hex, without a prefix. No archive bytes are read by the preview.

`phases` lists requested phases with unique nonempty names and explicit `completed`, `failed` or `not_run` status. Vocabulary remains provisional. `coverage` requires explicit boolean complete and nonnegative integer dropped/parse_failures. These are producer claims for inspection only, not trusted completeness attestations. False completeness, drops, failures or incomplete phases add incomplete_raw_coverage. Even all-positive claims cannot authorize.

`events` has unique IDs within this payload, a declared phase, RFC3339 timestamp, operation and result (`succeeded`, `failed`, `attempted`, `unknown`). Events in not_run phases reject. Failed phases may contain actions preceding the failure. IDs are source-local references, not CAP evidence IDs. Array position is not assumed to prove temporal ordering. No event ID hashing/inferred-evidence semantics are introduced.

Targets: connect/bind require host and explicit port 0–65535; read/write/delete/stat require a path; exec requires executable. Known operations reject mixed target families. Targets and timestamp strings are preserved, not canonicalized or interpreted as verified identity. Port 0 is retained as unresolved, never treated as a proven destination service. Unsupported operations remain visible and receive unsupported_raw_event/unmapped_raw_operation; they never supply a capability. Bind and stat have no mapped capability. Proposed capability strings in candidates are hints only; they are not registered by this change.

## Protected integration boundary

Binding is a separate Go argument, never accepted from JSON. The caller must obtain it through protected orchestration. Matching strings and SHA-256 pin bytes but do not implement signatures, remote identity authentication, archive verification or replay protection. A caller that trusts producer-supplied binding defeats this boundary. Preview does not set model.TrustContext or bypass evaluator validation.

Timestamp syntax is checked; freshness/future timestamps require explicit evaluator time and are not decided here. No wall clock, network, package execution, syscall execution or filesystem access occurs in Inspect.

## Secret handling

Prototype schema excludes environment and argv: unknown fields reject the whole document instead of deleting fields and hashing altered data. Original bytes are hashed before use and never logged by the implementation. Errors/diagnostics contain fixed reason codes and record indices only. Candidates retain raw targets and can themselves contain sensitive paths or strings; callers must not log/serialize them automatically. This is not a general credential detector or arbitrary-target redactor. Real raw collectors must avoid collecting unnecessary secrets or use protected raw storage and separate redacted presentation without replacing the original digest.

## Fixtures and limitations

`testdata/synthetic-connect.json` and generated tests are explicitly synthetic. Public OpenSSF summary fixtures are incompatible with this proposed contract and remain rejected by the original summary adapter. No genuine raw collector output, cryptographic attestation, approved mapping, complete collection guarantee or end-to-end OpenSSF integration is claimed. No NOT_OBSERVED/ABSENT is ever synthesized, including from an empty complete input.
