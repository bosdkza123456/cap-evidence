# Implementation report — corrected foundation

Status: Semantic Design Baseline — Pre-Spike Validation. Semantic state: foundation-0.2. No existing source repository was available when the initial foundation was created. This revision corrects the security review on that foundation.

The strict parser, model validation, host/path primitives, protected trust context, artifact binding, explicit time, CLI, generic adapter and fail-closed OpenSSF boundary remain. The UNKNOWN authorization flaw, DENY aggregation precedence and exact PRESENT/ABSENT conflict detection are corrected. Registered mapped-IP matching is restrictive-only. Inferred references are blocked until canonical identity/reference validation exists.

Validation: 151 passing test events, 4 explicit skipped blocked events; vet, formatting, race, parser/host fuzz and vendored-content regeneration passed. Go 1.26.8 normal builds use CGO_ENABLED=0. Temporary Linux/Windows build checks were performed, but this deliverable contains source only.

Read docs/security-fix-report.md for corrected behaviors and validation limits. Open canonical/path/OS/taxonomy/requirement/declaration/future-time semantics and the OpenSSF real-data spike are still required. No malware certification, authenticated evidence or solved replay/rollback is claimed. The full brief Definition of Done is still incomplete; no public release was created.


Scoped follow-up: restrictive rules reject os, ALLOW evaluates its OS requirements exactly once, and contradictory observed PRESENT/NOT_OBSERVED records in the same run impose REVIEW with observation_inconsistency while preserving DENY. New regressions cover field presence, producer OS changes, different runs/targets, record reversal and monotonic additions. Four existing conformance skips remain unchanged. See docs/security-fix-report.md for the **exact-key conflict** known limitation and scope audit. Candidate decision records remain PROPOSED; no owner approval is claimed.


## Canonical network conflict keys

Both declaration-conflict and observation-inconsistency keys now call the existing target.Host implementation on a copied network target. Hostname case and the already-defined IP spelling normalization therefore match the existing host model. Producer host strings, stored evidence, scope.os, target_scope and other target families remain unchanged. IPv4-mapped addresses are not unmapped for conflict identity. General evidence canonicalization/hashing is still OPEN and unmodified.

The observation pass collects every conflicting group before decision aggregation; it no longer stops after the first key. Each group receives observation_inconsistency and a bounded opaque conflict_key. Declaration conflicts also expose per-group declaration_conflict diagnostics and continue through DEC-DECLARATION-001's existing blocker path. Established DENY remains DENY. The added optional Diagnostic.ConflictKey field is the only model change; its SHA256 token is a presentation grouping reference, not an evidence ID, signature, or newly frozen evidence canonicalization profile. Plaintext hosts/paths are not included in these diagnostic tokens.

Known limitations: conflict matching remains exact for the full scope, including OS and target_scope, and lexical for filesystem/executable targets. Observational inconsistency additionally requires observed basis and the same run ID. Different runs do not trigger observation_inconsistency; declaration conflicts retain their previous scope-based, run-independent rules. No new cross-scope, path or security-equivalence conflict semantics are inferred.

New regressions cover mixed-case hosts, different runs/scopes, unchanged filesystem/executable key behavior, evidence immutability, distinct diagnostic tokens for three simultaneous observation groups (including DENY), and reversed record order. The test suite now explicitly documents that TestRulePlatformAppliesToRestrictiveEffects was replaced by TestRestrictiveRuleRejectsOS to reject the faulty prior OS-filter behavior. No DEC status is changed in this revision.

Canonical conflict-host fuzz passed 73,810 executions in its 10-second run. The unchanged target-host fuzzer initially reported context deadline exceeded during the parallel checks; a standalone one-worker rerun passed 8,661 executions. This timeout and rerun are recorded rather than omitted from validation history.
