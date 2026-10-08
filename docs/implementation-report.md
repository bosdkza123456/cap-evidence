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

## OpenSSF real-output spike (2026-10-08)

Pinned upstream source and two byte-exact historical public outputs were reviewed across all eight SPIKE topics. See `openssf-spike-report-th.md` and fixture provenance. The adapter implementation remains fail-closed; no evaluator or decision-register changes. Regression boundaries verify no invented evidence, success, coverage or negative assertions. These fixtures are not asserted to originate from the pinned current source commit, and no upstream analyzer/package was executed. Authorization mapping remains blocked on raw-event semantics and protected run/artifact/coverage contracts.

## Proposed raw-event contract and preview

See `raw-event-contract.md` and `raw-event-report-th.md`. The isolated preview checks strict bounded JSON, protected payload/run/artifact/analyzer binding, explicit phase/coverage and per-event operation/result. It preserves ports, targets and unsupported events for inspection. It never produces CAP evidence or authorization; proposal approval and genuine collector integration remain pending. Existing evaluator, DEC register and OpenSSF summary adapter are unchanged. Synthetic fixture provenance is explicit.

## Linux controlled collector PoC

See `linux-collector-report-th.md` and `experiments/linux-collector/README.md`. The isolated Python/C research prototype includes preflight, trace parser, local binding/freshness/replay checks and controlled-workload runner. Actual ptrace and namespace probes were denied, so live collection and end-to-end execution remain blocked. Unit traces are synthetic and complete coverage is never asserted. Core, DEC and adapters remain unchanged.

## Local pipeline hardening

Current results: `pipeline-hardening-report-th.md`. Added inspection-only rawpreview command and protected local snapshot bridge to acceptance/replay, conservative PID attribution, minimal mounts, private ledger checks and staged output. Twenty Python tests include real Go executable bridge on synthetic inputs. Live sandbox and authorization remain blocked; historical reports describe earlier revisions. No existing DEC or core semantics changed.

## Phase 1–2 loss enforcement

Current state: `phase1-2-report-th.md`. Runtime remains blocked; no available Docker/Podman/QEMU or attached supported host. Collection now emits an explicit loss sidecar and strict pipeline BLOCK before ledger consumption for incomplete/ambiguous input. Producer completeness claims remain pending independent verification. Synthetic bridge behavior intentionally changed from inspection acceptance to adapter_pending_spike; existing core semantics and DEC statuses are unchanged.

## Controlled integration harness and CI alignment

Current results: `controlled-harness-report-th.md`. Added non-privileged testing Docker/Compose profile, explicit PASS/BLOCKED/FAIL live harness, controlled restricted-file/bind attempts, configuration regression tests and strict live CI job. Thirty-five Python tests and 246 Go pass events passed; real workspace harness is BLOCKED (exit 2), not PASS. No container image or external CI execution is claimed; contracts/DEC remain unchanged.
