# Security review corrections — foundation-0.2

The review reproduced an authorization bug: a trusted allowed PRESENT plus in-scope UNKNOWN could become ALLOW. This revision repairs that behavior and adds mixed-bundle regressions. It replaces the earlier deliverable; earlier test counts are historical, not validation for this revision.

| Case | Corrected behavior |
| --- | --- |
| Allowed PRESENT + in-scope UNKNOWN | REVIEW |
| DENY + UNKNOWN | DENY |
| DENY + no_match | DENY; DEC-NOMATCH-001 diagnostic retained |
| ALLOW + matching DENY wildcard | DENY |
| DENY + pending platform/requirement semantics | DENY; semantic diagnostics retained |
| DENY + invalid evidence or artifact mismatch | Failure |
| PRESENT + declared ABSENT with exact same represented capability/target/scope | Failure DEC-DECLARATION-001 unless DENY already exists |
| Registered IPv4 ↔ IPv4-mapped IPv6 | DENY/REVIEW match only; no broadened ALLOW |
| Unregistered equivalence | Exact identity matching remains; no implicit unmapping |
| DENY/REVIEW rule with an os field | invalid_policy; wire presence is rejected even for empty/null values |
| Matching ALLOW with missing/mismatched OS | REVIEW, allow_requirements_unsatisfied |
| Producer changes evidence OS under DENY/REVIEW | No narrowing of the restrictive rule |
| Observed PRESENT + NOT_OBSERVED, exact same run/capability/target/scope | At least REVIEW, observation_inconsistency; existing DENY preserved |
| Different runs or negative evidence for other targets | No observation_inconsistency; unrelated negative evidence remains inert |
| UNKNOWN without basis | Accepted when reason/other applicable structural requirements hold |
| UNKNOWN with invalid supplied basis | Invalid evidence |
| Inferred PRESENT/ABSENT or supplied evidence_id | Explicit blocked boundary DEC-HASH-001; references are not accepted as verified |

Matching and conflict processing do not mutate producer evidence. Conflict detection deliberately uses exact represented assertion fields only; broader target/scope equivalence and final declaration-resolution rules remain OPEN. Unsupported or unresolvable target representations still fail whole-bundle validation; the adapter must not invent a target to avoid failure.

Old foundation-0.1 policies are rejected by the semantic-state pin. The fixture registry is re-versioned to fixture-0.2 and selects ipv4_mapped_ipv6_restrictive_v1 explicitly. Registry digests include this list, and the PATCH guard compares it. An actual capability taxonomy still requires real source data.

Regression tests are in internal/evaluate/mixed_bundle_test.go, including reversed evidence/rule order, protected input immutability, negative/unknown cases and restrictive policy additions. Existing PROP-034 is now enabled; four canonical/path properties remain skipped.

## Checks

Toolchain: Go 1.26.8, archive SHA256 verified against official Go release metadata. Tests and normal builds use CGO_ENABLED=0. Race tests use CGO_ENABLED=1 for instrumentation only.

- go test: 151 passing test/subtest/seed events; 4 skipped blocked events, no failures.
- go vet and gofmt: passed/clean.
- race: passed.
- parser and target fuzz: each passed a 10-second run.
- vendored dependencies: go mod verify passed; regenerated vendor matches all 17 files.
- Linux and Windows amd64 builds: passed; Linux smoke-tested, Windows cross-build only.
- external CI: not run; only its local equivalents were checked.

Skipped: TestBlockedConformance/PROP-002, TestBlockedConformance/PROP-024, TestBlockedConformance/PROP-025, TestBlockedConformance/PROP-027. These are dependencies on DEC-HASH-001/DEC-PATH-001, not claims of completed conformance. Exact machine-readable results are in docs/test-summary.json.

## Packaging and CI

No binaries are included. Normal build examples set CGO_ENABLED=0. Actions are pinned to verified immutable commit SHAs; Go is pinned in .go-version. CI regenerates vendor and checks tracked differences plus untracked files, and fuzzes parser and target. ubuntu-24.04 is still a managed changing runner image; this is improved reproducibility, not a hermetic build claim.

The malformed DEC-TRUST-001 example row was removed. No invented repository path, security reporting address or copyright owner is substituted. Public release blockers remain listed separately.

## Scoped follow-up and known limitations

Only platform handling, same-run observation inconsistency, their regression tests and associated register/report/manifest entries are changed in this follow-up. The older negative-invariance fixture previously used the same run/target as PRESENT; it now uses a genuinely unrelated target, while new inconsistency regressions enforce the same-run case. Monotonic addition tests isolate UNKNOWN, unmatched host, failed action, missing trust, future timestamp and out-of-scope capability. All prevent ALLOW; unrelated NOT_OBSERVED/ABSENT for another target retain it. Record order is reversed as part of the tests.

**Exact-key conflict:** assertion comparison uses capability, copied network target with target.Host normalization, and full scope including OS; other target families remain lexical. PRESENT on linux and declared ABSENT on windows are not classified as a conflict; broader canonical/security-equivalent keys are not introduced. Observation inconsistency additionally requires both records to be observed and to share a run ID. These are deliberate limits, not completed general conflict semantics.

The aggregation, platform, observation and security-equivalence records are PROPOSED — pending owner approval, with empty approver cells. No approval is asserted. DEC-FUTURE-002 is superseded by DEC-FUTURE-001 as requested; every other existing decision status is retained. The semantic-state pin, schema version, adapters, canonicalization, identity, matcher, trust, registry logic, CI, toolchain pins, module path and licensing are unchanged.


Canonical-host follow-up: case-only host differences now share conflict keys in both scans. All observation conflict groups are reported before aggregation, using per-group opaque diagnostic tokens. Producer evidence is immutable. The restrictive OS regression replacement is documented directly above TestRestrictiveRuleRejectsOS in the test suite. Canonical evidence identity, adapters, CI, module path, licensing and decision statuses are unchanged.
