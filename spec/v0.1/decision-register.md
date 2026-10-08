# Decision register

Semantic Design Baseline — Pre-Spike Validation. No final/frozen v0.1 claim.

| ID | Status | Dependency |
| --- | --- | --- |
| DEC-NOMATCH-001 | OPEN | final no_match → review or deny |
| DEC-PORT-001 | OPEN | host-only vs host+port / unsupported granularity |
| DEC-FUTURE-001 | OPEN | future observed_at behavior |
| DEC-PATH-001 | OPEN | exact raw/canonical equivalence rules |
| DEC-PATH-002 | OPEN | path trailing slash / dot / duplicate slash semantics |
| DEC-ROOT-001 | OPEN | exact broad-root ALLOW threshold |
| DEC-UNICODE-001 | OPEN | canonical Unicode normalization profile |
| DEC-CMD-001 | OPEN | executable positive authorization semantics |
| DEC-OS-001 | OPEN | final scope.os vocabulary |
| DEC-CAP-001 | OPEN | final capability taxonomy supported by real data |
| DEC-HASH-001 | OPEN | final canonical hashing profile |
| DEC-BUNDLE-001 | OPEN | final bundle canonical ordering |
| DEC-CONFLICT-001 | OPEN | final aggregate escalation semantics |
| DEC-DECLARATION-001 | OPEN | final declaration mismatch behavior |
| DEC-FUTURE-002 | SUPERSEDED | superseded by DEC-FUTURE-001 |
| SPIKE-NET-001 | PENDING_SPIKE | network target granularity |
| SPIKE-PATH-001 | PENDING_SPIKE | filesystem path representation |
| SPIKE-CMD-001 | PENDING_SPIKE | command/executable representation |
| SPIKE-ACTION-001 | PENDING_SPIKE | success/failure semantics |
| SPIKE-RUN-001 | PENDING_SPIKE | run completeness |
| SPIKE-COVERAGE-001 | PENDING_SPIKE | coverage semantics |
| SPIKE-ARTIFACT-001 | PENDING_SPIKE | artifact identity |
| SPIKE-UNKNOWN-001 | PENDING_SPIKE | failure/unsupported event representation |

Unknown noncritical extensions are retained by the provisional internal authoring profile, bounded and identity-bearing when a canonical profile is eventually selected. This is not a frozen schema.

## Foundation revision 0.2

In-scope UNKNOWN imposes at least REVIEW; established DENY takes precedence over semantic blockers and overlapping ALLOW. Genuine invalid input, artifact mismatch and resource failure remain Failure. General no_match severity and declaration-conflict resolution remain OPEN.

`ipv4_mapped_ipv6_restrictive_v1` is an explicitly registered DENY/REVIEW-only equivalence. The registry digest includes the selected equivalence list; PATCH cannot alter it. No evidence identity conversion is performed.

Inferred PRESENT/ABSENT is blocked by DEC-HASH-001 until parent identity/reference validation is possible. UNKNOWN may omit basis and must include a reason.

## Proposed decision records

These records document the requested implementation behavior. They remain **PROPOSED — pending owner approval**; implementation is not a claim of owner approval. Existing DEC statuses are unchanged except the requested supersession of DEC-FUTURE-002.

| ID | Status | Approver | Rule | Rationale | Related tests |
| --- | --- | --- | --- | --- | --- |
| DEC-AGG-001 | PROPOSED — pending owner approval | | In-scope UNKNOWN imposes at least REVIEW; established DENY survives semantic aggregation blockers/overlapping ALLOW. Genuine invalid input, artifact mismatch and resource errors remain Failure. | Uncertainty cannot preserve positive authorization; semantic blockers must not erase established DENY. | TestMixedBundles, TestMonotonicRecordAddition |
| DEC-PLATFORM-001 | PROPOSED — pending owner approval | | OS constrains ALLOW only. DENY/REVIEW rules with nonempty os are invalid_policy. Missing/mismatched evidence OS for matching ALLOW produces REVIEW with allow_requirements_unsatisfied. | Producer-controlled scope.os cannot narrow DENY/REVIEW. | TestPolicyOSValidation, TestProducerOSCannotEvadeRestrictiveRules, TestAllowOSRequirements |
| DEC-OBS-001 | PROPOSED — pending owner approval | | Observed PRESENT and NOT_OBSERVED with identical run/capability/target/scope impose at least REVIEW and observation_inconsistency. Keep DENY; different runs/unrelated targets do not trigger inconsistency. | Contradictory observations in one run cannot jointly support ALLOW; unrelated negative evidence must remain inert. | TestObservationInconsistency, TestMonotonicRecordAddition |
| DEC-EQUIV-001 | PROPOSED — pending owner approval | | Explicitly registered ipv4_mapped_ipv6_restrictive_v1 matches IPv4/mapped IPv6 for DENY/REVIEW only. No broadened ALLOW or evidence identity mutation; PATCH cannot change equivalence configuration. | Restrictive matching must not lose mapped-IP targets or weaken positive identity boundaries. | TestMixedBundles, TestEquivalencePatchGuard |
