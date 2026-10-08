# Threat coverage and limits

| Threat | Current coverage | Remaining risk / blocker |
| --- | --- | --- |
| Malicious evidence modification | Whole-bundle validation; immutable protected content snapshot required for pipeline trust | No authenticated evidence; producer may fabricate unverified observations |
| Policy modification | Strict policy parsing, no bypass fields | Operator must protect policy; no policy signature |
| Trust-context modification | CLI has no elevation; Go context is evaluator-owned | Compromised evaluator context is outside trust boundary |
| Registry modification | Policy pins hash of raw registry bytes; PATCH guard compares represented semantics including equivalences | External registry lifecycle/version migration not implemented |
| Duplicate-key parsing | Executable JSON/YAML tests | None for accepted parser profile |
| Parser differential | JSON/YAML scalar parity tests; tags/conversions blocked | YAML node parsing happens before tree depth check |
| Resource exhaustion | Input/record/rule/tree/extension/implication limits, cycle tests, fuzz targets | Host process resource controls and YAML parser allocation remain deployment concerns |
| Output injection | JSON escaping, target-free trace, bounded capability/rule IDs, generic errors | Caller rendering must treat JSON as data |
| Stale/replayed evidence | Explicit time; stale PRESENT stays positive | Replay accepted v0.1 risk; no nonce/revocation |
| Rollback | Registry byte pin detects changed inputs | Rollback to old operator pins accepted v0.1 risk |
| Compromised analyzer | Protected snapshots; unverified ALLOW becomes REVIEW | A protected compromised analyzer may lie |
| False-positive evidence poisoning | No producer trust elevation; immutable evidence | Stale false positives can remain DENY/REVIEW; rerun/replace active input |
| Artifact TOCTOU | Open once, stream bytes, never execute/unpack | Another process may modify file while hashing or replace it afterwards; no consuming/executing artifact phase |
| Adapter corruption | Generic adapter all-or-nothing; OpenSSF fail-closed fixture | Real OpenSSF mappings are pending all SPIKE IDs |
| Extension abuse | Unknown critical rejection, reserved names/depth/cycle/size checks | Final extension registry/canonical profile pending |

Mixed uncertainty and restrictive aggregation are now regression-tested in internal/evaluate/mixed_bundle_test.go. Exact PRESENT/ABSENT conflict detection blocks ALLOW pending declaration-resolution semantics. Inferred references are blocked by DEC-HASH-001.
