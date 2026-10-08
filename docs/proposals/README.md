# Proposed security extensions

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only. No implementation, official semantics, trust elevation or live ALLOW is authorized by this proposal. Existing DEC statuses and Foundation v0.1 scope are unchanged.

These are separate experimental extensions, not a v0.1 expansion or a custom signature protocol. Owner must choose an extension milestone or v0.2 and approve the listed decisions before code begins.

| Proposal ID | Document | Owner decisions required |
| --- | --- | --- |
| PROP-ATT-001 | [Signing and trust](signing-trust.md) | Verification profile, trust/freshness budgets, ledger retention and crash behavior |
| PROP-CEL-001 | [CEL constraints](cel-constraints.md) | Result mapping, limits, isolation and dependency version |
| PROP-BG-001 | [Break Glass](break-glass.md) | Exception authority, workflow and audit storage |

IDs are proposal tracking IDs, not replacements for existing DECs. Approvers remain blank. A signature validates a claim's origin and integrity, not its truth. Current raw preview does not produce CAP Evidence; raw payload digest must not be renamed evidence digest.

Delivery gates: document review and owner approval → implementation in a separate package → negative/property/fault-injection tests → independent review. Signing, CEL and exceptions are separate deliveries. Core exact-key isolation across scope/OS/target_scope stays unchanged; canonical host case handling is already present in internal/evaluate/canonical_conflict_test.go.

## Detailed review package

- [Trust snapshot and admission](trust-admission-detail.md)
- [Future extension backlog](extension-backlog.md)
- [Planned acceptance matrix](acceptance-matrix.md)
- [Owner decision worksheet](owner-review.md)

Audit outage rejects emergency exceptions; it does not automatically halt normally authorized work. Mock fault injection is permitted, but cannot replace genuine implementation integration tests.
