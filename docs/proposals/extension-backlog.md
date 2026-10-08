# Future extension backlog

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only; no implementation or approval claimed. Existing DECs and Foundation v0.1 remain unchanged.

These are future enhancements, not proven Foundation Core defects.

| Stage | Work | Exit gate |
| --- | --- | --- |
| 1 | Signing/revocation semantics | Owner selects profile, time budgets, snapshot authority and storage/coordination boundary |
| 2 | Signing implementation + TDD | Real cryptographic verification, atomic replay tests, race/fuzz/fault recovery and independent review |
| 3 | CEL implementation + benchmark | Approved result mapping; compile/evaluate/concurrency/cache peak memory measured on target OS; isolated worker limits enforced |
| 4 | Break Glass + recovery | Approved authority and eligible blockers; signed tokens, durable remote audit and idempotent dispatch recovery |

## CEL benchmark plan

Measure baseline worker/Core memory, compilation peaks, evaluation peaks, intermediate/result sizes, cache churn and concurrent throughput. Record pinned CEL/Go versions, OS/kernel, resource-control configuration and workload/input/expression digests. Select per-worker hard budget plus aggregate service budget, queue/concurrency/cache limits and timeout settings after measurements; no numeric MB guarantee is selected here.

Stress/OOM tests run in bounded disposable workers. Verify Core health and latency under worker loss, cleanup/reaping and bounded restart rates. Peak measurements support budget choice; enforcement tests prove the chosen limit operates on that runtime. cgroups and address-space limits need separate validation. No benchmark result exists yet.

## Durable audit and dispatch recovery

Break Glass requests alone are rejected when all approved remote audit channels are unavailable. Normally authorized work need not be blocked solely by loss of the exception audit service unless its own approved policy requires that service. No fallback to weaker local logging authorizes exceptions.

Use stable request/event IDs and idempotent audit writes. A lost acknowledgment is ambiguous: query durable audit state, or retry the same event ID; no dispatch before verified durable acknowledgment. An approved redundant audit backend must meet equivalent integrity/retention/authentication properties and preserve deduplication scope. Local buffers can aid delivery but never stand in for the required acknowledgment.

Persist recoverable stages for exception authorization, nonce redemption, acknowledged audit and dispatch intent/result. This is orchestration state, not invalid evidence admission in the replay ledger. Target execution must support idempotency/status queries or explicitly reject automatic redispatch when outcome is ambiguous. Cross-service audit/redemption/dispatch is not an automatic atomic transaction. No exactly-once external execution claim without a verified protocol. Audit outage beyond validity means the token expires; recovery must not extend it.

Mocks are appropriate for deterministic fault injection; they supplement real crypto/database/worker/backend integration tests. Neither mocks nor happy-path tests alone establish production readiness.
