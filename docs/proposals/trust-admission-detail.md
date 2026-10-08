# PROP-ATT-001 supplement: Trust snapshot and admission flow

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only; no implementation or approval claimed. Existing DECs and Foundation v0.1 remain unchanged.

## Proposed snapshot contract

The offline verifier receives a bounded, authenticated snapshot from orchestration and a protected evaluation_time. Snapshot authentication authority is separate from evidence producers and exception approvers. Bootstrap trust roots are operator provisioned; the snapshot must not authorize its own signing root. Root rotation needs authenticated continuity and operator recovery, not acceptance of an arbitrary root inside an incoming snapshot.

| Field / input | Proposed validation |
| --- | --- |
| schema/profile version | Exact approved identifier; unsupported version rejected |
| tenant/domain and purpose | Match caller-held scope; no producer-selected authority |
| snapshot version / digest | Monotonic version with protected high-water state; same version with different bytes rejected |
| issued_at, not_before, expires_at | Authenticated snapshot claims; compare to explicit protected evaluation_time |
| signer entries | Exact raw-key fingerprint or exact keyless issuer/subject; purpose and validity interval |
| revocation entries | Identity/key, effective time and status; current permission separate from historic signature validity |
| trust roots / timestamp authorities | Operator-approved scope, authenticated distribution; no implicit root elevation |
| signature metadata | Approved standard format/algorithm and pinned implementation, still awaiting selection |

This table defines requirements, not a frozen JSON schema. Wire representation, limits and dependency versions need owner review. Unknown/duplicate fields, oversized data and invalid signatures must be rejected under the approved bounded profile.

Orchestration fetches authenticated updates outside Core. Local admission coordinator installs a snapshot version and revocations together under synchronization. Persist its high-water version before permitting use of a newer registry; failed installation must not fall back to a lower version. High-water storage rollback/deletion is an explicit limitation unless independently protected. A producer cannot supply the trusted evaluation_time or reset the high-water state.

## Time and revocation rules

Snapshot validity is proposed as not_before <= evaluation_time < expires_at, with issued_at <= evaluation_time + approved clock-skew tolerance. Also check maximum snapshot age; signed expiry is not permission to exceed the operator's age budget. Negative age outside skew, inconsistent intervals and absent required trusted time fail closed.

Separate these time domains: certificate/signature validity at independently verified signing time; authenticated run context and permitted run age; snapshot currency; admission commit time. Producer observed_at is not trusted execution time. Reject re-signed old traces unless the protected run binding independently satisfies the approved freshness profile. No coverage inference from any timestamp.

A newly installed revocation takes effect at its specified effective time; reject new admissions once active, even if the historic signature verified. Future scheduled revocations are not immediate unless the approved compromise policy explicitly requires immediate withdrawal. Compromise recovery is a higher-version update, never editing a previously accepted version. Rotation introduces an explicitly authorized new key; it does not automatically restore a revoked old key.

Offline revocation has a bounded observation delay, not an instantaneous guarantee. Owner must choose update interval, maximum snapshot age, skew budget and monitoring/propagation targets. State whether the bound begins at authority publication or compromise detection; detection latency cannot be guaranteed by this verifier. Update failures allow only an authenticated snapshot still inside the approved age/validity budget; after expiry no new admissions. No stale grace period is implied.

Refresh protected admission time under the same coordinator before commit; pure verification keeps its explicit input time. A snapshot or signer interval that expires during long verification must cause restart/rejection at commit, not acceptance using an earlier timestamp. Coordinate snapshot installation and commit by a local lock/transaction fence held through durable commit; distributed coordinators need an explicit fencing/consensus design before deployment. Unknown coordination guarantees mean reject, not claim immediate distributed revocation.

## Proposed admission sequence

1. Bound request and obtain private owned bytes plus protected tenant/run/artifact context. No producer-controlled trust or mutable aliases.
2. Authenticate snapshot, validate purpose/time/version against protected high-water state; capture coordinator generation.
3. Verify attestation signature and exact signer permission using the snapshot; parse only the verified private payload after bounded envelope extraction.
4. Check artifact/trace/payload/loss-report digests, predicate profile, run binding and trusted-time freshness. Signature success remains integrity/authentication only.
5. Apply any independently approved restrictions before admission. Current candidate mapping remains closed; this sequence does not enable CAP Evidence generation or live ALLOW.
6. Acquire commit coordination fence, refresh explicit admission time and recheck registry generation/current permission/expiry. If changed, restart bounded verification or reject. Enforce tenant/run and attestation uniqueness.
7. Atomically commit admission binding, snapshot version and admission audit in the local ledger. This audit is not a Break Glass remote audit. No invalid-envelope rows or pending-evidence queue.
8. Return inspection admission status only. A committed entry remains consumed if response delivery fails; retry inspects existing status and never executes again.

No state from an invalid envelope enters replay admission rows. Independently authenticated snapshot updates may advance trust high-water state even when a later envelope is rejected; this is separate trust maintenance, not partial evidence admission. This distinction must be reflected in tests.

## Crash and retry boundaries

| Failure point | Required recovery |
| --- | --- |
| Before admission transaction commit | No run consumed; reject/retry only after gates |
| Commit returned definite failure | No partial rows; inspect database errors safely |
| Commit result ambiguous / response lost | Query durable admission status by protected tenant/run; do not assume rollback |
| After durable commit | Run consumed; idempotent inspection response, no duplicate execution |
| Trust installation crash | Recover durable high-water state; never silently accept older snapshot |
| Ledger/high-water deletion or rollback | Protection not guaranteed; fail recovery checks where detectable and document storage threat boundary |

Admission ledger is not a package execution queue. Safe distributed exactly-once execution is not claimed.

See [acceptance matrix](acceptance-matrix.md) and [owner review](owner-review.md).
