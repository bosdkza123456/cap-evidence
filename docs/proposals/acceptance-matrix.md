# Planned acceptance matrix

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only; no implementation or approval claimed. Existing DECs and Foundation v0.1 remain unchanged.

All rows are planned, NOT EXECUTED for these extensions. Failure below means extension Failure plus closed orchestration gate; an established Core DENY is retained. These do not change existing DEC semantics.

| ID | Input / scenario | Expected result | State invariant | Required test mode |
| --- | --- | --- | --- | --- |
| ATT-01 | Real valid signature and approved snapshot/binding | Verified inspection only; no trust/coverage elevation | At most one admission only when all gates pass | Real crypto + database |
| ATT-02 | Altered signature, payload or digest | Failure/BLOCK | No admission row | Real crypto negative tests |
| ATT-03 | Wrong issuer/subject/key/purpose/tenant | Failure/BLOCK | No cross-tenant admission | Real verification |
| ATT-04 | Duplicate fields, wrong profile, multiple signatures, oversized envelope | Failure/BLOCK | No admission; bounded allocation | Parser tests + fuzz |
| ATT-05 | Caller changes original buffer/model after owned handoff | Result uses snapshot or rejects invalid handoff | Verified and processed bytes identical | Real ownership tests + race detector |
| ATT-06 | Snapshot invalid signature, expired/too old/future interval | Failure/BLOCK | No admission; no invalid trust install | Real crypto + explicit clock fixtures |
| ATT-07 | Lower snapshot version / same version different digest | Failure/BLOCK | High-water never decreases | Durable store integration |
| ATT-08 | Fresh signature over old run; producer timestamp rewritten | Failure/BLOCK when protected freshness fails | No admission | Real signing + protected binding fixtures |
| ATT-09 | Revoked signer, scheduled effective time, key rotation | Exact approved interval rule; revoked signer rejected | No unauthorized admission | Real verification + time boundary tests |
| ATT-10 | Revocation/generation/expiry changes before commit | Restart within bounds or Failure/BLOCK | No commit under stale permission | Real concurrent coordinator/store tests |
| ATT-11 | Concurrent same tenant/run; different payload same run | At most one valid admission | Unique run; no partial rows | Real database concurrency |
| ATT-12 | Crash before/after commit; acknowledgment lost | Recover durable status; no execution retry | No partial row / committed run remains consumed | Subprocess crash tests + injected I/O |
| ATT-13 | Ledger/high-water rollback/deletion | Report documented protection boundary; reject detectable inconsistency | No false replay guarantee | Real storage recovery tests |
| CEL-01 | true/false/nonboolean/compile or type error | Approved result table; no relaxation | DENY retained; error consumes no admission | Real pinned CEL |
| CEL-02 | Large map/nested comprehensions/cache/concurrency | Bounded result or resource Failure | Core responsive; no leaks | Bounded worker benchmark/integration |
| CEL-03 | Worker timeout/OOM/abrupt exit | Failure/BLOCK | Reaped worker; no admission | OS-enforced subprocess stress |
| CEL-04 | CEL disabled / constraint added | Byte-identical disabled output / no relaxed outcome | Core semantics unchanged | Golden/property tests |
| BG-01 | Wrong key/audience/scope/expired or revoked exception | Exception rejected | No dispatch; no authorized-run admission | Real token verification |
| BG-02 | Concurrent nonce replay | At most one redemption/eligible dispatch | Durable unique nonce | Real concurrent store/dispatcher |
| BG-03 | Audit outage or lost acknowledgment | Reject or recover acknowledged event before dispatch | No dispatch without durable acknowledgment | Fault injection + real audit integration |
| BG-04 | Crash at redemption/audit/dispatch boundary | Idempotent recovery or explicit ambiguous outcome | No blind duplicate dispatch | Subprocess faults + real status/idempotency backend |
| BG-05 | Root-compromised collector boundary | No complete-monitoring claim | Remote audit not treated as proof of all host activity | Threat-model review; bounded integration where applicable |

Clock fixtures test boundary semantics; operational clock authenticity and remote backend durability require separate deployment review. Unsynchronized arbitrary writes inside the verifier process violate the ownership contract and cannot be made safe by a copy or mock.
