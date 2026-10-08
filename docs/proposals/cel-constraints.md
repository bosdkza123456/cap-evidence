# PROP-CEL-001: Restrictive CEL extension

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only. No implementation, official semantics, trust elevation or live ALLOW is authorized by this proposal. Existing DEC statuses and Foundation v0.1 scope are unchanged.

## Boundary and results

CEL is an opt-in additional restriction over validated inputs, never a replacement for Foundation matching. No Rego implementation in this milestone. Disabled extension returns byte-identical existing serialized result; no extra output fields in disabled mode.

| Core state | CEL true | CEL false | CEL error/timeout/resource failure |
| --- | --- | --- | --- |
| ALLOW | ALLOW | REVIEW | Failure |
| REVIEW | REVIEW | REVIEW | Failure |
| DENY | DENY | DENY | DENY, extension error diagnostic retained |
| Failure | Failure | Failure | Failure |

All non-ALLOW states gate execution closed. Failure is an operational state, not a severity ordered below DENY. This table is proposed extension aggregation, not a change to existing DEC-CONFLICT-001. Core invalid policy/evidence is handled before CEL. Compile/type-check failure rejects policy loading, never silently disables the constraint.

## Determinism and resource limits

Pin and vendor a reviewed cel-go version before implementation; record engine version, expression bytes digest, policy/input digests and explicit evaluation_time for reproducibility. No implicit current clock, network/filesystem/env access or nondeterministic custom functions. Signer authorization comes from the single verified trust snapshot; CEL cannot maintain a second authoritative producer allowlist or raise its trust level.

Compile/type-check at policy load with expression/AST/type limits, bounded cache and compile concurrency. Limit input bytes, string lengths, collection cardinality, expression count and aggregate cost per request. Use static cost checks plus runtime cost budget and ContextEval cancellation checkpoints. Context timeout is cooperative; goroutine abandonment is not cancellation. Do not permit blocking/custom I/O functions. Bound queue length and concurrent evaluations, not just per-expression work.

50 ms is an experimental per-policy deadline candidate, not a proven guarantee. Numeric limits and benchmark targets must be approved after measurement. Include overall request and compilation budgets. For a hard wall-clock termination guarantee, choose a killable isolated worker process with cleanup and memory/CPU bounds; this is an unresolved deployment choice. Deadline failures can vary with host load and must be recorded as Failure, not described as deterministic successful evaluation.

No admission is consumed on extension error under the proposed admission transaction. CEL must complete before commit; signed report inspection that is independent of authorization must have a separate documented ledger purpose.

## Memory isolation requirements

CPU cost accounting is not a byte allocation quota. Do not assume an API named cel.MaxMemoryLimit exists. Check the pinned dependency's actual APIs during implementation. Specify limits on collection and result cardinality/bytes, comprehension nesting, string expansion, compiled-program cache bytes/entries and aggregate concurrent requests. Enforcing a result size only after allocation is insufficient; restrict allocation-producing operations and validate bounds before evaluating them.

For untrusted expressions requiring hard memory isolation, compile and evaluate in a separate killable worker, keeping Core outside the worker resource boundary. Select and test OS controls on the target runtime: cgroup memory limits and setrlimit address-space limits have different behavior and are not interchangeable. Go runtime soft memory targets do not constitute per-expression hard quotas. If required isolation is unavailable, reject the extension request; do not silently fall back to unrestricted in-process evaluation.

Run OOM/stress tests only in bounded disposable workers, never deliberately exhaust the host/Core. Record peak memory, termination reason and whether Core remains responsive. Worker OOM, abrupt exit, timeout or cleanup failure must gate closed as an extension Failure, retaining an existing DENY. Reap descendants, bound worker restart rate/queue/cache and verify repeated failures do not leak resources. Host scheduling/OS kill timing prevents a universal exact wall-clock guarantee; document the verified runtime boundary and budgets.

## Planned tests

Worker OOM and peak-memory measurements; Core responsiveness during worker loss; oversized intermediate map results; nesting and cache churn; unsupported isolation; repeated worker cleanup/restart limits; compile-stage memory pressure. Compile/type error; false/true/nonboolean output; oversized inputs; regex/string and nested collection stress; runtime cost limit; deadline/cancel; queue saturation; worker cleanup/no accumulating goroutines; pin/version drift; evaluation_time repeatability; trust source consistency. Properties: adding a constraint never relaxes the outcome, DENY retained on all error branches, disabled result byte-identical. These are acceptance requirements, not new passing tests.

Reference: https://pkg.go.dev/cel.dev/cel-go/cel
