# PROP-BG-001: Emergency exception procedure

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only. No implementation, official semantics, trust elevation or live ALLOW is authorized by this proposal. Existing DEC statuses and Foundation v0.1 scope are unchanged.

## Purpose and limits

No emergency bypass is currently implemented. This proposal records risk acceptance in external orchestration; it does not add an evaluator decision, change evidence, replace BLOCK/DENY with ALLOW or certify safety. It cannot unlock kernel tracing/namespaces, run unsandboxed, bypass signature/integrity checks or admit invalid evidence. Proposed eligibility is a validated, independently identified artifact blocked by an operational/policy issue; malformed, ambiguous or unbound artifacts are ineligible.

## Signed exception and external trust boundary

Require an exception token signed under dedicated exception-approval keys, separate from artifact signing and root trust-management keys. Protect key storage, rotation and current revocation checks. Root private keys must not be routine exception-signing keys. Token binds exact tenant, artifact SHA-256, job ID/action, ticket, approver identity, audience, validity interval and nonce. Verify all fields against protected caller context; expiry alone does not prevent replay.

Nonce redemption must be atomic within the authorized scope, with durable one-use state. Coordinate revocation, expiry and dispatch; remote audit, local redemption and external job execution are not one automatic database transaction. Define recoverable stages and idempotent dispatch. Failures after audit/redemption must not enable duplicate action or falsely report execution success. The coordination protocol remains an owner/review gate.

Require authenticated remote audit storage outside the collector host's trust boundary, with protected retention/integrity and a durable acknowledgment before dispatch. Merely sending a log or buffering locally is insufficient. Audit unavailability prevents exceptions. Do not log raw credentials/trace content in exception tokens or audit records.

A root-compromised enforcement host can potentially bypass local controls and suppress events. Remote audit cannot guarantee all actions were recorded, make an untrusted host truthful or undo compromise. Local append-only flags are not undeletable under root. No complete Collector monitoring claim is made; operational isolation and independent enforcement remain required threat-model decisions.

## Proposed operator procedure

1. Stop automatic retries and preserve sanitized reason, artifact digest and component versions. Investigate runtime prerequisites/configuration before requesting an exception.
2. Authorized operator creates a ticket naming exact tenant, artifact SHA-256, job/action, original result, reason, start/end time and compensating controls.
3. A separate authorized approver reviews the exception using protected identity authentication. Evidence producers cannot grant exceptions. No wildcard artifacts or global disable switch.
4. Orchestration checks current authority, scope and expiry, then obtains a durable acknowledgment of a tamper-evident remote audit event before the specified action. Audit unavailable/failed means no exception. Protect append-only storage and integrity checkpoints; an ordinary mutable log is insufficient.
5. Retain original evaluator result. Report orchestration disposition BYPASSED separately, never accepted authorization. Prevent replay/reuse outside approved job; synchronize exception use, revocation and expiry checks with action dispatch.
6. Automatically expire/revoke the exception, confirm enforcement is restored, review activity and close the ticket. Crash/restart must not extend validity or enable global bypass.

BYPASSED is a proposed orchestration disposition, not a wire value in the current evaluator. Authority model, approval quorum, eligible blocker taxonomy, audit backend, validity maximum, isolation controls and dispatch atomicity need owner approval before code.

## Planned tests

Wrong exception key/audience; revoked/rotated key; absent nonce; concurrent nonce redemption; remote audit acknowledgment lost; dispatch crash/retry/idempotency; audit storage unavailable; compromised-host limitations. Producer self-approval; wrong tenant/digest/job; missing approver/ticket; expired/revoked permission; clock skew; duplicate use; audit outage/tampering; revoke/dispatch race; process restart; fail to restore enforcement. No exception may alter original evidence bytes or consume a normal authorized-run admission entry.

Audit outage rejects the exception request, not all otherwise authorized work. Recovery/idempotency requirements are in [future backlog](extension-backlog.md); no weaker audit fallback is authorized.
