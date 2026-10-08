# PROP-ATT-001: Signed attestation, trust and admission

Status: **PROPOSED — pending owner approval**

Approver: 

Documentation only. No implementation, official semantics, trust elevation or live ALLOW is authorized by this proposal. Existing DEC statuses and Foundation v0.1 scope are unchanged.

## Architecture and trust

Use established in-toto Statement/DSSE and a pinned, reviewed Go verification library; do not invent signature primitives or invoke cosign through PATH inside verification. Cosign interoperability is a future acceptance test, not an implemented feature. Core evaluation remains offline and pure. Verification receives an offline bundle plus operator-owned trust snapshot; online signing/trust distribution belongs outside Core.

Verified signature produces authenticated signer/integrity metadata only. It never changes evaluator trust level, action success, target identity or coverage. Evaluator-owned trust remains explicit; no implicit mapping to an authorization trust tier is proposed. Loss accounting is a signed collector claim, not independent completeness attestation. SPIKE-COVERAGE-001 remains unresolved.

## Ownership and snapshot contract

This is a future API requirement, not a confirmed exploit or implemented Signing boundary. Python-to-Go pipe/file delivery does not automatically share Go backing arrays. No cross-process synchronization is required solely because two languages are involved.

Bound envelope/payload size before allocation, including streaming reads and base64 expansion. At the Go admission boundary, establish exclusive ownership or synchronize with actual shared-buffer writers before copying. make+copy or bytes.Clone alone does not prevent races while the source is being copied. A Go slice is not language-enforced immutable.

Verify, hash and parse the same private bounded snapshot. Parsing the outer envelope before signature verification is limited to extracting a bounded signature/payload; unverified claims must not affect trust/admission. Do not expose writable snapshot aliases. Own or deep-copy mutable parts of the parsed model, policy and trust context; passing a struct by value does not detach nested slices/maps. Keep snapshots stable through verification, evaluation and admission commit. Snapshot creation failure resolves to Failure/BLOCK without admission state.

## Envelope profile for owner review

Require exactly one DSSE signature initially; reject zero/multiple signatures rather than select an arbitrary one. Verify DSSE payloadType exactly `application/vnd.in-toto+json` using standard pre-authentication encoding. Verify original decoded payload bytes, then parse those same privately owned snapshot bytes; never reserialize before verification. Hash original artifact/trace/payload bytes without redaction or canonical rewriting.

Statement `_type` must equal `https://in-toto.io/Statement/v1`. Require exactly one subject with exactly one digest algorithm `sha256`, 64 lowercase hex digits, matching caller-held artifact digest. Reject duplicate keys, invalid UTF-8, unknown fields and excess resources according to a documented bounded profile. Subject name is informational, not identity. This is a stricter project profile, not a claim that upstream rejects every extension field.

Predicate schema version must match a fixed approved predicateType URI exactly; final project URI and schema remain owner decisions (no deployable identifier claimed here). Required bindings: run ID, artifact digest, original trace digest, raw payload digest, collector version/binary digest and loss report digest. CAP Evidence digest is allowed only in a separately approved evidence-producing profile. Include explicit run interval and collector identity; producer timestamps remain untrusted assertions.

## Time, revocation and registry

Receive evaluation_time and expected run challenge/context from protected caller inputs. Require bounded run age, signing age, clock skew and registry validity; numeric budgets are approval gates. A re-signed old trace with a fresh producer timestamp must not gain freshness. Trusted Rekor/TSA verification can establish signing time, not actual execution time. Without authenticated execution binding, admission cannot claim fresh genuine execution.

For keyless: verify bundle chain, timestamp/log proofs and approved trust roots offline. Match issuer and subject exactly, no broad regex/prefix. Certificate validity at verified signing time is separate from current signer permission at admission. For raw keys: identify by trusted fingerprint and registry validity, not certificate CRL. CRL/OCSP applies only to an approved PKI profile; offline revocation material must be authenticated and within a freshness budget, otherwise fail closed.

Registry is operator-controlled and versioned, with active/revoked status, authorization intervals, effective revocation time and explicit key rotation. Deny new admissions from currently revoked identities even if historical signatures verify. Historic verification reports remain separate from admission. Distribution must authenticate registry updates and prevent version rollback using protected monotonic state; exact implementation remains an approval gate.

Check registry version and authorization atomically with admission using synchronized local state; a second unsynchronized read is insufficient. External registry update and database commit require a defined coordination protocol. If that cannot be guaranteed, reject admission rather than claim race-free revocation.

## Ledger and failure model

PROPOSED is a documentation lifecycle status only, with the approver field in this document. It is not an evidence state, ledger row status or manual-overrule status. No pending-evidence queue is proposed in the replay ledger. Invalid signatures must be rejected before admission writes; bounded operational diagnostics are separate from run consumption. These signature gates are future requirements, not functionality of the current unsigned inspection utility.

Consume run means committing a durable unique admission entry after all verification gates; it does not mean authorization ALLOW. Proposed tenant-scoped uniqueness is (tenant_id, run_id), plus a unique attestation digest within each tenant. Do not use only (run_id,digest) uniqueness, which permits different payloads for the same run. Run binding must compare caller expectations, not producer-supplied tenant ownership.

Commit run binding, verified digests, trust version and admission audit together in one transaction with uniqueness constraints. Concurrent replay admits at most one. Validation failure writes no admission state. Crash before commit leaves no consumed run; crash after commit is consumed even if response delivery failed. Retry queries committed status without executing again. Durable SQLite settings and busy/timeout behavior need tests; this is local protection, not distributed replay prevention. Deletion/rollback of ledger resets history unless protected storage/checkpoints are added. Multi-tenant isolation and retention must be explicitly specified before implementation.

Verification/registry/time/resource/I/O errors become an extension Failure and orchestration BLOCK; no new Core decision named BLOCK is introduced. Existing DENY stays DENY; diagnostics retain both causes without suggesting safe acceptance.

## Acceptance tests (planned, not executed)

Bounded snapshot allocation; caller mutation after handoff; synchronized shared-source copy; nested model/policy/trust alias mutation; no writable-reference escape; race detector checks of supported ownership contracts. Deliberate unsynchronized caller writes violate the API contract and must not be described as made safe by copying. Tampered artifact/trace/payload/loss report; wrong key/issuer/subject; swapped run/tenant; wrong predicate/payload type; unknown/duplicate fields; multiple signatures; expired certificate at signing time; valid historic signature but revoked current signer; skew/future/old timestamps; stale registry; key rotation; rollback attempt; revoke-before-commit race; replay/concurrent replay; I/O failure; crash before/after commit; bounded parser fuzz. Every rejected input must leave no partial admission record. No test may infer coverage or ALLOW from signature verification.

## References

- https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- https://docs.sigstore.dev/cosign/verifying/timestamps/
- https://docs.sigstore.dev/about/security/

Dependency version, payload limits, approved URI, time budgets, registry protocol and ledger durability remain explicit owner/review gates. No installed dependency or implementation is claimed.

Detailed proposed coordinator, time and crash rules: [Trust snapshot and admission](trust-admission-detail.md). Test planning: [acceptance matrix](acceptance-matrix.md).
