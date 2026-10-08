# Security policy

This is a pre-spike foundation, not a production security release. Report suspected vulnerabilities privately to the repository owner; no public disclosure address has been configured. Do not post exploitable details in public issues before owner coordination.

Protect policy, registry and evaluator trust context from producer writes. Evidence is untrusted. Raw artifact hashes prove byte identity only, not analyzer execution. Replay/rollback, compromised analyzers, stale false positives and artifact replacement after hashing remain accepted/unresolved risks. There are no signatures, nonces, revocations or transparency log. The evaluator requires explicit time.

Only frozen/resolved behavior can become a stable contract. See spec/v0.1/threat-model.md and docs/implementation-report.md for coverage and remaining work.

Public publication is blocked until an owner-controlled private reporting channel is configured. No email address or repository reporting feature is asserted to exist. See docs/public-release-checklist.md.
