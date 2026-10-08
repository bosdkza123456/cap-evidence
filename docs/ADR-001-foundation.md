# ADR-001: Provisional internal authoring schema

No existing repository or source archive was found in the supplied workspace or project search. This is a new foundation, not a patch to an unseen repository.

Use internal types and a provisional foundation-0.2 semantic state. Candidate registry files are operator-pinned test fixtures, not an empirically verified v0.1 taxonomy. CLI computes a raw-byte SHA256 registry digest and checks the policy pin. Evidence identity is a separate pending profile.

No final no_match severity, path matcher, executable authorization, scope.os vocabulary, coverage containment algorithm, negative authorization, or OpenSSF source interpretation is introduced. Coverage supports exact scope equality only; non-identical scopes do not establish coverage. General coverage containment remains a spike dependency.

Unresolved paths fail explicitly. An established DENY survives semantic aggregation blockers, which remain visible as diagnostics. Without DENY, no_match and general conflict/declaration semantics remain explicit blockers. In-scope UNKNOWN contributes REVIEW. Requirements and declaration mismatch aggregation remain blocked.

The CLI always derives unverified trust. Go integrations may supply immutable protected evidence snapshots plus run/artifact/analyzer pipeline bindings. Matching producer metadata alone cannot confer pipeline trust. An injected platform authorization boundary is required for local ALLOW; the default vocabulary is blocked by DEC-OS-001. Producers cannot elevate trust through evidence or a CLI flag. Binding checks do not authenticate analyzer claims.

The synthetic OpenSSF fixture is deliberately not represented as real source data. Its adapter fails rather than emitting fabricated evidence.
