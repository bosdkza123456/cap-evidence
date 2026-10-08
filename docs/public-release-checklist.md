# Remaining public release blockers

This is an auditable research foundation, not a public production release.

1. Supply the actual repository URL/owner, then change module capevidence and all imports to the real repository module path. No placeholder GitHub identity is invented here.
2. Establish a working private vulnerability reporting channel (repository private vulnerability reporting or an owner-controlled address), then update SECURITY.md. None is currently configured.
3. Confirm the copyright owner and MIT licensing choice. The existing contributors attribution is a provisional project default, not a verified owner identity.
4. Resolve canonical hashing/Unicode/bundle ordering, then implement and verify evidence IDs and complete parent references before enabling inferred evidence. Four related canonical/path property tests remain blocked.
5. Complete path/executable/OS/taxonomy, generic requirements, declaration-conflict aggregation and future-timestamp decisions. Restrictive DENY precedence is implemented; general no_match severity without DENY remains OPEN.
6. Pinned OpenSSF source and two historical summary fixtures have been reviewed. Raw semantics, protected provenance, completeness and live integration remain unresolved; do not enable the summary adapter.
7. Run the pinned CI on the actual repository and review publication/versioning. Its configuration is present; no external run is claimed.

The archive includes no binaries. Its internal SHA256 manifest detects accidental file changes but does not authenticate the archive or include its own hash. Reproducibility pins are recorded; managed runner OS images remain mutable. Replay/rollback, compromised analyzers and artifact TOCTOU remain accepted/documented v0.1 limitations.
