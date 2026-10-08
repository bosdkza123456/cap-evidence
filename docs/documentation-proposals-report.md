# Documentation and extension proposal delivery — 2026-10-08

Scope: README/Thai quickstart refresh and documentation-only Signing/Revocation, CEL and Break Glass proposals. No Signing/CEL/bypass implementation, no contract approval and no original DEC changes.

Verified this delivery:
- Go test -mod=vendor ./... passed. Existing count remains 246 pass events / 4 skips; no tests added by documentation changes.
- Go vet passed; Go race suite passed (cached results reused because code/dependencies unchanged).
- Python integration suite: 39 tests passed with real preview binary. The printed harness_report_write_failed line is an expected injected negative test, not a suite failure.
- Preview and Core CLI builds passed. Example returned REVIEW, exit 1 as documented.
- Real probe: tracing blocked, sandbox blocked, compiler available. Live harness returned BLOCKED/runtime_prerequisite_blocked with no genuine trace claimed. User-supplied earlier Codespaces PASS is not a rerun in this environment.
- Canonical conflict fuzz: 9,812 executions over a requested 5-second campaign, passed. This is not Signing/CEL fuzz coverage.
- Markdown fences and relative links checked. Windows commands inspected only; Windows runtime and Docker were not executed here.

Proposal review gates are explicit: owner chooses extension milestone; approves trust/freshness/revocation, admission transaction and CEL result/limit models. Fixed predicate URI, dependencies and numeric budgets are not selected silently. Acceptance tests in proposals are planned, not claimed passing.

Scope audit compared SHA-256 against the pre-edit snapshot: only existing README.md and docs/quickstart-th.md changed before report/manifest generation. Core, canonical conflict tests, original DEC, existing specs, Collector, Harness, Bridge/Ledger, CI, module, license and vendor remained byte-identical. Exact-key isolation remains intentional; canonical host case handling remains implemented.

Known limitations: no authenticated live authorization mapping; coverage and target identity remain unresolved; local replay storage deletion/rollback limitation persists; proposal mechanisms are not deployed. ALLOW ≠ SAFE; harness PASS is collection plus closed mapping, not safety certification.
