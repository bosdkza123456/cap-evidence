# CAP-Evidence

**Foundation evaluator + controlled Linux research harness**

> **ALLOW ≠ SAFE.** A policy decision does not certify package safety. Harness PASS does not mean authorization ALLOW.

[คู่มือเริ่มทดลองภาษาไทย](docs/quickstart-th.md) · [Implementation report](docs/implementation-report.md) · [Proposed extensions](docs/proposals/README.md)

## Start here

| Component | Current boundary |
| --- | --- |
| Core evaluator | Foundation `foundation-0.2`; unresolved decisions remain open |
| Linux harness | Bundled controlled workload only; reports PASS / BLOCKED / FAIL |
| Live pipeline | Candidate inspection; authorization mapping remains closed |
| Signing, CEL, Break Glass | Documentation proposals only; not implemented |

From the repository root on Linux, with Go, Python 3, cc, strace and bubblewrap installed:

```bash
go build -mod=vendor -trimpath -o /tmp/cap-rawpreview ./cmd/rawpreview
python3 experiments/linux-collector/collector.py probe
python3 experiments/linux-collector/harness.py --preview /tmp/cap-rawpreview
echo "exit_code=$?"
```

| Harness status | Exit | Meaning |
| --- | --- | --- |
| PASS | 0 | Genuine controlled trace and closed pipeline checks succeeded; pipeline remains BLOCK |
| BLOCKED | 2 | Runtime prerequisites unavailable/denied; no live success claimed |
| FAIL | 1 | Collection or verification checks failed; inspect sanitized reason/checks |

Kernel policy can block tracing/namespaces even when tools are installed. There is no unsandboxed fallback. `testdata/runtime-probe.json` is a historical sample, not a probe of your machine. Do not run arbitrary packages with this harness.

## Foundation baseline

**Semantic Design Baseline — Pre-Spike Validation**

CAP-Evidence is a portable capability evidence and deterministic policy evaluation foundation. It evaluates evidence against operator policy; it does not certify packages as safe.

This repository was created from the supplied implementation brief. No existing source repository was available. All wire schemas here are **provisional internal authoring schemas**, version `0.1`, semantic state `foundation-0.2`. No final v0.1 release or OpenSSF compatibility is claimed.

## Build and verify

The checked toolchain is Go 1.26.8, pinned in `.go-version`; `go.mod` retains the minimum language version 1.24. Install the pinned toolchain, then:

```bash
go mod download
go test ./...
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o bin/capevidence ./cmd/capevidence
```

Dependencies are also vendored: `go test -mod=vendor ./...` can run offline. After dependencies are downloaded, the tests and evaluator require no network access. `go.sum` pins dependency content. YAML uses `gopkg.in/yaml.v3 v3.0.1`.

## Try the example

```bash
./bin/capevidence policy check \
  --evidence spec/v0.1/examples/evidence.json \
  --policy spec/v0.1/examples/policy.yaml \
  --registry spec/v0.1/examples/registry.json \
  --artifact spec/v0.1/examples/artifact.txt \
  --evaluation-time 2026-10-08T10:00:00Z
```

Expected: `review`, exit 1. The CLI supplies unverified trust. Matching ALLOW rules do not elevate unverified evidence. `--mode audit` or `--mode inform` returns zero for completed evaluations, never for failure. Audit exit status must not be used for authorization.

An explicit `--artifact-digest sha256:...` can replace `--artifact`. File binding streams raw bytes without unpacking or execution. The explicit digest route trusts the caller's expected digest and does not inspect artifact bytes.

Protect the policy and operator registry from producer writes. The policy pins the SHA256 of the exact registry file bytes. The example registry is synthetic and provisional; it does not establish verified OpenSSF capability mappings. Whitespace changes require a new pin.

## Foundation implemented

- Strict bounded JSON and YAML authoring parsing: duplicate keys, aliases, anchors, custom tags, dangerous numeric conversions, trailing documents, unknown fields and invalid UTF-8 are rejected.
- Whole-bundle validation and constrained evidence forms; no producer-owned trust, derived assertions or derived path fields.
- Host primitives: DNS label wildcards, ASCII hostnames, IPv4 and IPv6, ambiguous-IP rejection, no port truncation.
- Raw path validation and explicit unavailable canonical/path/executable boundaries.
- Protected evaluator context, run/artifact/analyzer pipeline bindings, explicit evaluation time, stale-PRESENT diagnostics and artifact mismatch failures.
- Applicability, provisional rule matching, target-free trace, exit gating, registry pin checks, generic JSON adapter and fail-closed OpenSSF adapter boundary.
- In-scope UNKNOWN imposes at least REVIEW. Exact represented PRESENT/ABSENT conflicts block ALLOW while declaration semantics are pending.
- Explicitly registered `ipv4_mapped_ipv6_restrictive_v1` matches mapped IPv6/IPv4 for DENY/REVIEW only, without changing evidence identity.
- Evidence identity and canonicalization interfaces, property/conformance fixtures, fuzz targets, CLI tests and CI.

## Intentionally blocked

`no_match` is a classification; final severity remains DEC-NOMATCH-001. An established DENY wins over overlapping ALLOW/REVIEW and semantic aggregation blockers; unresolved allow/review-only conflicts still fail with DEC-CONFLICT-001. Genuine parse/validation/artifact/resource failures remain Failure. Canonical hashing, bundle ordering and Unicode normalization remain unselected. Path/executable authorization, future timestamps, final OS vocabulary/taxonomy, general coverage containment, declared/inferred positive authorization, requirements aggregation and OpenSSF real-data mappings are not stable implemented features. Implications have a bounded internal trace-only helper; restrictive target propagation and evaluator integration remain blocked.

See [decision register](spec/v0.1/decision-register.md), [implementation report](docs/implementation-report.md), and [source brief](docs/implementation-brief.md). Skipped conformance tests are blockers, not proof of compliance. The entire brief's Definition of Done is not yet satisfied.

## Output and limits

Exit codes: 0 = enforce ALLOW or completed audit/inform; 1 = enforce REVIEW/DENY; 2 = failure. JSON separates decision, failure, diagnostics and trace. Targets and analyzer metadata are omitted from presentation; identifiers are bounded. The core does not use filesystem, DNS, environment, system clock or network access.

Default limits: 1 MiB input, 1024 records/rules, depth 32, 16384 keys, 32768 values/items, 64 KiB retained extensions per record, pattern length 253, 1024 implication expansions and 4096 trace entries. JSON scanning enforces limits before typed decoding; YAML input size bounds parsing, then the YAML node tree is checked before conversion. The YAML library itself builds a node tree before depth checking.

## License

MIT. Governance and contribution terms are initial project defaults for review by the owner. Copyright ownership is provisional and must be confirmed by the owner before public publication. No release is published and no external account is connected.

## Review revision

This source-only package replaces the original foundation deliverable. It contains no prebuilt binaries. Inferred PRESENT/ABSENT records are now explicitly blocked by DEC-HASH-001 rather than accepting unverifiable parent references. UNKNOWN may omit basis, but must include a reason; an invalid supplied basis is rejected.

The semantic state changed from foundation-0.1 to foundation-0.2 and fixture registry pins were updated. Old policies cannot silently run under the new state. See docs/security-fix-report.md and docs/public-release-checklist.md.

`deliverable-sha256.json` checks package file integrity, excluding itself. Because it ships in the same package, it is not an authenticated trust anchor.
