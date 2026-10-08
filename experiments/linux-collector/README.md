# Controlled Linux collector PoC

Research-only, PROPOSED semantics. No arbitrary package execution, CAP evidence or authorization. Requires Linux, Python 3 standard library, cc, strace and bubblewrap with working ptrace and namespaces. No network traffic leaves the isolated network namespace; workload attempts loopback only. Sandbox starts from an empty root and mounts only /usr, /bin, /lib, /lib64 read-only plus private /work, /proc, /dev and temporary /tmp. These directories are still visible; this unverified sandbox is not suitable for hostile packages. Only bundled trusted workload is supported.

Run from project root:

```sh
python3 experiments/linux-collector/collector.py probe
python3 experiments/linux-collector/collector.py collect --output /path/to/new-private-run
python3 -m unittest discover -s experiments/linux-collector -v
```

If runtime prerequisites fail, collect exits 2 with runtime_prerequisite_blocked before compiling/running any workload. There is no unsandboxed fallback. Output directory must not already exist. Successful research execution emits original trace, proposed payload, caller-side binding and report, all private files. Do not publish raw trace: it can contain paths/arguments/secrets. Fixed-code console output never prints raw stderr or trace. Run files are staged privately and committed together; injected fsync/disk-write failure leaves no partial run. A failure after destination reservation or after committed collection can still leave a directory; inspect its report before retrying with a new path.

Parser is deliberately narrow: timestamped strace -ttt -yy output; connect/bind sockaddr IP/port; read/write FD path; unlink; execve. Escaped/truncated identities, unknown calls and unfinished/resumed lines remain unsupported rather than guessed. Entry events are not silently converted into completed syscalls. Network EINPROGRESS remains attempted. Open/stat never imply content read. Original trace retains startup/sandbox events. attribution.json classifies ordered successful /work/workload exec and observed fork/clone descendants; all other events remain unattributed. Those events become unsupported in the preview payload. Missing/resumed clone records and PID namespace translation remain unresolved; attribution is not authenticated or claimed complete. Candidate timestamps are clock values, not authenticated time. No complete coverage or package-only capability claim is made.

Artifact binding hashes the compiled controlled executable before/after run, source and payload/trace. It is not archive authentication or protection against an adversarial self-modifying workload. File size/CPU/timeout limits are provisional; trace/process failures do not produce authorization. Timeout kills the tracing process group. Complete is always false; dropped=0 means no positively counted drop, not proof of loss-free collection. Unsupported/truncated parse data remains visible. Unknown observed timestamps block local acceptance.

`accept(payload, binding, database, now)` is a separate inspection API for caller-owned envelopes: checks full bytes, run/artifact/analyzer, run/event freshness and one-use run ID through SQLite uniqueness transactions. Ledger must be in a private caller-controlled directory; deleting/restoring it resets replay history. It is not cryptographic authentication or distributed replay prevention. The pipeline command invokes the real Go preview on a private payload snapshot, then the loss/ambiguity guard. Incomplete or ambiguous input is blocked before any acceptance/ledger write. Producer complete=true still yields adapter_pending_spike until independent collection verification and mapping exist. The separate accept() inspection utility remains tested but is no longer called by this pipeline. Binding file is generated locally and is not accepted as remote authentication. Synthetic payload bridge tests passed, while live collector chaining remains blocked by runtime prerequisites. The process metadata is not supplied from untrusted JSON as a trusted binding.

`testdata/runtime-probe.json` records an actual environment probe, not syscall evidence. Unit traces are synthetic. No genuine live trace fixture is included because ptrace and namespace prerequisites were denied in this environment. Workload C source passed compiler warnings-as-errors syntax checks, but was not executed here.

## One-command research pipeline

Build the preview binary into a local temporary path (not shipped in the archive):

```sh
go build -o /tmp/cap-rawpreview ./cmd/rawpreview
mkdir -m 700 /path/to/private-ledger-directory
python3 experiments/linux-collector/collector.py pipeline --output /path/to/new-run --preview /tmp/cap-rawpreview --ledger /path/to/private-ledger-directory/runs.sqlite
CAP_PREVIEW_TEST_BIN=/tmp/cap-rawpreview python3 -m unittest discover -s experiments/linux-collector -v
```

Exit 0 means inspection succeeded only, never authorization. Exit 2 means a blocker; reason codes runtime_prerequisite_blocked (use a Linux VM with working ptrace/namespaces), output_exists (choose a fresh output), preview_unavailable (build/check preview), preview_rejected (fix schema), replayed_run (do not reuse accepted run), run_not_fresh/event_outside_run (check caller time/run envelope), replay_directory_not_private/replay_store_not_private (use an owner-controlled private directory). Missing ledger or preview is rejected before collection. Do not use privileged containers as the default workaround.

Relative/symlink/interpreter identity is preserved, not resolved into authoritative identities. Network port is retained; core host-only target conversion is not enabled. Coverage is always incomplete and CAP evidence generation remains disabled. Existing Linux report is historical; current hardening results are in docs/pipeline-hardening-report-th.md.

## Phase 1–2 loss gate revision

Current pipeline deliberately has no successful authorization or acceptance route. It emits pipeline_status=BLOCK and exits 2 for runtime/loss/ambiguity blockers. Standalone rawpreview can inspect candidates, but this does not override the pipeline guard. The earlier synthetic bridge success test now expects adapter_pending_spike and verifies no ledger is created; this behavior change is explicitly authorized by the Phase 1–2 fail-closed requirement.

loss-accounting.json retains raw/event/metadata counts, parse failures, unsupported/truncated records, unattributed events and known identity ambiguities. known_dropped=null means unmeasured, completeness_verified=false. The proposed 0.1 wire coverage uses integer dropped=0 as a compatibility placeholder with complete=false, never as a loss-free attestation; the sidecar is authoritative about uncertainty. No source bytes are altered before original trace hashing. Original IPv6 spelling/ports remain intact; invalid IP text stays unsupported. Missing target resolution, symlink identity and interpreter identity remain unverified and cannot authorize.

No Docker/Podman/QEMU runtime is available in the current workspace, and ptrace/namespaces probes remain denied. Re-run probe on an operator-controlled Linux VM first. Do not bypass the environment policy or run arbitrary packages. Live timeout/sandbox descendant cleanup still needs supported-host verification. Phase 1 is blocked, not completed.

## Controlled integration harness and containers

```sh
go build -mod=vendor -trimpath -o /tmp/cap-rawpreview ./cmd/rawpreview
python3 experiments/linux-collector/harness.py --preview /tmp/cap-rawpreview --report /tmp/new-cap-live-report.json
docker compose build
docker compose run --rm collector-harness
```

Harness status/exit contract:

- PASS / 0: a genuine controlled collector execution completed, original trace/payload/source hashes match, workload exec and restricted-file/bind attempts were observed, real Go preview ran, pipeline remained BLOCK, and no ledger was created. This never means authorization ALLOW or complete syscall coverage.
- BLOCKED / 2: prerequisites are denied/unavailable; no genuine trace is claimed. On this workspace this is the actual observed result.
- FAIL / 1: empty trace, collection failure, missing controlled events, mismatched bytes, preview failure, unexpected authorization/acceptance, or output report failure. Fixed reason codes only.

The C workload attempts open(/restricted/forbidden.txt) in an empty-root sandbox, binds loopback:12345 and attempts loopback:9. These are controlled simulations of restricted actions, not malicious packages. The file is absent and must yield a failed open. No approval mapping or core policy DENY is inferred from it; the negative check is the closed pipeline BLOCK with no ledger consumption. Raw original trace retains startup/unknown events. The harness deletes private run/trace artifacts on return and only emits a sanitized summary. Live cleanup/timeout proof beyond the existing mocked tests remains pending.

Compose drops all capabilities and adds exactly SYS_PTRACE/NET_ADMIN, uses UID 10001, read-only root, bounded temporary /tmp, no host mounts or external networking. Default seccomp/AppArmor and no-new-privileges remain enabled. These capabilities do not guarantee ptrace or user/network namespace access, especially as a non-root user: unsupported policy must produce BLOCKED. No unconfined profile, SYS_ADMIN escalation or privileged fallback is configured.

Docker build/runtime was not executed in this workspace (no Docker engine). The image version tags and apt repositories are not digest/snapshot pinned; container build reproducibility and tool versions must be verified on the target host. This is a testing profile, not a production-ready service. Docker official configuration references: https://docs.docker.com/reference/compose-file/services/ and https://docs.docker.com/engine/security/seccomp/.

CI separates synthetic regression from the genuine live job. Live harness BLOCKED exits nonzero, so the live job is not green. Hosted Linux policies may block it. A manually dispatched trusted revision can target the operator-provided capspec-live runner label; PRs use the hosted runner, never that dedicated label. Dedicated runner operators must preinstall the tracing/compiler toolchain and Go prerequisites and isolate this trusted controlled workload. No sysctl/AppArmor/seccomp relaxation is performed by CI. Raw trace data is not uploaded.
