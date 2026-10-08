# Contributing

Keep changes small and map semantic behavior to DEC/PROP/TEST/SPIKE IDs. Read docs/implementation-brief.md first. Do not turn an OPEN decision into a default. Add a blocked test and a boundary when semantics are unresolved. Never fabricate source success, coverage or completeness.

Run gofmt, go test ./..., go vet ./... and go test -race ./.... Add meaningful conformance and malformed-input tests. Explain changed behavior and evidence in review. Public APIs, final schema and releases require a separate reviewed design decision.
