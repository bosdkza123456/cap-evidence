# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 28. Target model — what can be implemented now

Some target semantics are sufficiently defined to create interfaces and conformance tests.

## Network

Current baseline:

```text
network.outbound
target = host
```

This is a current normative baseline, NOT an irrevocably frozen decision.

The OpenSSF spike may invalidate it.

Do not silently strip a port from source data and authorize only the host.

If input contains unsupported granularity such as:

```text
example.com:443
```

the adapter/evaluator must not truncate it to:

```text
example.com
```

for authorization.

Exact handling is subject to:

```text
DEC-PORT-001
```

---

# 29. Hostname glob

v0.1 baseline:

```text
*
```

means exactly one complete DNS label.

Examples:

```text
*.example.com
```

matches:

```text
api.example.com
www.example.com
```

does not match:

```text
example.com
a.b.example.com
```

No substring wildcard.

No:

```text
ab*
*a
a*b
```

No regex.

No character classes.

No brace expansion.

Invalid/unsupported pattern:

```text
→ invalid_policy
```

Never best-effort.

Matching must be resource-bounded.

---

# 30. DNS / IDNA

Current baseline:

* ASCII hostnames supported
* IDNA A-labels supported
* raw Unicode hostnames rejected

Do not implement a custom IDNA interpretation without a dedicated decision.

DNS identity rules must remain deterministic.

---

# 31. DNS underscore baseline

Current baseline:

```text
_dmarc.example.com
```

may be accepted.

But:

```text
_sip._tcp.example.com
```

is not accepted under the current v0.1 baseline.

Likewise:

```text
a_b.example.com
```

is invalid.

Wildcard ALLOW must not unintentionally cover underscore labels.

This remains a source/target-model area that may be refined before semantic freeze.

---

# 32. IPv4

Use canonical dotted-decimal IPv4.

Reject ambiguous forms such as:

```text
127.1
0x7f.1
octal-style representations
```

Do not interpret ambiguous numeric host forms differently depending on platform/library.

---

# 33. IPv6

Use deterministic canonical IPv6 representation.

Zone identifiers such as:

```text
fe80::1%eth0
```

are rejected in v0.1.

IPv4-mapped IPv6 remains a distinct canonical identity:

```text
::ffff:127.0.0.1
```

is NOT the same evidence identity as:

```text
127.0.0.1
```

However, a future/security-equivalence matcher may use:

```text
IPv4-mapped IPv6 ↔ IPv4
```

for DENY/REVIEW matching.

It must NOT change evidence identity.

---

# 34. Path model

Current baseline:

* lexical normalization only
* no filesystem resolution
* no symlink resolution
* no bind-mount inference
* no cwd inference
* no `~` expansion
* relative paths are invalid evidence in the core baseline
* NUL/control characters are invalid

Raw path must be preserved.

Canonical path is evaluator-derived.

`contains_parent_reference` is evaluator-derived from raw input.

Producer MUST NOT set it.

If raw input contains:

```text
..
```

it cannot be used as the basis for ALLOW.

DENY/REVIEW may inspect both raw and canonical representation.

The exact equivalence rules for:

```text
/tmp/a
/tmp/./a
/tmp//a
/tmp/a/
```

remain subject to the path decisions.

Do not silently invent extra equivalence rules.

---

# 35. Path authorization asymmetry

The intended security principle is:

```text
ALLOW:
    raw semantics must be safe
    AND
    canonical semantics must match

DENY / REVIEW:
    may inspect raw OR canonical forms
```

This is deliberately conservative.

Do not weaken ALLOW by adding broad normalization.

---

# 36. Windows path security

Do not authorize the following in v0.1 ALLOW semantics unless explicitly covered by a future target decision:

```text
UNC paths
\\?\ paths
\\.\ paths
alternate data streams
drive-relative paths such as C:foo
short-name forms such as PROGRA~1
```

Windows-specific normalization is an open area.

Do not create fake portability by simply replacing `\` with `/`.

---

# 37. Universal ALLOW

Universal target patterns must not produce ALLOW.

Examples:

```text
*
*.*
within("/")
within("com")
```

are not valid positive authorization patterns where they cover universal/broad target space.

DNS ALLOW wildcard baseline:

A wildcard ALLOW should contain a sufficiently specific literal suffix.

For example:

```text
*.example.com
```

is allowed.

Patterns such as:

```text
*.com
*
*.*
```

are not valid ALLOW patterns.

---

# 38. Security equivalence

Canonical identity and security matching are separate.

Canonical identity determines:

* evidence_id
* digest
* audit identity
* conflict identity

Security equivalence may be used only where explicitly registered.

Current intended example:

```text
IPv4-mapped IPv6 ↔ IPv4
```

for:

```text
DENY / REVIEW
```

It must NOT:

* change evidence identity
* create ALLOW
* broaden positive authorization

Adding/removing/changing security equivalence must be versioned.

---

# 39. Capability taxonomy

Keep capability names separate from target families.

For example:

```text
process.spawn
system.command
```

are capabilities.

They are not automatically target families.

Candidate capability taxonomy:

```text
network.outbound
network.inbound
filesystem.read
filesystem.write
process.spawn
system.command
environment.read
credential.access
```

IMPORTANT:

Do not assume every candidate capability belongs in v0.1.

Capability mappings must be supported by real source evidence.

Unsupported capabilities must be removed or marked unavailable rather than guessed.

---

# 40. Executables / commands

Do NOT assume:

```text
executable.name
```

alone can create ALLOW.

No PATH lookup.

No symlink resolution.

No command-intent inference.

Arguments are not currently a target representation.

The exact positive authorization semantics for executable paths remain OPEN.

Therefore create interfaces and tests around executable targets, but do not finalize a path-only ALLOW model.

---

# 41. Platform

Platform is derived from evidence scope:

```text
scope.os
```

It is not a producer-controlled target attribute.

`scope.os` participates in evidence identity.

Policy may specify platform requirements.

If policy omits platform:

> Do not allow unknown platform information to broaden ALLOW.

If policy specifies a platform:

```text
evidence.scope.os
```

must satisfy that requirement.

The exact allowed `scope.os` vocabulary is still subject to formalization.

---

