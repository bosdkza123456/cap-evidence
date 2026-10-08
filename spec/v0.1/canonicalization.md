# Foundation source excerpts

Status: Semantic Design Baseline — Pre-Spike Validation. The full brief is authoritative; this is an index of verbatim requirements. Internal authoring schemas remain provisional.

# 22. Evidence identity

Current design:

```text
evidence_id =
    hash(canonical form of evidence record
         excluding evidence_id itself)
```

Identity-bearing fields include:

* run_id
* observed_at
* target
* scope
* outcome
* basis
* action
* relevant metadata
* retained extensions

`created_at` is not identity-bearing.

`derived_from` is identity-bearing where present.

Do not implement Merkle-DAG terminology yet.

The bundle canonicalization/order specification is not sufficiently frozen for that terminology.

---

# 23. Canonicalization

The implementation must have a dedicated canonicalization layer.

Do not mix canonicalization with policy evaluation.

Pipeline:

```text
input
 ↓
parse
 ↓
typed model
 ↓
semantic validation
 ↓
canonical representation
 ↓
hash / identity
```

YAML is an authoring format only.

Do not use YAML serialization itself as evidence identity.

Strict YAML parsing should reject or safely handle:

* duplicate keys
* aliases/anchors
* custom tags
* dangerous implicit conversions

The exact canonical JSON / hashing profile is still subject to final decision.

Therefore:

> Build the canonicalization interface and conformance harness now, but do not claim the exact final canonical wire profile is frozen.

---

# 24. Extensions

Extensions must be bounded.

Unknown critical extensions:

```text
→ reject
```

Unknown non-critical extensions may be preserved according to the eventual specification.

All retained extension content participates in canonical identity.

Extensions must have limits on:

* size
* nesting depth
* key count
* item count

Reserved evaluator-owned names cannot be shadowed by extensions.

For example, an extension must not redefine:

```text
trust
derived
contains_parent_reference
```

or any future evaluator-owned field.

Reserved-name collision:

```text
→ invalid_evidence
```

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

