package identity

import (
	"capevidence/internal/canonical"
	"capevidence/internal/model"
)

// Hasher is injected; no final hashing or canonical profile is selected by foundation code.
type Hasher interface{ Sum([]byte) (string, error) }

func Record(r model.EvidenceRecord, p canonical.Profile, h Hasher) (string, error) {
	if p == nil || h == nil {
		return "", model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-HASH-001"}
	}
	r.EvidenceID = ""
	r.CreatedAt = ""
	b, e := p.Record(r)
	if e != nil {
		return "", e
	}
	return h.Sum(b)
}
