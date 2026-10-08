// Package canonical separates identity representation from authorization and security matching.
package canonical

import "capevidence/internal/model"

// Profile must be chosen after DEC-HASH-001 and DEC-UNICODE-001 are resolved.
type Profile interface {
	Name() string
	Record(model.EvidenceRecord) ([]byte, error)
	Bundle(model.Bundle) ([]byte, error)
}
type PendingProfile struct{}

func (PendingProfile) Name() string { return "pending" }
func (PendingProfile) Record(model.EvidenceRecord) ([]byte, error) {
	return nil, model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-HASH-001"}
}
func (PendingProfile) Bundle(model.Bundle) ([]byte, error) {
	return nil, model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-BUNDLE-001"}
}
