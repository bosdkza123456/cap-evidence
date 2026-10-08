package identity

import (
	"capevidence/internal/model"
	"testing"
)

type captureProfile struct{ captured *model.EvidenceRecord }

func (p captureProfile) Name() string { return "test-only" }
func (p captureProfile) Record(r model.EvidenceRecord) ([]byte, error) {
	*p.captured = r
	return []byte("test"), nil
}
func (p captureProfile) Bundle(model.Bundle) ([]byte, error) { return nil, nil }

type testHasher struct{}

func (testHasher) Sum(b []byte) (string, error) { return string(b), nil }
func TestIdentityFieldBoundary(t *testing.T) {
	var got model.EvidenceRecord
	r := model.EvidenceRecord{EvidenceID: "old", CreatedAt: "yesterday", ObservedAt: "today", DerivedFrom: []string{"parent"}, Target: model.Target{Family: "network", Host: "::ffff:127.0.0.1"}, Extensions: map[string]model.Extension{"retained": {Value: "data"}}}
	if _, e := Record(r, captureProfile{&got}, testHasher{}); e != nil {
		t.Fatal(e)
	}
	if got.EvidenceID != "" || got.CreatedAt != "" || got.ObservedAt != "today" || got.Target.Host != r.Target.Host || len(got.DerivedFrom) != 1 || len(got.Extensions) != 1 {
		t.Fatal("identity field boundary lost")
	}
	if r.EvidenceID != "old" {
		t.Fatal("mutated producer record")
	}
	if _, e := Record(r, nil, testHasher{}); e == nil {
		t.Fatal("froze missing profile")
	}
}
