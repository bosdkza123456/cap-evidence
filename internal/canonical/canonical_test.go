package canonical

import (
	"capevidence/internal/model"
	"testing"
)

func TestPendingProfile(t *testing.T) {
	p := PendingProfile{}
	if _, e := p.Record(model.EvidenceRecord{}); e == nil {
		t.Fatal("froze hashing")
	}
	if _, e := p.Bundle(model.Bundle{}); e == nil {
		t.Fatal("froze bundle order")
	}
}
