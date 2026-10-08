package genericjson

import (
	"capevidence/internal/model"
	"os"
	"testing"
)

func TestAllOrNothing(t *testing.T) {
	b, e := os.ReadFile("../../test-vectors/evidence/observed-present.json")
	if e != nil {
		t.Fatal(e)
	}
	out, _, e := Parse(b, model.DefaultLimits())
	if e != nil || len(out.Evidence) != 1 {
		t.Fatal(e)
	}
	bad, e := os.ReadFile("../../test-vectors/evidence/producer-trust.json")
	if e != nil {
		t.Fatal(e)
	}
	out, _, e = Parse(bad, model.DefaultLimits())
	if e == nil || len(out.Evidence) > 0 {
		t.Fatal("adapter leaked partial evidence")
	}
}
