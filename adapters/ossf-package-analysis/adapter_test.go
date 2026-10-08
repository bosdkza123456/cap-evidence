package ossfpackageanalysis

import (
	"capevidence/internal/model"
	"os"
	"testing"
)

func TestFixtureDoesNotInventSemantics(t *testing.T) {
	b, e := os.ReadFile("testdata/unmapped.json")
	if e != nil {
		t.Fatal(e)
	}
	out, d, e := Parse(b, model.DefaultLimits())
	if e == nil || len(out.Evidence) != 0 || len(d) == 0 {
		t.Fatal("adapter fabricated semantics")
	}
}
