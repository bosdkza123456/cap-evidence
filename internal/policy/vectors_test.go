package policy

import (
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"encoding/json"
	"os"
	"testing"
)

func TestPolicyVectors(t *testing.T) {
	var manifest []struct{ ID, Path, Expected string }
	raw, e := os.ReadFile("../../test-vectors/expected/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("bad manifest")
	}
	for _, v := range manifest {
		t.Run(v.ID, func(t *testing.T) {
			raw, e := os.ReadFile("../../" + v.Path)
			if e != nil {
				t.Fatal(e)
			}
			var p model.Policy
			e = parse.Decode(raw, "json", &p, model.DefaultLimits())
			if e == nil {
				e = Validate(p, model.DefaultLimits())
			}
			d, ok := e.(model.Diagnostic)
			if !ok || d.ReasonCode != v.Expected {
				t.Fatal(e)
			}
		})
	}
}
