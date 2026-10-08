package validate

import (
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConformanceVectors(t *testing.T) {
	var manifest []struct {
		ID    string `json:"id"`
		Path  string `json:"path"`
		Valid bool   `json:"valid"`
	}
	root := "../../"
	b, e := os.ReadFile(filepath.Join(root, "test-vectors/expected/evidence.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &manifest); e != nil {
		t.Fatal(e)
	}
	for _, v := range manifest {
		t.Run(v.ID, func(t *testing.T) {
			raw, e := os.ReadFile(filepath.Join(root, v.Path))
			if e != nil {
				t.Fatal(e)
			}
			var bundle model.Bundle
			e = parse.Decode(raw, "json", &bundle, model.DefaultLimits())
			if e == nil {
				e = Bundle(bundle, model.DefaultLimits())
			}
			if (e == nil) != v.Valid {
				t.Fatal("unexpected vector result", e)
			}
		})
	}
}

func TestEvaluatorOwnedReasonCodes(t *testing.T) {
	for _, field := range []string{`"trust":"pipeline_local"`, `"kind":"derived"`, `"contains_parent_reference":false`} {
		var b model.Bundle
		e := parse.Decode([]byte("{"+field+"}"), "json", &b, model.DefaultLimits())
		d, ok := e.(model.Diagnostic)
		if !ok || d.ReasonCode != "invalid_evidence" {
			t.Fatal("wrong evaluator-owned field failure", e)
		}
	}
}
func TestExtensionDepthAndCycle(t *testing.T) {
	root := map[string]any{}
	cursor := root
	for i := 0; i < 40; i++ {
		next := map[string]any{}
		cursor["nested"] = next
		cursor = next
	}
	if !unsafeExtension(root, model.DefaultLimits()) {
		t.Fatal("unbounded extension depth")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if !unsafeExtension(cycle, model.DefaultLimits()) {
		t.Fatal("unbounded extension cycle")
	}
}
