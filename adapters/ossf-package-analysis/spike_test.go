package ossfpackageanalysis

import (
	"bytes"
	"capevidence/internal/model"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSpikeProvenance(t *testing.T) {
	raw, err := os.ReadFile("testdata/spike/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		SourceCommit string `json:"source_commit"`
		Files        []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.SourceCommit != "c5c45008da694036d701ba76fe9567fc8a5b9675" || len(p.Files) != 14 {
		t.Fatal("unexpected provenance")
	}
	for _, f := range p.Files {
		t.Run(f.Path, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join("testdata/spike", f.Path))
			if e != nil {
				t.Fatal(e)
			}
			h := sha256.Sum256(b)
			if hex.EncodeToString(h[:]) != f.SHA256 {
				t.Fatal("fixture bytes changed")
			}
		})
	}
}

func requireBlocked(t *testing.T, b []byte) {
	t.Helper()
	before := bytes.Clone(b)
	out, d, err := Parse(b, model.DefaultLimits())
	if err == nil || len(out.Evidence) != 0 || len(d) == 0 || d[0].ReasonCode != "adapter_pending_spike" {
		t.Fatal("unresolved source semantics must remain fail-closed")
	}
	if !bytes.Equal(before, b) {
		t.Fatal("input mutated")
	}
}

func TestPublicOutputsRemainFailClosed(t *testing.T) {
	for _, name := range []string{"discordcmd-0.0.2.json", "colorsss-0.0.2.json"} {
		t.Run(name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join("testdata/spike", name))
			if e != nil {
				t.Fatal(e)
			}
			var d struct{ Analysis map[string]json.RawMessage }
			if e = json.Unmarshal(b, &d); e != nil {
				t.Fatal(e)
			}
			if len(d.Analysis) != 2 {
				t.Fatal("historical fixture phases changed")
			}
			requireBlocked(t, b)
			for phase, raw := range d.Analysis {
				t.Run(phase, func(t *testing.T) {
					var summary map[string]json.RawMessage
					if e := json.Unmarshal(raw, &summary); e != nil {
						t.Fatal(e)
					}
					for _, field := range []string{"Status", "Files", "Sockets", "Commands"} {
						if _, ok := summary[field]; !ok {
							t.Fatalf("missing source field %s", field)
						}
					}
					if _, ok := summary["Coverage"]; ok {
						t.Fatal("fixture unexpectedly provides coverage")
					}
					var wrapper map[string]json.RawMessage
					if e := json.Unmarshal(b, &wrapper); e != nil {
						t.Fatal(e)
					}
					phases, _ := json.Marshal(map[string]json.RawMessage{phase: raw})
					wrapper["Analysis"] = phases
					single, _ := json.Marshal(wrapper)
					requireBlocked(t, single)
				})
			}
		})
	}
}

// These mutations are synthetic boundary probes, not upstream observations.
func TestSpikeUnsupportedShapesDoNotFabricateEvidence(t *testing.T) {
	for name, b := range map[string][]byte{
		"unknown_event":   []byte(`{"Analysis":{"install":{"Status":"completed","FutureEvents":[{"op":"unsupported"}]}}}`),
		"unknown_phase":   []byte(`{"Analysis":{"future":{"Status":"completed"}}}`),
		"empty_completed": []byte(`{"Analysis":{"install":{"Status":"completed","Files":[],"Sockets":[],"Commands":[]}}}`),
		"failed_action":   []byte(`{"Analysis":{"install":{"Status":"error_analysis","Sockets":[{"Address":"127.0.0.1","Port":443}]}}}`),
		"malformed":       []byte(`{"Analysis":`),
	} {
		t.Run(name, func(t *testing.T) { requireBlocked(t, b) })
	}
}

func TestSpikeOversizedInputFailsClosed(t *testing.T) {
	lim := model.DefaultLimits()
	lim.InputBytes = 1
	out, _, err := Parse([]byte("{}"), lim)
	if err == nil || len(out.Evidence) != 0 {
		t.Fatal("resource limit bypass")
	}
}
