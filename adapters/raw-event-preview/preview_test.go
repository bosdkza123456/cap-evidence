package raweventpreview

import (
	"bytes"
	"capevidence/internal/model"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func fixture() Input {
	yes := true
	zero := 0
	port := 443
	return Input{Version: Version, RunID: "synthetic-run", ArtifactDigest: strings64(), Analyzer: model.Analyzer{Name: "synthetic", Version: "0.1"}, Phases: []Phase{{Name: "install", Status: "completed"}}, Coverage: Coverage{&yes, &zero, &zero}, Events: []Event{{ID: "e1", Phase: "install", Operation: "connect", Result: "succeeded", Host: "API.EXAMPLE.COM", Port: &port, ObservedAt: "2026-10-08T00:00:00Z"}}}
}
func strings64() string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
func encode(in Input) ([]byte, Binding) {
	b, _ := json.Marshal(in)
	h := sha256.Sum256(b)
	return b, Binding{in.RunID, in.ArtifactDigest, hex.EncodeToString(h[:]), in.Analyzer.Name, in.Analyzer.Version}
}
func TestPreviewPreservesTargetsAndNeverAuthorizes(t *testing.T) {
	in := fixture()
	b, binding := encode(in)
	before := bytes.Clone(b)
	out, e := Inspect(b, binding, model.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if out.AuthorizationReady || len(out.Candidates) != 1 || out.Candidates[0].Host != "API.EXAMPLE.COM" || *out.Candidates[0].Port != 443 || !bytes.Equal(b, before) {
		t.Fatal("identity, port or authorization invariant broken")
	}
}
func TestOperationAndResultBoundaries(t *testing.T) {
	for _, op := range []string{"connect", "bind", "stat", "read", "write", "delete", "exec", "future"} {
		for _, result := range []string{"succeeded", "failed", "attempted", "unknown"} {
			t.Run(op+"/"+result, func(t *testing.T) {
				in := fixture()
				e := &in.Events[0]
				e.Operation = op
				e.Result = result
				if op != "connect" && op != "bind" && op != "future" {
					e.Host = ""
					e.Port = nil
					if op == "exec" {
						e.Executable = "/bin/tool"
					} else {
						e.Path = "../raw/path"
					}
				}
				b, bind := encode(in)
				out, err := Inspect(b, bind, model.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				if out.AuthorizationReady || len(out.Candidates) != 1 || out.Candidates[0].Result != result {
					t.Fatal("invented success or dropped event")
				}
				if (op == "bind" || op == "stat" || op == "future") && out.Candidates[0].Capability != "" {
					t.Fatal("incorrect capability inference")
				}
			})
		}
	}
}
func TestInvalidContractRejectsEntireInput(t *testing.T) {
	cases := map[string]func(*Input){"duplicate_event": func(i *Input) { i.Events = append(i.Events, i.Events[0]) }, "unknown_phase": func(i *Input) { i.Events[0].Phase = "missing" }, "missing_result": func(i *Input) { i.Events[0].Result = "" }, "missing_coverage": func(i *Input) { i.Coverage = Coverage{} }, "negative_drop": func(i *Input) { n := -1; i.Coverage.Dropped = &n }, "duplicate_phase": func(i *Input) { i.Phases = append(i.Phases, i.Phases[0]) }, "bad_port": func(i *Input) { n := 65536; i.Events[0].Port = &n }, "bad_timestamp": func(i *Input) { i.Events[0].ObservedAt = "bad" }, "mixed_target": func(i *Input) { i.Events[0].Path = "/other" }, "bad_digest": func(i *Input) { i.ArtifactDigest = "bad" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixture()
			mutate(&in)
			b, bind := encode(in)
			out, err := Inspect(b, bind, model.DefaultLimits())
			if err == nil || len(out.Candidates) != 0 {
				t.Fatal("partial or invalid input accepted")
			}
		})
	}
}
func TestProtectedBinding(t *testing.T) {
	for _, field := range []string{"run", "artifact", "payload", "name", "version"} {
		t.Run(field, func(t *testing.T) {
			b, bind := encode(fixture())
			switch field {
			case "run":
				bind.RunID = "other"
			case "artifact":
				bind.ArtifactDigest = "other"
			case "payload":
				bind.PayloadDigest = strings64()
			case "name":
				bind.AnalyzerName = "other"
			case "version":
				bind.AnalyzerVersion = "other"
			}
			out, e := Inspect(b, bind, model.DefaultLimits())
			if e == nil || len(out.Candidates) != 0 {
				t.Fatal("binding bypass")
			}
		})
	}
}
func TestIncompleteCoverageAndUnknownRemainVisible(t *testing.T) {
	for _, kind := range []string{"dropped", "parse", "incomplete", "failed_phase", "not_run"} {
		t.Run(kind, func(t *testing.T) {
			in := fixture()
			n := 1
			no := false
			switch kind {
			case "dropped":
				in.Coverage.Dropped = &n
			case "parse":
				in.Coverage.ParseFailures = &n
			case "incomplete":
				in.Coverage.Complete = &no
			case "failed_phase":
				in.Phases[0].Status = "failed"
			case "not_run":
				in.Phases[0].Status = "not_run"
				in.Events = nil
			}
			b, bind := encode(in)
			out, e := Inspect(b, bind, model.DefaultLimits())
			if e != nil || out.AuthorizationReady || len(out.Diagnostics) < 2 {
				t.Fatal("coverage ignored")
			}
		})
	}
}
func TestStrictAndSecretSafeFailures(t *testing.T) {
	b, bind := encode(fixture())
	for _, raw := range [][]byte{[]byte(`{"version":"x","version":"y"}`), append(bytes.Clone(b), []byte(` {}`)...), []byte(`{"environment":{"TOKEN":"secret-marker"}}`), []byte(`{"events":`)} {
		out, err := Inspect(raw, bind, model.DefaultLimits())
		if err == nil || len(out.Candidates) != 0 || bytes.Contains([]byte(err.Error()), []byte("secret-marker")) {
			t.Fatal("strictness or secret safety failure")
		}
	}
	lim := model.DefaultLimits()
	lim.Records = 0
	if _, e := Inspect(b, bind, lim); e == nil {
		t.Fatal("record limit bypass")
	}
}
func TestOrderIndependence(t *testing.T) {
	in := fixture()
	second := in.Events[0]
	second.ID = "e2"
	second.Operation = "bind"
	in.Events = append(in.Events, second)
	b, bind := encode(in)
	first, e := Inspect(b, bind, model.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	in.Events[0], in.Events[1] = in.Events[1], in.Events[0]
	b, bind = encode(in)
	other, e := Inspect(b, bind, model.DefaultLimits())
	if e != nil || first.Candidates[0] != other.Candidates[1] { // pointers have distinct addresses; compare JSON instead
		a, _ := json.Marshal(first.Candidates[0])
		c, _ := json.Marshal(other.Candidates[1])
		if e != nil || !bytes.Equal(a, c) {
			t.Fatal("order changed interpretation")
		}
	}
}
func FuzzInspect(f *testing.F) {
	b, _ := encode(fixture())
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		h := sha256.Sum256(b)
		bind := Binding{"synthetic-run", strings64(), hex.EncodeToString(h[:]), "synthetic", "0.1"}
		out, err := Inspect(b, bind, model.DefaultLimits())
		if out.AuthorizationReady || (err != nil && len(out.Candidates) != 0) {
			t.Fatal("authorization or partial failure")
		}
	})
}

func TestSyntheticFixtureFile(t *testing.T) {
	b, e := os.ReadFile("testdata/synthetic-connect.json")
	if e != nil {
		t.Fatal(e)
	}
	var in Input
	if e = json.Unmarshal(b, &in); e != nil {
		t.Fatal(e)
	}
	_, bind := encode(in)
	h := sha256.Sum256(b)
	bind.PayloadDigest = hex.EncodeToString(h[:])
	out, e := Inspect(b, bind, model.DefaultLimits())
	if e != nil || len(out.Candidates) != 1 || out.AuthorizationReady {
		t.Fatal("fixture boundary")
	}
}
func TestEventInNotRunPhaseRejected(t *testing.T) {
	in := fixture()
	in.Phases[0].Status = "not_run"
	b, bind := encode(in)
	out, e := Inspect(b, bind, model.DefaultLimits())
	if e == nil || len(out.Candidates) != 0 {
		t.Fatal("impossible phase accepted")
	}
}
