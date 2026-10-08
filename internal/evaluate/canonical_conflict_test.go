package evaluate

import (
	"capevidence/internal/model"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func negativeObservation(r model.EvidenceRecord) model.EvidenceRecord {
	r.Target.Host = strings.ToUpper(r.Target.Host)
	r.Outcome = model.NotObserved
	r.Action = ""
	run := *r.Run
	run.Coverage = []model.Coverage{{Capability: r.Capability, Scope: r.Scope}}
	r.Run = &run
	return r
}
func conflictDiagnostics(r model.Result, reason string) []model.Diagnostic {
	out := []model.Diagnostic{}
	for _, d := range r.Diagnostics {
		if d.ReasonCode == reason {
			out = append(out, d)
		}
	}
	return out
}
func TestCanonicalHostObservationKeys(t *testing.T) {
	for _, kind := range []string{"same_run", "deny", "different_run", "different_os", "different_target_scope"} {
		t.Run(kind, func(t *testing.T) {
			b, p, c := fixture()
			negative := negativeObservation(b.Evidence[0])
			want := model.Review
			conflict := true
			switch kind {
			case "deny":
				p.Rules[0].Effect = model.Deny
				want = model.Deny
			case "different_run":
				negative.Run.ID = "other-run"
				want = model.Allow
				conflict = false
			case "different_os":
				negative.Scope.OS = "windows"
				negative.Run.Coverage[0].Scope = negative.Scope
				want = model.Allow
				conflict = false
			case "different_target_scope":
				negative.Scope.TargetScope = "different-scope"
				negative.Run.Coverage[0].Scope = negative.Scope
				want = model.Allow
				conflict = false
			}
			b.Evidence = append(b.Evidence, negative)
			before, _ := json.Marshal(b)
			r := Check(b, p, c)
			if r.Failure != nil || r.Decision != want {
				t.Fatal(r)
			}
			diagnostics := conflictDiagnostics(r, "observation_inconsistency")
			if (len(diagnostics) == 1) != conflict {
				t.Fatal("conflict diagnostic", diagnostics)
			}
			if conflict && len(diagnostics[0].ConflictKey) != 71 {
				t.Fatal("missing bounded conflict token")
			}
			if !reflect.DeepEqual(r, reversedResult(b, p, c)) {
				t.Fatal("record order changed diagnostic")
			}
			after, _ := json.Marshal(b)
			if string(before) != string(after) {
				t.Fatal("mutated producer evidence")
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "api.example.com") || strings.Contains(string(raw), "API.EXAMPLE.COM") {
				t.Fatal("target leaked in diagnostics")
			}
		})
	}
}
func TestCanonicalHostDeclarationKeys(t *testing.T) {
	for _, kind := range []string{"conflict", "deny", "different_os", "different_target_scope"} {
		t.Run(kind, func(t *testing.T) {
			b, p, c := fixture()
			e := b.Evidence[0]
			e.Target.Host = "API.EXAMPLE.COM"
			e.Basis = model.Declared
			e.Outcome = model.Absent
			e.Action = ""
			e.Run = nil
			e.DeclarationSource = "manifest"
			want := model.Decision("")
			conflict := true
			switch kind {
			case "deny":
				p.Rules[0].Effect = model.Deny
				want = model.Deny
			case "different_os":
				e.Scope.OS = "windows"
				want = model.Allow
				conflict = false
			case "different_target_scope":
				e.Scope.TargetScope = "different-scope"
				want = model.Allow
				conflict = false
			}
			b.Evidence = append(b.Evidence, e)
			before, _ := json.Marshal(b)
			r := Check(b, p, c)
			if r.Decision != want {
				t.Fatal(r)
			}
			if kind == "conflict" && (r.Failure == nil || r.Failure.DecisionID != "DEC-DECLARATION-001") {
				t.Fatal("conflict silently authorized")
			}
			if kind != "conflict" && r.Failure != nil {
				t.Fatal(r)
			}
			d := conflictDiagnostics(r, "declaration_conflict")
			if (len(d) == 1) != conflict {
				t.Fatal("declaration diagnostic", d)
			}
			if !reflect.DeepEqual(r, reversedResult(b, p, c)) {
				t.Fatal("declaration order dependent")
			}
			after, _ := json.Marshal(b)
			if string(before) != string(after) {
				t.Fatal("evidence mutated")
			}
		})
	}
}
func TestAllObservationGroupsReported(t *testing.T) {
	for _, deny := range []bool{false, true} {
		b, p, c := fixture()
		base := b.Evidence[0]
		b.Evidence = nil
		p.Rules = nil
		for i, host := range []string{"api.example.com", "www.example.com", "files.example.com"} {
			e := base
			e.Target.Host = host
			e.Scope.TargetScope = host
			b.Evidence = append(b.Evidence, e, negativeObservation(e))
			effect := model.Allow
			if deny && i == 2 {
				effect = model.Deny
			}
			p.Rules = append(p.Rules, model.Rule{ID: []string{"rule-a", "rule-b", "rule-c"}[i], Capability: e.Capability, Effect: effect, Target: e.Target})
		}
		pinEvidence(b, &c)
		r := Check(b, p, c)
		want := model.Review
		if deny {
			want = model.Deny
		}
		if r.Failure != nil || r.Decision != want {
			t.Fatal(r)
		}
		d := conflictDiagnostics(r, "observation_inconsistency")
		if len(d) != 3 {
			t.Fatal("scan stopped before reporting all keys", d)
		}
		seen := map[string]bool{}
		for _, item := range d {
			if len(item.ConflictKey) != 71 || seen[item.ConflictKey] {
				t.Fatal("missing/distinct conflict keys")
			}
			seen[item.ConflictKey] = true
		}
		if !reflect.DeepEqual(r, reversedResult(b, p, c)) {
			t.Fatal("group reporting order dependent")
		}
	}
}
func TestConflictKeyNormalizationBoundary(t *testing.T) {
	b, _, _ := fixture()
	left := b.Evidence[0]
	right := left
	right.Target.Host = "API.EXAMPLE.COM"
	a, e := conflictKey(left, true)
	if e != nil {
		t.Fatal(e)
	}
	bb, e := conflictKey(right, true)
	if e != nil || a != bb {
		t.Fatal("network case was not normalized")
	}
	if right.Target.Host != "API.EXAMPLE.COM" {
		t.Fatal("host mutated")
	}
	left.Target = model.Target{Family: "filesystem", Path: "/tmp/A"}
	right.Target = model.Target{Family: "filesystem", Path: "/tmp/a"}
	a, _ = conflictKey(left, true)
	bb, _ = conflictKey(right, true)
	if a == bb {
		t.Fatal("path semantics changed")
	}
	left.Target = model.Target{Family: "executable", Name: "Tool"}
	right.Target = model.Target{Family: "executable", Name: "tool"}
	a, _ = conflictKey(left, true)
	bb, _ = conflictKey(right, true)
	if a == bb {
		t.Fatal("executable semantics changed")
	}
	left.Target = model.Target{Family: "network", Host: "127.0.0.1"}
	right.Target = model.Target{Family: "network", Host: "::ffff:127.0.0.1"}
	a, _ = conflictKey(left, true)
	bb, _ = conflictKey(right, true)
	if a == bb {
		t.Fatal("security equivalence changed key identity")
	}
}
func FuzzCanonicalConflictHost(f *testing.F) {
	for _, s := range []string{"api.example.com", "API.EXAMPLE.COM", "2001:DB8::1", "127.1", "::ffff:127.0.0.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if len(host) > 1024 {
			return
		}
		e := model.EvidenceRecord{Capability: "network.outbound", Target: model.Target{Family: "network", Host: host}, Scope: model.Scope{OS: "linux", TargetScope: "unchanged"}, Run: &model.Run{ID: "run"}}
		before, _ := json.Marshal(e)
		a, err := conflictKey(e, true)
		if err != nil {
			return
		}
		e.Target.Host = strings.ToUpper(host)
		b, err := conflictKey(e, true)
		if err != nil || a != b {
			t.Fatal("ASCII case changed canonical conflict key")
		}
		e.Target.Host = host
		after, _ := json.Marshal(e)
		if string(before) != string(after) {
			t.Fatal("mutated input")
		}
	})
}
