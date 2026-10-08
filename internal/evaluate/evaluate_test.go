package evaluate

import (
	"capevidence/internal/model"
	"capevidence/internal/registry"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testPlatforms struct{}

func (testPlatforms) Supports(os string) bool { return os == "linux" }
func fixture() (model.Bundle, model.Policy, model.Context) {
	digest := "sha256:" + strings.Repeat("a", 64)
	rec := model.EvidenceRecord{Version: "0.1", Capability: "network.outbound", Basis: model.Observed, Outcome: model.Present, Action: model.Succeeded, Target: model.Target{Family: "network", Host: "api.example.com"}, Scope: model.Scope{OS: "linux", TargetScope: "api.example.com"}, Run: &model.Run{ID: "r1", Completed: true}, Analyzer: &model.Analyzer{Name: "test", Version: "1"}}
	b := model.Bundle{Version: "0.1", Artifact: model.Artifact{Digest: digest}, Evidence: []model.EvidenceRecord{rec}}
	p := model.Policy{Version: "0.1", SemanticState: model.SemanticState, RegistryVersion: "fixture-0.1", RegistryDigest: "sha256:" + strings.Repeat("b", 64), DecisionScope: []string{"network.outbound"}, OutOfScope: model.Review, Rules: []model.Rule{{ID: "allow-api", Capability: "network.outbound", Effect: model.Allow, Target: rec.Target}}}
	c := model.Context{EvaluationTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ArtifactDigest: digest, Limits: model.DefaultLimits(), Registry: model.Registry{Version: p.RegistryVersion, Digest: p.RegistryDigest, SemanticState: model.SemanticState, Capabilities: map[string]string{"network.outbound": "network"}}, Trust: model.TrustContext{Runs: map[string]model.PipelineBinding{"r1": {ArtifactDigest: digest, AnalyzerName: "test", AnalyzerVersion: "1"}}}}
	var protected model.EvidenceRecord
	encoded, _ := json.Marshal(rec)
	_ = json.Unmarshal(encoded, &protected)
	c.Trust.Evidence = []model.EvidenceRecord{protected}
	c.Platforms = testPlatforms{}
	return b, p, c
}
func TestPositiveAuthorizationProperties(t *testing.T) {
	cases := []struct {
		id      string
		change  func(*model.Bundle, *model.Policy, *model.Context)
		want    model.Decision
		failure bool
	}{
		{"PROP-003_unverified", func(b *model.Bundle, p *model.Policy, c *model.Context) { c.Trust = model.TrustContext{} }, model.Review, false},
		{"PROP-004_not_observed", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			e := &b.Evidence[0]
			e.Outcome = model.NotObserved
			e.Action = ""
			e.Run.Coverage = []model.Coverage{{Capability: e.Capability, Scope: e.Scope}}
		}, model.Review, false},
		{"PROP-005_empty_scope", func(b *model.Bundle, p *model.Policy, c *model.Context) { p.DecisionScope = nil; p.Rules = nil }, model.Review, false},
		{"PROP-006_no_match", func(b *model.Bundle, p *model.Policy, c *model.Context) { p.Rules = nil }, "", true},
		{"PROP-011_stale_present", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].ObservedAt = "2020-01-01T00:00:00Z"
			c.MaxAge = time.Hour
			p.Rules[0].Effect = model.Deny
		}, model.Deny, false},
		{"PROP-012_incomplete_negative", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			e := &b.Evidence[0]
			e.Outcome = model.NotObserved
			e.Action = ""
			e.Run.Completed = false
		}, "", true},
		{"PROP-013_invalid_record", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			bad := b.Evidence[0]
			bad.Target.Host = "127.1"
			b.Evidence = append(b.Evidence, bad)
		}, "", true},
		{"PROP-014_future_state", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Outcome = "new_state" }, "", true},
		{"PROP-018_context_change", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			c.Trust.Runs["r1"] = model.PipelineBinding{ArtifactDigest: c.ArtifactDigest, AnalyzerName: "other", AnalyzerVersion: "1"}
		}, model.Review, false},
		{"PROP-019_other_run", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Run.ID = "r2" }, model.Review, false},
		{"PROP-020_artifact_mismatch", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			c.ArtifactDigest = "sha256:" + strings.Repeat("b", 64)
		}, "", true},
		{"PROP-026_unknown_platform", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Scope.OS = "" }, model.Review, false},
		{"PROP-028_universal_allow", func(b *model.Bundle, p *model.Policy, c *model.Context) { p.Rules[0].Target.Host = "*" }, "", true},
		{"PROP-029_unsupported_glob", func(b *model.Bundle, p *model.Policy, c *model.Context) { p.Rules[0].Target.Host = "a*.example.com" }, "", true},
		{"PROP-030_mapped_IP_no_allow", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target.Host = "::ffff:127.0.0.1"
			p.Rules[0].Target.Host = "127.0.0.1"
		}, "", true},
		{"PROP-031_invalid_target", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Target.Host = "a..example.com" }, "", true},
		{"PROP-032_failed_action", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Action = model.AttemptedFailed }, model.Review, false},
		{"PROP-032_unknown_action", func(b *model.Bundle, p *model.Policy, c *model.Context) { b.Evidence[0].Action = model.ActionUnknown }, model.Review, false},
		{"PROP-033_executable_name", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target = model.Target{Family: "executable", Name: "curl"}
		}, "", true},
		{"PROP-035_reserved_extension", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Extensions = map[string]model.Extension{"vendor": {Value: map[string]any{"trust": "authenticated"}}}
		}, "", true},
		{"TEST-TRUST-001_unverified_deny", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			c.Trust = model.TrustContext{}
			p.Rules[0].Effect = model.Deny
		}, model.Deny, false},
		{"TEST-VERSION-001_registry_mismatch", func(b *model.Bundle, p *model.Policy, c *model.Context) { p.RegistryDigest = "changed" }, "", true},
		{"TEST-TIME-001_future", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].ObservedAt = "2027-01-01T00:00:00Z"
		}, "", true},
		{"TEST-TIME-002_explicit", func(b *model.Bundle, p *model.Policy, c *model.Context) { c.EvaluationTime = time.Time{} }, "", true},
		{"TEST-CONFLICT-001", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			r := p.Rules[0]
			r.ID = "deny-api"
			r.Effect = model.Deny
			p.Rules = append(p.Rules, r)
		}, model.Deny, false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			b, p, c := fixture()
			tc.change(&b, &p, &c)
			if tc.id != "PROP-018_context_change" && tc.id != "PROP-019_other_run" && len(c.Trust.Runs) > 0 {
				raw, _ := json.Marshal(b.Evidence)
				_ = json.Unmarshal(raw, &c.Trust.Evidence)
			}
			r := Check(b, p, c)
			if r.Decision != tc.want || (r.Failure != nil) != tc.failure {
				t.Fatalf("unexpected result: %+v", r)
			}
		})
	}
	b, p, c := fixture()
	if r := Check(b, p, c); r.Decision != model.Allow || r.Failure != nil {
		t.Fatal("trusted positive failed", r)
	}
}
func TestOrderAndNegativeInvariance(t *testing.T) {
	b, p, c := fixture()
	e := b.Evidence[0]
	e.Target.Host = "other.example.com"
	e.Scope.TargetScope = "other.example.com"
	e.Outcome = model.NotObserved
	e.Action = ""
	run := *e.Run
	run.Coverage = []model.Coverage{{Capability: e.Capability, Scope: e.Scope}}
	e.Run = &run
	b.Evidence = append(b.Evidence, e)
	first := Check(b, p, c)
	b.Evidence[0], b.Evidence[1] = b.Evidence[1], b.Evidence[0]
	second := Check(b, p, c)
	a, _ := json.Marshal(first)
	bb, _ := json.Marshal(second)
	if string(a) != string(bb) {
		t.Fatal("PROP-001 order dependent")
	}
	if first.Decision != model.Allow {
		t.Fatal("PROP-021 irrelevant not_observed changed decision")
	}
	p.Rules[0].Effect = model.Deny
	if Check(b, p, c).Decision != model.Deny {
		t.Fatal("PROP-015 weakened deny")
	}
	c.Trust = model.TrustContext{}
	if Check(b, p, c).Decision != model.Deny {
		t.Fatal("PROP-007 trust reduction weakened deny")
	}
}
func TestModes(t *testing.T) {
	for _, d := range []model.Decision{model.Allow, model.Review, model.Deny} {
		r := model.Result{Decision: d}
		if ExitCode(r, "audit") != 0 || ExitCode(r, "inform") != 0 {
			t.Fatal("PROP-016 audit failure")
		}
		if d != model.Allow && ExitCode(r, "enforce") == 0 {
			t.Fatal("PROP-015 review bypass")
		}
	}
	if ExitCode(model.Result{Failure: &model.Diagnostic{ReasonCode: "invalid_evidence"}}, "audit") == 0 {
		t.Fatal("audit swallowed failure")
	}
}
func TestImplicationBoundaries(t *testing.T) {
	edges := []Implication{{"a", "b"}, {"b", "a"}, {"b", "c"}}
	r, e := Derive([]string{"a"}, edges, map[string]bool{"a": true, "b": true}, 10)
	if e != nil || len(r) != 2 {
		t.Fatal("cycle bound", e)
	}
	for _, x := range r {
		if x.Kind != "derived" || x.Classification == "allow" {
			t.Fatal("PROP-008/009")
		}
		if x.Capability == "c" && x.Classification != "derived_out_of_scope" {
			t.Fatal("PROP-010")
		}
	}
	if _, e := Derive([]string{"a"}, edges, nil, 1); e == nil {
		t.Fatal("unbounded implication")
	}
}
func TestRegistryPatch(t *testing.T) {
	_, _, c := fixture()
	r := c.Registry
	r.Capabilities = map[string]string{"other": "network"}
	if registry.CheckPatch(c.Registry, r) == nil {
		t.Fatal("PROP-017 patch changed semantics")
	}
}

func TestProtectedTrustContent(t *testing.T) {
	b, p, c := fixture()
	b.Evidence[0].Target.Host = "www.example.com"
	p.Rules[0].Target.Host = "www.example.com"
	r := Check(b, p, c)
	if r.Decision != model.Review || r.Failure != nil {
		t.Fatal("modified producer record retained pipeline trust", r)
	}
}
func TestPendingPlatform(t *testing.T) {
	b, p, c := fixture()
	c.Platforms = nil
	r := Check(b, p, c)
	if r.Failure == nil || r.Failure.DecisionID != "DEC-OS-001" {
		t.Fatal("selected default platform vocabulary")
	}
	c.Platforms = testPlatforms{}
	b.Evidence[0].Scope.OS = "unrecognized"
	raw, _ := json.Marshal(b.Evidence)
	_ = json.Unmarshal(raw, &c.Trust.Evidence)
	if Check(b, p, c).Decision != model.Review {
		t.Fatal("unknown OS broadened allow")
	}
}
func TestOutOfScopeNegativeInvariance(t *testing.T) {
	b, p, c := fixture()
	negative := b.Evidence[0]
	negative.Capability = "network.inbound"
	negative.Outcome = model.NotObserved
	negative.Action = ""
	run := *negative.Run
	run.Coverage = []model.Coverage{{Capability: negative.Capability, Scope: negative.Scope}}
	negative.Run = &run
	c.Registry.Capabilities[negative.Capability] = "network"
	b.Evidence = append(b.Evidence, negative)
	p.OutOfScope = model.Deny
	if Check(b, p, c).Decision != model.Allow {
		t.Fatal("irrelevant out-of-scope not_observed changed allow")
	}
}

func TestTraceLimit(t *testing.T) {
	b, p, c := fixture()
	p.Rules = append(p.Rules, p.Rules[0])
	p.Rules[1].ID = "second-allow"
	c.Limits.TraceEntries = 1
	r := Check(b, p, c)
	if r.Failure == nil || r.Failure.ReasonCode != "resource_limit" || len(r.Trace) > 1 {
		t.Fatal("unbounded trace", r)
	}
}
