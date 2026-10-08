package evaluate

import (
	"capevidence/internal/model"
	"capevidence/internal/registry"
	"capevidence/internal/target"
	"capevidence/internal/validate"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestMixedBundles(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*model.Bundle, *model.Policy, *model.Context)
		want    model.Decision
		blocker string
	}{
		{"TEST-UNKNOWN-001_allow_plus_unknown", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			e := b.Evidence[0]
			e.Outcome = model.Unknown
			e.Basis = ""
			e.Action = ""
			e.Reason = "unsupported_source_event"
			e.Target.Host = "evil.example.net"
			e.Scope.TargetScope = "evil.example.net"
			b.Evidence = append(b.Evidence, e)
		}, model.Review, ""},
		{"TEST-UNKNOWN-002_deny_plus_unknown", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			e := b.Evidence[0]
			e.Outcome = model.Unknown
			e.Action = ""
			e.Reason = "unsupported_source_event"
			e.Target.Host = "evil.example.net"
			b.Evidence = append(b.Evidence, e)
		}, model.Deny, ""},
		{"TEST-UNKNOWN-003_out_of_scope", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			e := b.Evidence[0]
			e.Outcome = model.Unknown
			e.Action = ""
			e.Reason = "not_covered"
			e.Capability = "network.inbound"
			c.Registry.Capabilities[e.Capability] = "network"
			b.Evidence = append(b.Evidence, e)
			p.OutOfScope = model.Deny
		}, model.Deny, ""},
		{"TEST-DENY-001_no_match", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			e := b.Evidence[0]
			e.Target.Host = "evil.example.net"
			b.Evidence = append(b.Evidence, e)
		}, model.Deny, "DEC-NOMATCH-001"},
		{"TEST-DENY-002_overlapping_rules", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			r := p.Rules[0]
			r.ID = "deny-wildcard"
			r.Effect = model.Deny
			r.Target.Host = "*.example.com"
			p.Rules = append(p.Rules, r)
		}, model.Deny, ""},
		{"TEST-DENY-003_pending_platform", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			c.Platforms = nil
			r := p.Rules[0]
			r.ID = "deny-api"
			r.Effect = model.Deny
			p.Rules = append(p.Rules, r)
		}, model.Deny, "DEC-OS-001"},
		{"TEST-DENY-004_require", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			p.Require = []model.Requirement{{Capability: "network.outbound", Kind: "pending"}}
		}, model.Deny, "DEC-CONFLICT-001"},
		{"TEST-CONFLICT-002_present_absent", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			e := b.Evidence[0]
			e.Basis = model.Declared
			e.Outcome = model.Absent
			e.Action = ""
			e.Run = nil
			e.DeclarationSource = "manifest"
			b.Evidence = append(b.Evidence, e)
		}, "", "DEC-DECLARATION-001"},
		{"TEST-CONFLICT-003_deny_present_absent", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			e := b.Evidence[0]
			e.Basis = model.Declared
			e.Outcome = model.Absent
			e.Action = ""
			e.Run = nil
			e.DeclarationSource = "manifest"
			b.Evidence = append(b.Evidence, e)
		}, model.Deny, "DEC-DECLARATION-001"},
		{"TEST-DENY-005_invalid_record", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			e := b.Evidence[0]
			e.Target.Host = "127.1"
			b.Evidence = append(b.Evidence, e)
		}, "", ""},
		{"TEST-DENY-006_artifact_mismatch", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			p.Rules[0].Effect = model.Deny
			c.ArtifactDigest = "sha256:" + strings.Repeat("f", 64)
		}, "", ""},
		{"TEST-EQUIVALENCE-001_registered_deny", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target.Host = "::ffff:127.0.0.1"
			p.Rules[0].Target.Host = "127.0.0.1"
			p.Rules[0].Effect = model.Deny
			c.Registry.SecurityEquivalences = []string{target.MappedIPRestrictiveV1}
		}, model.Deny, ""},
		{"TEST-EQUIVALENCE-002_registered_review", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target.Host = "::ffff:127.0.0.1"
			p.Rules[0].Target.Host = "127.0.0.1"
			p.Rules[0].Effect = model.Review
			c.Registry.SecurityEquivalences = []string{target.MappedIPRestrictiveV1}
		}, model.Review, ""},
		{"TEST-EQUIVALENCE-003_no_allow", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target.Host = "::ffff:127.0.0.1"
			p.Rules[0].Target.Host = "127.0.0.1"
			c.Registry.SecurityEquivalences = []string{target.MappedIPRestrictiveV1}
		}, "", "DEC-NOMATCH-001"},
		{"TEST-EQUIVALENCE-004_not_registered", func(b *model.Bundle, p *model.Policy, c *model.Context) {
			b.Evidence[0].Target.Host = "::ffff:127.0.0.1"
			p.Rules[0].Target.Host = "127.0.0.1"
			p.Rules[0].Effect = model.Deny
		}, "", "DEC-NOMATCH-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, p, c := fixture()
			tc.mutate(&b, &p, &c)
			before, _ := json.Marshal(b)
			r := Check(b, p, c)
			if r.Decision != tc.want {
				t.Fatalf("decision=%s failure=%+v", r.Decision, r.Failure)
			}
			if tc.want == "" && r.Failure == nil {
				t.Fatal("expected failure")
			}
			if tc.want != "" && r.Failure != nil {
				t.Fatal("unexpected failure")
			}
			if tc.blocker != "" {
				found := false
				for _, d := range r.Diagnostics {
					if d.DecisionID == tc.blocker {
						found = true
					}
				}
				if !found {
					t.Fatal("missing blocker diagnostic")
				}
			}
			after, _ := json.Marshal(b)
			if string(before) != string(after) {
				t.Fatal("mutated evidence identity input")
			}
			for i, j := 0, len(b.Evidence)-1; i < j; i, j = i+1, j-1 {
				b.Evidence[i], b.Evidence[j] = b.Evidence[j], b.Evidence[i]
			}
			for i, j := 0, len(p.Rules)-1; i < j; i, j = i+1, j-1 {
				p.Rules[i], p.Rules[j] = p.Rules[j], p.Rules[i]
			}
			rr := Check(b, p, c)
			if r.Decision != rr.Decision || ((r.Failure == nil) != (rr.Failure == nil)) {
				t.Fatal("order-dependent decision")
			}
			if r.Failure == nil && !reflect.DeepEqual(r, rr) {
				t.Fatal("order-dependent successful trace")
			}
		})
	}
}
func TestInferredReferencesBlocked(t *testing.T) {
	b, _, c := fixture()
	e := b.Evidence[0]
	e.Basis = model.Inferred
	e.Action = ""
	e.DerivedFrom = []string{"missing-id"}
	e.Analyzer = &model.Analyzer{Name: "test", Version: "1", Method: "test"}
	err := validate.Record(e, c.Limits)
	d, ok := err.(model.Diagnostic)
	if !ok || d.DecisionID != "DEC-HASH-001" {
		t.Fatal("dangling reference accepted", err)
	}
	e.EvidenceID = "pretend-parent"
	err = validate.Record(e, c.Limits)
	if err == nil {
		t.Fatal("unverified evidence ID accepted")
	}
}
func TestUnknownBasis(t *testing.T) {
	b, _, c := fixture()
	e := b.Evidence[0]
	e.Outcome = model.Unknown
	e.Action = ""
	e.Reason = "unsupported_source_event"
	e.Basis = ""
	if err := validate.Record(e, c.Limits); err != nil {
		t.Fatal(err)
	}
	e.Reason = ""
	if validate.Record(e, c.Limits) == nil {
		t.Fatal("unknown lacks reason")
	}
	e.Reason = "not_covered"
	e.Basis = "made_up"
	if validate.Record(e, c.Limits) == nil {
		t.Fatal("invalid optional basis")
	}
}
func TestEquivalencePatchGuard(t *testing.T) {
	_, _, c := fixture()
	next := c.Registry
	next.SecurityEquivalences = []string{target.MappedIPRestrictiveV1}
	if registry.CheckPatch(c.Registry, next) == nil {
		t.Fatal("PATCH changed matching semantics")
	}
}

func TestPROP034RestrictiveAddition(t *testing.T) {
	b, p, c := fixture()
	if Check(b, p, c).Decision != model.Allow {
		t.Fatal("baseline")
	}
	r := p.Rules[0]
	r.ID = "deny-evil"
	r.Effect = model.Deny
	r.Target.Host = "evil.example.net"
	p.Rules = append(p.Rules, r)
	e := b.Evidence[0]
	e.Target.Host = "evil.example.net"
	b.Evidence = append(b.Evidence, e)
	if Check(b, p, c).Decision != model.Deny {
		t.Fatal("in-scope forbidden evidence preserved ALLOW")
	}
}

// Replaces TestRulePlatformAppliesToRestrictiveEffects: restrictive OS fields
// are invalid policy, rather than filters that producer OS could bypass.
func TestRestrictiveRuleRejectsOS(t *testing.T) {
	b, p, c := fixture()
	for _, effect := range []model.Decision{model.Deny, model.Review} {
		p.Rules[0].Effect = effect
		p.Rules[0].OS = "windows"
		r := Check(b, p, c)
		if r.Failure == nil || r.Failure.ReasonCode != "invalid_policy" {
			t.Fatal("restrictive rule silently accepted OS", r)
		}
	}
}
