package evaluate

import (
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"capevidence/internal/policy"
	"encoding/json"
	"reflect"
	"testing"
)

func pinEvidence(b model.Bundle, c *model.Context) {
	raw, _ := json.Marshal(b.Evidence)
	_ = json.Unmarshal(raw, &c.Trust.Evidence)
}
func hasDiagnostic(r model.Result, reason string) bool {
	for _, d := range r.Diagnostics {
		if d.ReasonCode == reason {
			return true
		}
	}
	return false
}
func reversedResult(b model.Bundle, p model.Policy, c model.Context) model.Result {
	b.Evidence = append([]model.EvidenceRecord(nil), b.Evidence...)
	for i, j := 0, len(b.Evidence)-1; i < j; i, j = i+1, j-1 {
		b.Evidence[i], b.Evidence[j] = b.Evidence[j], b.Evidence[i]
	}
	return Check(b, p, c)
}

func TestPolicyOSValidation(t *testing.T) {
	for _, effect := range []model.Decision{model.Deny, model.Review} {
		_, p, c := fixture()
		p.Rules[0].Effect = effect
		p.Rules[0].OS = "windows"
		d, ok := policy.Validate(p, c.Limits).(model.Diagnostic)
		if !ok || d.ReasonCode != "invalid_policy" {
			t.Fatal("restrictive OS accepted")
		}
	}
}
func TestRestrictiveOSFieldPresence(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		for _, effect := range []string{"deny", "review"} {
			for _, osValue := range []string{`""`, `null`} {
				input := `{"rules":[{"effect":"` + effect + `","os":` + osValue + `}]}`
				if format == "yaml" {
					input = "rules:\n  - effect: " + effect + "\n    os: " + osValue + "\n"
				}
				var p model.Policy
				d, ok := parse.Decode([]byte(input), format, &p, model.DefaultLimits()).(model.Diagnostic)
				if !ok || d.ReasonCode != "invalid_policy" {
					t.Fatal("explicit OS field accepted", format, effect, osValue)
				}
			}
		}
	}
}
func TestProducerOSCannotEvadeRestrictiveRules(t *testing.T) {
	for _, effect := range []model.Decision{model.Deny, model.Review} {
		for _, os := range []string{"", "linux", "windows", "producer_invented"} {
			b, p, c := fixture()
			p.Rules[0].Effect = effect
			b.Evidence[0].Scope.OS = os
			r := Check(b, p, c)
			if r.Failure != nil || r.Decision != effect {
				t.Fatal("producer OS narrowed restrictive rule", os, r)
			}
		}
	}
}
func TestAllowOSRequirements(t *testing.T) {
	for _, os := range []string{"", "linux"} {
		b, p, c := fixture()
		p.Rules[0].OS = "windows"
		b.Evidence[0].Scope.OS = os
		pinEvidence(b, &c)
		r := Check(b, p, c)
		if r.Failure != nil || r.Decision != model.Review || len(r.Trace) != 1 || r.Trace[0].Classification != "allow_requirements_unsatisfied" {
			t.Fatal("mismatched/missing OS did not review", r)
		}
	}
}
func TestObservationInconsistency(t *testing.T) {
	for _, kind := range []string{"same_run", "same_run_deny", "different_run", "different_target", "declared_present"} {
		t.Run(kind, func(t *testing.T) {
			b, p, c := fixture()
			negative := b.Evidence[0]
			negative.Outcome = model.NotObserved
			negative.Action = ""
			run := *negative.Run
			run.Coverage = []model.Coverage{{Capability: negative.Capability, Scope: negative.Scope}}
			negative.Run = &run
			want := model.Allow
			inconsistent := false
			switch kind {
			case "same_run":
				want = model.Review
				inconsistent = true
			case "same_run_deny":
				p.Rules[0].Effect = model.Deny
				want = model.Deny
				inconsistent = true
			case "different_run":
				negative.Run.ID = "different-run"
			case "different_target":
				negative.Target.Host = "other.example.com"
				negative.Scope.TargetScope = "other.example.com"
				negative.Run.Coverage[0].Scope = negative.Scope
			case "declared_present":
				b.Evidence[0].Basis = model.Declared
				b.Evidence[0].DeclarationSource = "manifest"
				b.Evidence[0].Action = ""
				b.Evidence[0].Run = nil
				want = model.Review
			}
			b.Evidence = append(b.Evidence, negative)
			r := Check(b, p, c)
			if r.Failure != nil || r.Decision != want || hasDiagnostic(r, "observation_inconsistency") != inconsistent {
				t.Fatal("inconsistency handling", r)
			}
			rr := reversedResult(b, p, c)
			if !reflect.DeepEqual(r, rr) {
				t.Fatal("record order changed result")
			}
		})
	}
}
func TestMonotonicRecordAddition(t *testing.T) {
	for _, kind := range []string{"unknown", "unmatched_host", "failed_action", "untrusted", "future_timestamp", "out_of_scope", "irrelevant_not_observed", "irrelevant_absent"} {
		t.Run(kind, func(t *testing.T) {
			b, p, c := fixture()
			if Check(b, p, c).Decision != model.Allow {
				t.Fatal("baseline not ALLOW")
			}
			e := b.Evidence[0]
			keepAllow := false
			switch kind {
			case "unknown":
				e.Outcome = model.Unknown
				e.Basis = ""
				e.Action = ""
				e.Reason = "unsupported_source_event"
			case "unmatched_host":
				e.Target.Host = "evil.example.net"
				e.Scope.TargetScope = "evil.example.net"
			case "failed_action":
				e.Action = model.AttemptedFailed
			case "untrusted":
				run := *e.Run
				run.ID = "unbound-run"
				e.Run = &run
			case "future_timestamp":
				e.ObservedAt = "2027-01-01T00:00:00Z"
			case "out_of_scope":
				e.Capability = "network.inbound"
				c.Registry.Capabilities[e.Capability] = "network"
			case "irrelevant_not_observed":
				keepAllow = true
				e.Target.Host = "other.example.com"
				e.Scope.TargetScope = "other.example.com"
				e.Outcome = model.NotObserved
				e.Action = ""
				run := *e.Run
				run.Coverage = []model.Coverage{{Capability: e.Capability, Scope: e.Scope}}
				e.Run = &run
			case "irrelevant_absent":
				keepAllow = true
				e.Target.Host = "other.example.com"
				e.Scope.TargetScope = "other.example.com"
				e.Basis = model.Declared
				e.Outcome = model.Absent
				e.Action = ""
				e.Run = nil
				e.DeclarationSource = "manifest"
			}
			b.Evidence = append(b.Evidence, e)
			if kind != "untrusted" {
				pinEvidence(b, &c)
			}
			r := Check(b, p, c)
			if (r.Decision == model.Allow) != keepAllow {
				t.Fatal("monotonicity violation", kind, r)
			}
			rr := reversedResult(b, p, c)
			if r.Decision != rr.Decision || ((r.Failure == nil) != (rr.Failure == nil)) {
				t.Fatal("order-dependent classification")
			}
			if r.Failure == nil && !reflect.DeepEqual(r, rr) {
				t.Fatal("order-dependent trace")
			}
		})
	}
}
