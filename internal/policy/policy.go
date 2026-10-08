// Package policy validates the provisional policy authoring schema.
package policy

import (
	"capevidence/internal/model"
	"capevidence/internal/target"
	"capevidence/internal/validate"
)

func Validate(p model.Policy, lim model.Limits) error {
	if p.Version != model.Version || p.SemanticState != model.SemanticState {
		return model.Diagnostic{ReasonCode: "unsupported_version"}
	}
	if p.RegistryVersion == "" || p.RegistryDigest == "" {
		return model.Diagnostic{ReasonCode: "invalid_policy"}
	}
	if p.OutOfScope != model.Review && p.OutOfScope != model.Deny {
		return model.Diagnostic{ReasonCode: "invalid_policy"}
	}
	if lim.Rules <= 0 || len(p.Rules) > lim.Rules || len(p.DecisionScope) > lim.Rules || len(p.Require) > lim.Rules {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	caps := map[string]bool{}
	for _, c := range p.DecisionScope {
		if !validate.Identifier(c) || caps[c] {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		caps[c] = true
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		if !validate.Identifier(r.ID) || ids[r.ID] || !caps[r.Capability] || r.Effect != model.Allow && r.Effect != model.Review && r.Effect != model.Deny {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		// Producer-controlled OS cannot narrow restrictive policy effects.
		if r.Effect != model.Allow && r.OS != "" {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		ids[r.ID] = true
		if len(r.Target.Host) > lim.PatternLength {
			return model.Diagnostic{ReasonCode: "resource_limit"}
		}
		if r.Target.Family != "network" {
			return model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-CMD-001"}
		}
		if r.Target.Path != "" || r.Target.Name != "" {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		if e := target.Pattern(r.Target.Host, r.Effect); e != nil {
			return e
		}
	}
	return nil
}
