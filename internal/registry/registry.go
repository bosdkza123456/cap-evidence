package registry

import (
	"capevidence/internal/artifact"
	"capevidence/internal/model"
	"capevidence/internal/target"
	"capevidence/internal/validate"
	"reflect"
)

func Validate(r model.Registry, lim model.Limits) error {
	if !validate.Identifier(r.Version) || !artifact.ValidDigest(r.Digest) || r.SemanticState != model.SemanticState {
		return model.Diagnostic{ReasonCode: "unsupported_version"}
	}
	if len(r.Capabilities) > lim.Rules {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	if len(r.SecurityEquivalences) > lim.Rules {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	seen := map[string]bool{}
	for _, id := range r.SecurityEquivalences {
		if id != target.MappedIPRestrictiveV1 || seen[id] {
			return model.Diagnostic{ReasonCode: "invalid_registry"}
		}
		seen[id] = true
	}
	for _, family := range r.Capabilities {
		if family != "network" && family != "filesystem" && family != "executable" {
			return model.Diagnostic{ReasonCode: "unsupported_capability"}
		}
	}
	return nil
}

// CheckPatch checks the currently represented semantic surface. Implications and equivalences
// are guarded explicitly; future semantic fields must extend this guard.
func CheckPatch(old, next model.Registry) error {
	if old.SemanticState != next.SemanticState || !reflect.DeepEqual(old.Capabilities, next.Capabilities) || !reflect.DeepEqual(old.SecurityEquivalences, next.SecurityEquivalences) {
		return model.Diagnostic{ReasonCode: "registry_semantics_changed"}
	}
	return nil
}
