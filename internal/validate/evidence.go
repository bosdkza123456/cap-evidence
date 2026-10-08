package validate

import (
	"capevidence/internal/artifact"
	"capevidence/internal/model"
	"capevidence/internal/target"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func Bundle(b model.Bundle, lim model.Limits) error {
	if b.Version != model.Version {
		return model.Diagnostic{ReasonCode: "unsupported_version"}
	}
	if !artifact.ValidDigest(b.Artifact.Digest) {
		return model.Diagnostic{ReasonCode: "invalid_evidence", JSONPointer: "/artifact/digest"}
	}
	if lim.Records <= 0 || len(b.Evidence) > lim.Records {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	for i, r := range b.Evidence {
		if e := Record(r, lim); e != nil {
			d, ok := e.(model.Diagnostic)
			if !ok {
				d = model.Diagnostic{ReasonCode: "invalid_evidence"}
			}
			d.RecordIndex = &i
			d.JSONPointer = fmt.Sprintf("/evidence/%d", i) + d.JSONPointer
			return d
		}
	}
	return nil
}
func bad(field string) error {
	return model.Diagnostic{ReasonCode: "invalid_evidence", JSONPointer: "/" + field}
}
func Record(r model.EvidenceRecord, lim model.Limits) error {
	if r.EvidenceID != "" {
		return model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-HASH-001"}
	}
	if r.Version != model.Version {
		return model.Diagnostic{ReasonCode: "unsupported_version"}
	}
	for _, ext := range r.Extensions {
		if unsafeExtension(ext.Value, lim) {
			return bad("extensions")
		}
	}
	encoded, err := json.Marshal(r)
	if err != nil || lim.InputBytes <= 0 || len(encoded) > lim.InputBytes {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	if r.Run != nil && len(r.Run.Coverage) > lim.Items || len(r.DerivedFrom) > lim.Items || len(r.Extensions) > lim.Keys {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	if !Identifier(r.Capability) {
		return bad("capability")
	}
	if !(r.Outcome == model.Unknown && r.Basis == "") && r.Basis != model.Declared && r.Basis != model.Observed && r.Basis != model.Inferred {
		return bad("basis")
	}
	if r.Outcome != model.Present && r.Outcome != model.NotObserved && r.Outcome != model.Absent && r.Outcome != model.Unknown {
		return bad("outcome")
	}
	if r.Action != "" && r.Action != model.Succeeded && r.Action != model.AttemptedFailed && r.Action != model.ActionUnknown {
		return bad("action")
	}
	if e := target.Validate(r.Target); e != nil {
		if d, ok := e.(model.Diagnostic); ok && d.ReasonCode == "unresolved_semantics" {
			return d
		}
		return bad("target")
	}
	for _, s := range []string{r.ObservedAt, r.CreatedAt} {
		if s != "" {
			if _, e := time.Parse(time.RFC3339Nano, s); e != nil {
				return bad("observed_at")
			}
		}
	}
	if r.Outcome == model.Unknown {
		if r.Reason == "" {
			return bad("reason")
		}
		if r.Action != "" || len(r.DerivedFrom) > 0 {
			return bad("outcome")
		}
	} else {
		switch r.Basis {
		case model.Observed:
			if len(r.DerivedFrom) > 0 {
				return bad("derived_from")
			}
			if r.Run == nil || r.Run.ID == "" || r.Scope.TargetScope == "" {
				return bad("run")
			}
			if r.Outcome == model.Present {
				if r.Action == "" {
					return bad("action")
				}
			} else if r.Outcome == model.NotObserved {
				if !r.Run.Completed {
					return bad("run/completed")
				}
				covered := false
				for _, c := range r.Run.Coverage {
					if c.Capability == r.Capability && c.Scope == r.Scope {
						covered = true
					}
				}
				if !covered {
					return bad("run/coverage")
				}
				if r.Action != "" {
					return bad("action")
				}
			} else {
				return bad("outcome")
			}
		case model.Declared:
			if r.Outcome != model.Present && r.Outcome != model.Absent {
				return bad("outcome")
			}
			if r.DeclarationSource == "" {
				return bad("declaration_source")
			}
			if r.Action != "" || len(r.DerivedFrom) > 0 {
				return bad("basis")
			}
		case model.Inferred:
			if r.Outcome != model.Present && r.Outcome != model.Absent {
				return bad("outcome")
			}
			if len(r.DerivedFrom) == 0 || r.Analyzer == nil || r.Analyzer.Name == "" || r.Analyzer.Method == "" {
				return bad("derived_from")
			}
			for _, id := range r.DerivedFrom {
				if id == "" {
					return bad("derived_from")
				}
			}
			if r.Action != "" {
				return bad("action")
			}
			if r.Outcome == model.Absent && (r.ProofRule == "" || !r.Complete) {
				return bad("proof_rule")
			}
			// TODO DEC-HASH-001: no parent identity/reference can be verified before a profile exists.
			return model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-HASH-001"}

		}
	}
	extensionData, err := json.Marshal(r.Extensions)
	if err != nil || len(extensionData) > lim.ExtensionBytes || lim.ExtensionBytes <= 0 {
		return model.Diagnostic{ReasonCode: "resource_limit"}
	}
	names := make([]string, 0, len(r.Extensions))
	for k := range r.Extensions {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		e := r.Extensions[k]
		if e.Critical {
			return bad("extensions")
		}
		if reserved(k) || unsafeExtension(e.Value, lim) {
			return bad("extensions")
		}
		data, err := json.Marshal(e)
		if err != nil || len(data) > lim.ExtensionBytes || lim.ExtensionBytes <= 0 {
			return model.Diagnostic{ReasonCode: "resource_limit"}
		}
	}
	return nil
}
func reserved(s string) bool {
	switch strings.ToLower(s) {
	case "trust", "derived", "contains_parent_reference", "canonical_path", "platform":
		return true
	}
	return false
}

func Identifier(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func unsafeExtension(v any, lim model.Limits) bool {
	type entry struct {
		value any
		depth int
	}
	queue := []entry{{v, 0}}
	keys, items := 0, 0
	for len(queue) > 0 {
		e := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		items++
		if e.depth > lim.Depth || items > lim.Items {
			return true
		}
		switch x := e.value.(type) {
		case map[string]any:
			for k, v := range x {
				keys++
				if keys > lim.Keys || reserved(k) {
					return true
				}
				queue = append(queue, entry{v, e.depth + 1})
			}
		case []any:
			for _, v := range x {
				queue = append(queue, entry{v, e.depth + 1})
			}
		}
	}
	return false
}
