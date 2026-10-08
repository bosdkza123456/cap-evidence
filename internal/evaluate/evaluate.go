// Package evaluate never accesses time, network, environment, or filesystem implicitly.
package evaluate

import (
	"capevidence/internal/artifact"
	"capevidence/internal/model"
	"capevidence/internal/policy"
	"capevidence/internal/registry"
	"capevidence/internal/target"
	"capevidence/internal/trace"
	"capevidence/internal/trust"
	"capevidence/internal/validate"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

func fail(r model.Result, e error) model.Result {
	d, ok := e.(model.Diagnostic)
	if !ok {
		d = model.Diagnostic{ReasonCode: "evaluation_failure"}
	}
	r.Decision = ""
	r.Failure = &d
	trace.Sort(&r)
	return r
}

// AggregateBoundary deliberately cannot finalize no_match (DEC-NOMATCH-001).
type AggregateBoundary interface {
	Resolve([]model.TraceEntry) (model.Decision, error)
}

func Check(b model.Bundle, p model.Policy, c model.Context) model.Result {
	r := model.Result{Gating: true, Diagnostics: []model.Diagnostic{}, Trace: []model.TraceEntry{}, SemanticState: model.SemanticState, RegistryVersion: c.Registry.Version, RegistryDigest: c.Registry.Digest}
	if e := validate.Bundle(b, c.Limits); e != nil {
		return fail(r, e)
	}
	if e := policy.Validate(p, c.Limits); e != nil {
		return fail(r, e)
	}
	if e := registry.Validate(c.Registry, c.Limits); e != nil {
		return fail(r, e)
	}
	if c.EvaluationTime.IsZero() || c.MaxAge < 0 {
		return fail(r, model.Diagnostic{ReasonCode: "invalid_context"})
	}
	if c.Registry.SemanticState != model.SemanticState || p.RegistryVersion != c.Registry.Version || p.RegistryDigest != c.Registry.Digest {
		return fail(r, model.Diagnostic{ReasonCode: "unsupported_version"})
	}
	if e := artifact.Bind(b.Artifact.Digest, c.ArtifactDigest); e != nil {
		return fail(r, e)
	}
	for _, cap := range p.DecisionScope {
		if _, ok := c.Registry.Capabilities[cap]; !ok {
			return fail(r, model.Diagnostic{ReasonCode: "unsupported_capability", DecisionID: "DEC-CAP-001"})
		}
	}

	if len(p.DecisionScope) == 0 {
		r.Decision = model.Review
		r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "empty_decision_scope"})
		return r
	}
	scope := map[string]bool{}
	for _, cap := range p.DecisionScope {
		scope[cap] = true
	}
	records := append([]model.EvidenceRecord(nil), b.Evidence...)
	sort.SliceStable(records, func(i, j int) bool {
		a, _ := json.Marshal(records[i])
		b, _ := json.Marshal(records[j])
		return string(a) < string(b)
	})
	// Validate all represented capabilities before making a policy decision, even when DENY exists.
	for _, e := range records {
		family, ok := c.Registry.Capabilities[e.Capability]
		if !ok {
			return fail(r, model.Diagnostic{ReasonCode: "unsupported_capability", DecisionID: "DEC-CAP-001"})
		}
		if family != e.Target.Family {
			return fail(r, model.Diagnostic{ReasonCode: "invalid_evidence"})
		}
	}
	blockers := map[string]bool{}
	if len(p.Require) > 0 {
		blockers["DEC-CONFLICT-001"] = true
	}
	// Network host keys use the existing target.Host canonical form on a copy.
	// Scope, other target families and security equivalence remain unchanged.
	outcomes := map[string]map[model.Outcome]bool{}
	for _, e := range records {
		if !scope[e.Capability] {
			continue
		}
		k, err := conflictKey(e, false)
		if err != nil {
			return fail(r, err)
		}
		if outcomes[k] == nil {
			outcomes[k] = map[model.Outcome]bool{}
		}
		outcomes[k][e.Outcome] = true
	}
	for _, key := range sortedConflictKeys(outcomes) {
		states := outcomes[key]
		if states[model.Present] && states[model.Absent] {
			blockers["DEC-DECLARATION-001"] = true
			r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "declaration_conflict", DecisionID: "DEC-DECLARATION-001", ConflictKey: conflictToken(key)})
		}
	}

	// Only contradictory observations of the exact same assertion in the same run
	// constrain authorization. Independent runs and unrelated negative evidence do not.
	observationStates := map[string]map[model.Outcome]bool{}
	for _, e := range records {
		if e.Basis != model.Observed || e.Run == nil {
			continue
		}
		k, err := conflictKey(e, true)
		if err != nil {
			return fail(r, err)
		}
		if observationStates[k] == nil {
			observationStates[k] = map[model.Outcome]bool{}
		}
		observationStates[k][e.Outcome] = true
	}
	inconsistent := false
	for _, key := range sortedConflictKeys(observationStates) {
		states := observationStates[key]
		if states[model.Present] && states[model.NotObserved] {
			inconsistent = true
			r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "observation_inconsistency", DecisionID: "DEC-OBS-001", ConflictKey: conflictToken(key)})
		}
	}
	push := func(entry model.TraceEntry) bool {
		if c.Limits.TraceEntries <= 0 || len(r.Trace) >= c.Limits.TraceEntries {
			return false
		}
		r.Trace = append(r.Trace, entry)
		return true
	}
	positive, review, deny := false, inconsistent, false
	for _, e := range records {
		if e.ObservedAt != "" {
			at, _ := time.Parse(time.RFC3339Nano, e.ObservedAt)
			if at.After(c.EvaluationTime) {
				blockers["DEC-FUTURE-001"] = true
			} else if c.MaxAge > 0 && c.EvaluationTime.Sub(at) > c.MaxAge {
				r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "stale_evidence"})
			}
		}
		entry := model.TraceEntry{Kind: "evidence", Capability: e.Capability}
		if e.Outcome == model.NotObserved || e.Outcome == model.Absent {
			entry.Classification = string(e.Outcome)
			if !push(entry) {
				return fail(r, model.Diagnostic{ReasonCode: "resource_limit"})
			}
			continue
		}
		if !scope[e.Capability] {
			entry.Classification = "out_of_scope"
			if p.OutOfScope == model.Deny {
				deny = true
			} else {
				review = true
			}
			if !push(entry) {
				return fail(r, model.Diagnostic{ReasonCode: "resource_limit"})
			}
			continue
		}
		if e.Outcome == model.Unknown {
			review = true
			entry.Classification = "unknown"
			r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "in_scope_unknown"})
			if !push(entry) {
				return fail(r, model.Diagnostic{ReasonCode: "resource_limit"})
			}
			continue
		}
		positive = true
		effects := map[model.Decision]bool{}
		matched := false
		for _, rule := range p.Rules {
			if rule.Capability != e.Capability {
				continue
			}
			if e.Target.Family != "network" {
				blockers["DEC-PATH-001"] = true
				continue
			}
			m, err := target.MatchRegisteredHost(rule.Target.Host, e.Target.Host, rule.Effect, c.Registry.SecurityEquivalences)
			if err != nil {
				return fail(r, err)
			}
			if !m {
				continue
			}
			matched = true
			effects[rule.Effect] = true
			entry.Classification = string(rule.Effect)
			entry.RuleID = rule.ID
			switch rule.Effect {
			case model.Deny:
				deny = true
			case model.Review:
				review = true
			case model.Allow:
				if trust.Derive(e, b.Artifact.Digest, c.Trust) != trust.PipelineLocal || e.Basis != model.Observed || e.Action != model.Succeeded || e.Scope.OS == "" || rule.OS != "" && rule.OS != e.Scope.OS {
					review = true
					entry.Classification = "allow_requirements_unsatisfied"
				} else if c.Platforms == nil {
					blockers["DEC-OS-001"] = true
					entry.Classification = "platform_semantics_pending"
				} else if !c.Platforms.Supports(e.Scope.OS) {
					review = true
					entry.Classification = "unknown_platform"
				}
			}
			if !push(entry) {
				return fail(r, model.Diagnostic{ReasonCode: "resource_limit"})
			}
		}
		// DENY already determines a non-authorizing result for overlapping rules.
		if len(effects) > 1 && !effects[model.Deny] {
			blockers["DEC-CONFLICT-001"] = true
		}
		if !matched {
			blockers["DEC-NOMATCH-001"] = true
			entry.Classification = "no_match"
			entry.RuleID = ""
			if !push(entry) {
				return fail(r, model.Diagnostic{ReasonCode: "resource_limit"})
			}
		}
	}
	ids := make([]string, 0, len(blockers))
	for id := range blockers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: id})
	}
	// Semantic blockers never erase an established DENY. Parse/validation/binding/resource
	// failures still stop evaluation as Failure; they are not reclassified as DENY.
	if deny {
		r.Decision = model.Deny
	} else if len(ids) > 0 {
		return fail(r, model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: ids[0]})
	} else if review || !positive {
		r.Decision = model.Review
		if !positive {
			r.Diagnostics = append(r.Diagnostics, model.Diagnostic{ReasonCode: "no_positive_evidence"})
		}
	} else {
		r.Decision = model.Allow
	}
	trace.Sort(&r)
	return r
}

func ExitCode(r model.Result, mode string) int {
	if r.Failure != nil {
		return 2
	}
	if mode != "enforce" && mode != "audit" && mode != "inform" {
		return 2
	}
	if r.Decision != model.Allow && r.Decision != model.Review && r.Decision != model.Deny {
		return 2
	}
	if mode == "enforce" && r.Decision != model.Allow {
		return 1
	}
	return 0
}

// conflictKey changes only the copied network target. It does not normalize scope,
// resolve paths or unmap IPv6. Observation keys additionally include the exact run ID.
func conflictKey(e model.EvidenceRecord, includeRun bool) (string, error) {
	t := e.Target
	if t.Family == "network" {
		host, err := target.Host(t.Host)
		if err != nil {
			return "", err
		}
		t.Host = host
	}
	runID := ""
	if includeRun && e.Run != nil {
		runID = e.Run.ID
	}
	key, err := json.Marshal(struct {
		RunID      string
		Capability string
		Target     model.Target
		Scope      model.Scope
	}{runID, e.Capability, t, e.Scope})
	if err != nil {
		return "", model.Diagnostic{ReasonCode: "evaluation_failure"}
	}
	return string(key), nil
}
func sortedConflictKeys(groups map[string]map[model.Outcome]bool) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// conflictToken is a bounded presentation identifier, not canonical evidence identity.
func conflictToken(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}
