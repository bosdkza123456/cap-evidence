package evaluate

import "capevidence/internal/model"

// Implications are internal capability-only assertions. Target propagation remains unavailable.
// They carry no evidence IDs and cannot participate in positive rule satisfaction.
type Implication struct {
	From string
	To   string
}

func Derive(caps []string, edges []Implication, scope map[string]bool, limit int) ([]model.TraceEntry, error) {
	if limit <= 0 || len(edges) > limit || len(caps) > limit {
		return nil, model.Diagnostic{ReasonCode: "resource_limit"}
	}
	seen := map[string]bool{}
	queue := []string{}
	for _, c := range caps {
		if !seen[c] {
			seen[c] = true
			queue = append(queue, c)
		}
	}
	out := []model.TraceEntry{}
	for i := 0; i < len(queue); i++ {
		for _, edge := range edges {
			if edge.From != queue[i] || seen[edge.To] {
				continue
			}
			if len(queue) >= limit {
				return nil, model.Diagnostic{ReasonCode: "resource_limit"}
			}
			seen[edge.To] = true
			queue = append(queue, edge.To)
			classification := "derived_restrictive_only"
			if !scope[edge.To] {
				classification = "derived_out_of_scope"
			}
			out = append(out, model.TraceEntry{Kind: "derived", Capability: edge.To, Classification: classification})
		}
	}
	return out, nil
}
