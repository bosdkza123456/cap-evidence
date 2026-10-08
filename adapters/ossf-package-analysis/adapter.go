// Package ossfpackageanalysis is a fail-closed adapter boundary, not an OpenSSF-compatible implementation.
package ossfpackageanalysis

import "capevidence/internal/model"

// TODO SPIKE-NET-001, SPIKE-PATH-001, SPIKE-CMD-001, SPIKE-ACTION-001,
// SPIKE-RUN-001, SPIKE-COVERAGE-001, SPIKE-ARTIFACT-001, SPIKE-UNKNOWN-001.
func Parse(input []byte, lim model.Limits) (model.Bundle, []model.Diagnostic, error) {
	if lim.InputBytes <= 0 || len(input) > lim.InputBytes {
		return model.Bundle{}, nil, model.Diagnostic{ReasonCode: "resource_limit"}
	}
	return model.Bundle{}, []model.Diagnostic{{ReasonCode: "adapter_pending_spike", DecisionID: "SPIKE-UNKNOWN-001"}}, model.Diagnostic{ReasonCode: "adapter_pending_spike", DecisionID: "SPIKE-UNKNOWN-001"}
}
