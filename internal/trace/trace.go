// Package trace emits bounded, target-free presentation output. It never mutates evidence.
package trace

import (
	"capevidence/internal/model"
	"encoding/json"
	"sort"
)

func Sort(r *model.Result) {
	sort.Slice(r.Trace, func(i, j int) bool {
		a, _ := json.Marshal(r.Trace[i])
		b, _ := json.Marshal(r.Trace[j])
		return string(a) < string(b)
	})
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		a, _ := json.Marshal(r.Diagnostics[i])
		b, _ := json.Marshal(r.Diagnostics[j])
		return string(a) < string(b)
	})
}
