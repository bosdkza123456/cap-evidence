package trust

import (
	"capevidence/internal/model"
	"reflect"
)

type Level string

const (
	Unverified    Level = "unverified"
	PipelineLocal Level = "pipeline_local"
)

func Derive(r model.EvidenceRecord, digest string, c model.TrustContext) Level {
	if r.Run == nil || r.Analyzer == nil {
		return Unverified
	}
	b, ok := c.Runs[r.Run.ID]
	if !ok || b.ArtifactDigest != digest || b.AnalyzerName != r.Analyzer.Name || b.AnalyzerVersion != r.Analyzer.Version || b.AnalyzerName == "" || b.AnalyzerVersion == "" {
		return Unverified
	}
	// A metadata match alone does not confer trust: the protected integration
	// must pin the complete evidence content it received from its local pipeline.
	for _, protected := range c.Evidence {
		if reflect.DeepEqual(r, protected) {
			return PipelineLocal
		}
	}
	return Unverified
}
