// Package model contains internal, provisional foundation types, not a frozen wire schema.
package model

import "time"

const Version = "0.1"
const SemanticState = "foundation-0.2"

type Outcome string
type Basis string
type Action string
type Decision string

const (
	Present         Outcome  = "present"
	NotObserved     Outcome  = "not_observed"
	Absent          Outcome  = "absent"
	Unknown         Outcome  = "unknown"
	Declared        Basis    = "declared"
	Observed        Basis    = "observed"
	Inferred        Basis    = "inferred"
	Succeeded       Action   = "succeeded"
	AttemptedFailed Action   = "attempted_failed"
	ActionUnknown   Action   = "action_unknown"
	Allow           Decision = "allow"
	Review          Decision = "review"
	Deny            Decision = "deny"
)

type Target struct {
	Family string `json:"family"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
}
type Scope struct {
	OS          string `json:"os,omitempty"`
	TargetScope string `json:"target_scope,omitempty"`
}
type Coverage struct {
	Capability string `json:"capability"`
	Scope      Scope  `json:"scope"`
}
type Run struct {
	ID        string     `json:"id"`
	Completed bool       `json:"completed"`
	Coverage  []Coverage `json:"coverage,omitempty"`
}
type Analyzer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Method  string `json:"method,omitempty"`
}
type Extension struct {
	Critical bool `json:"critical"`
	Value    any  `json:"value"`
}
type EvidenceRecord struct {
	Version           string               `json:"version"`
	EvidenceID        string               `json:"evidence_id,omitempty"`
	Capability        string               `json:"capability"`
	Outcome           Outcome              `json:"outcome"`
	Basis             Basis                `json:"basis,omitempty"`
	Target            Target               `json:"target"`
	Scope             Scope                `json:"scope"`
	Run               *Run                 `json:"run,omitempty"`
	Action            Action               `json:"action,omitempty"`
	Reason            string               `json:"reason,omitempty"`
	DeclarationSource string               `json:"declaration_source,omitempty"`
	DerivedFrom       []string             `json:"derived_from,omitempty"`
	Analyzer          *Analyzer            `json:"analyzer,omitempty"`
	ProofRule         string               `json:"proof_rule,omitempty"`
	Complete          bool                 `json:"complete,omitempty"`
	ObservedAt        string               `json:"observed_at,omitempty"`
	CreatedAt         string               `json:"created_at,omitempty"`
	Extensions        map[string]Extension `json:"extensions,omitempty"`
}
type Artifact struct {
	Digest string `json:"digest"`
}
type Bundle struct {
	Version  string           `json:"version"`
	Artifact Artifact         `json:"artifact"`
	Evidence []EvidenceRecord `json:"evidence"`
}
type Rule struct {
	ID         string   `json:"id"`
	Capability string   `json:"capability"`
	Effect     Decision `json:"effect"`
	Target     Target   `json:"target"`
	OS         string   `json:"os,omitempty"`
}
type Requirement struct {
	Capability string `json:"capability"`
	Kind       string `json:"kind"`
}
type Policy struct {
	Version         string        `json:"version"`
	SemanticState   string        `json:"semantic_state"`
	RegistryVersion string        `json:"registry_version"`
	RegistryDigest  string        `json:"registry_digest"`
	DecisionScope   []string      `json:"decision_scope"`
	OutOfScope      Decision      `json:"out_of_scope"`
	Rules           []Rule        `json:"rules"`
	Require         []Requirement `json:"require,omitempty"`
}
type Diagnostic struct {
	ConflictKey string `json:"conflict_key,omitempty"` // presentation-only group token, never an evidence ID
	ReasonCode  string `json:"reason_code"`
	RecordIndex *int   `json:"record_index,omitempty"`
	JSONPointer string `json:"json_pointer,omitempty"`
	DecisionID  string `json:"decision_id,omitempty"`
}

func (d Diagnostic) Error() string { return d.ReasonCode }

type TraceEntry struct {
	Kind           string   `json:"kind"`
	Capability     string   `json:"capability,omitempty"`
	Classification string   `json:"classification"`
	RuleID         string   `json:"rule_id,omitempty"`
	DerivedFrom    []string `json:"derived_from,omitempty"`
}
type Result struct {
	Decision        Decision     `json:"decision,omitempty"`
	Failure         *Diagnostic  `json:"failure,omitempty"`
	Gating          bool         `json:"gating"`
	Diagnostics     []Diagnostic `json:"diagnostics"`
	Trace           []TraceEntry `json:"trace"`
	SemanticState   string       `json:"semantic_state"`
	RegistryVersion string       `json:"registry_version"`
	RegistryDigest  string       `json:"registry_digest"`
}
type Limits struct {
	InputBytes     int
	Records        int
	Depth          int
	Keys           int
	Items          int
	ExtensionBytes int
	Rules          int
	PatternLength  int
	Implications   int
	TraceEntries   int
}

func DefaultLimits() Limits {
	return Limits{1 << 20, 1024, 32, 16384, 32768, 65536, 1024, 253, 1024, 4096}
}

type Registry struct {
	SecurityEquivalences []string
	Version              string
	Digest               string
	SemanticState        string
	Capabilities         map[string]string
}

// PlatformAuthorization is an unresolved boundary, DEC-OS-001. No default vocabulary is selected.
type PlatformAuthorization interface{ Supports(os string) bool }
type Context struct {
	Platforms      PlatformAuthorization
	EvaluationTime time.Time
	Registry       Registry
	ArtifactDigest string
	Trust          TrustContext
	MaxAge         time.Duration
	Limits         Limits
}

// TrustContext must be supplied by a protected evaluator integration, never by evidence.
// A pipeline binding binds a run to an artifact and analyzer metadata. It is not cryptographic authentication.
type PipelineBinding struct {
	ArtifactDigest  string
	AnalyzerName    string
	AnalyzerVersion string
}
type TrustContext struct {
	Runs     map[string]PipelineBinding
	Evidence []EvidenceRecord // immutable protected input snapshots, not producer metadata
}
