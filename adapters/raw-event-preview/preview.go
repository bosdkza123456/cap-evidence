// Package raweventpreview implements a proposed research contract only.
// It produces inspection candidates, never CAP evidence or authorization.
package raweventpreview

import (
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const Version = "raw-event-proposed-0.1"

type Phase struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type Coverage struct {
	Complete      *bool `json:"complete"`
	Dropped       *int  `json:"dropped"`
	ParseFailures *int  `json:"parse_failures"`
}
type Event struct {
	ID         string `json:"id"`
	Phase      string `json:"phase"`
	Operation  string `json:"operation"`
	Result     string `json:"result"`
	Host       string `json:"host,omitempty"`
	Port       *int   `json:"port,omitempty"`
	Path       string `json:"path,omitempty"`
	Executable string `json:"executable,omitempty"`
	ObservedAt string `json:"observed_at"`
}
type Input struct {
	Version        string         `json:"version"`
	RunID          string         `json:"run_id"`
	ArtifactDigest string         `json:"artifact_digest"`
	Analyzer       model.Analyzer `json:"analyzer"`
	Phases         []Phase        `json:"phases"`
	Coverage       Coverage       `json:"coverage"`
	Events         []Event        `json:"events"`
}

// Binding must be supplied by a protected integration, never decoded from input.
// PayloadDigest pins the complete original bytes. This is not signature verification.
type Binding struct{ RunID, ArtifactDigest, PayloadDigest, AnalyzerName, AnalyzerVersion string }

// Candidate deliberately retains the port and original targets and has no Outcome or Trust.
type Candidate struct {
	EventID, Phase, Capability, Operation, Result, Host, Path, Executable, ObservedAt string
	Port                                                                              *int
}
type Preview struct {
	Candidates         []Candidate
	Diagnostics        []model.Diagnostic
	AuthorizationReady bool
}

func fail(code string) (Preview, error) { return Preview{}, model.Diagnostic{ReasonCode: code} }
func digest(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func Inspect(b []byte, binding Binding, lim model.Limits) (Preview, error) {
	var in Input
	if err := parse.Decode(b, "json", &in, lim); err != nil {
		return Preview{}, err
	}
	if in.Version != Version || in.RunID == "" || !digest(in.ArtifactDigest) || in.Analyzer.Name == "" || in.Analyzer.Version == "" {
		return fail("invalid_raw_contract")
	}
	sum := sha256.Sum256(b)
	if !digest(binding.PayloadDigest) || hex.EncodeToString(sum[:]) != binding.PayloadDigest || binding.RunID != in.RunID || binding.ArtifactDigest != in.ArtifactDigest || binding.AnalyzerName != in.Analyzer.Name || binding.AnalyzerVersion != in.Analyzer.Version {
		return fail("raw_binding_mismatch")
	}
	if lim.Records <= 0 || len(in.Events) > lim.Records || len(in.Phases) == 0 || len(in.Phases) > lim.Records {
		return fail("resource_limit")
	}
	c := in.Coverage
	if c.Complete == nil || c.Dropped == nil || c.ParseFailures == nil || *c.Dropped < 0 || *c.ParseFailures < 0 {
		return fail("invalid_raw_contract")
	}
	phases := map[string]string{}
	incomplete := !*c.Complete || *c.Dropped != 0 || *c.ParseFailures != 0
	for _, p := range in.Phases {
		if p.Name == "" || phases[p.Name] != "" {
			return fail("invalid_raw_contract")
		}
		phases[p.Name] = p.Status
		switch p.Status {
		case "completed":
		case "failed", "not_run":
			incomplete = true
		default:
			return fail("invalid_raw_contract")
		}
	}
	out := Preview{Diagnostics: []model.Diagnostic{{ReasonCode: "proposed_contract_not_authorization"}}}
	if incomplete {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{ReasonCode: "incomplete_raw_coverage"})
	}
	ids := map[string]bool{}
	for i, e := range in.Events {
		if e.ID == "" || ids[e.ID] || (phases[e.Phase] == "" || phases[e.Phase] == "not_run") {
			return fail("invalid_raw_contract")
		}
		ids[e.ID] = true
		if _, err := time.Parse(time.RFC3339Nano, e.ObservedAt); err != nil {
			return fail("invalid_raw_contract")
		}
		switch e.Result {
		case "succeeded", "failed", "attempted", "unknown":
		default:
			return fail("invalid_raw_contract")
		}
		candidate := Candidate{EventID: e.ID, Phase: e.Phase, Operation: e.Operation, Result: e.Result, Host: e.Host, Path: e.Path, Executable: e.Executable, ObservedAt: e.ObservedAt}
		if e.Port != nil {
			v := *e.Port
			candidate.Port = &v
		}
		switch e.Operation {
		case "connect", "bind":
			if e.Host == "" || e.Port == nil || *e.Port < 0 || *e.Port > 65535 || e.Path != "" || e.Executable != "" {
				return fail("invalid_raw_contract")
			}
			if e.Operation == "connect" {
				candidate.Capability = "network.outbound"
			}
		case "read", "write", "delete", "stat":
			if e.Path == "" || e.Host != "" || e.Port != nil || e.Executable != "" {
				return fail("invalid_raw_contract")
			}
			if e.Operation != "stat" {
				candidate.Capability = "filesystem." + e.Operation
			}
		case "exec":
			if e.Executable == "" || e.Host != "" || e.Port != nil || e.Path != "" {
				return fail("invalid_raw_contract")
			}
			candidate.Capability = "process.exec"
		default:
			idx := i
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{ReasonCode: "unsupported_raw_event", RecordIndex: &idx})
		}
		if candidate.Capability == "" {
			idx := i
			out.Diagnostics = append(out.Diagnostics, model.Diagnostic{ReasonCode: "unmapped_raw_operation", RecordIndex: &idx})
		}
		out.Candidates = append(out.Candidates, candidate)
	}
	return out, nil
}
