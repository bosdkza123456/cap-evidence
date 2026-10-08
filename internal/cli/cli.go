package cli

import (
	"capevidence/internal/artifact"
	"capevidence/internal/evaluate"
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Run(args []string, out io.Writer) int {
	fail := func(code string) int {
		json.NewEncoder(out).Encode(model.Result{Failure: &model.Diagnostic{ReasonCode: code}, Gating: true, Diagnostics: []model.Diagnostic{}, Trace: []model.TraceEntry{}})
		return 2
	}
	if len(args) < 2 || args[0] != "policy" || args[1] != "check" {
		return fail("invalid_command")
	}
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	evidence := fs.String("evidence", "", "evidence file")
	policyPath := fs.String("policy", "", "policy authoring file")
	artifactPath := fs.String("artifact", "", "raw artifact file")
	digest := fs.String("artifact-digest", "", "sha256 digest")
	evalTime := fs.String("evaluation-time", "", "explicit RFC3339 evaluation time")
	registryPath := fs.String("registry", "", "operator-pinned registry file")
	mode := fs.String("mode", "enforce", "enforce, audit, or inform")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 || *evidence == "" || *policyPath == "" || *registryPath == "" || *evalTime == "" || (*artifactPath != "" && *digest != "") || (*mode != "enforce" && *mode != "audit" && *mode != "inform") {
		return fail("invalid_arguments")
	}
	at, e := time.Parse(time.RFC3339Nano, *evalTime)
	if e != nil {
		return fail("invalid_evaluation_time")
	}
	lim := model.DefaultLimits()
	read := func(path string) ([]byte, error) {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, int64(lim.InputBytes)+1))
	}
	decode := func(path string, v any) error {
		b, e := read(path)
		if e != nil {
			return model.Diagnostic{ReasonCode: "input_read_error"}
		}
		format := "json"
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			format = "yaml"
		}
		return parse.Decode(b, format, v, lim)
	}
	var b model.Bundle
	var p model.Policy
	resultError := func(e error, class string) int {
		d, ok := e.(model.Diagnostic)
		if !ok {
			d = model.Diagnostic{ReasonCode: class}
		}
		r := model.Result{Failure: &d, Gating: true, Diagnostics: []model.Diagnostic{}, Trace: []model.TraceEntry{}}
		json.NewEncoder(out).Encode(r)
		return 2
	}
	if e := decode(*evidence, &b); e != nil {
		return resultError(e, "invalid_evidence")
	}
	if e := decode(*policyPath, &p); e != nil {
		return resultError(e, "invalid_policy")
	}
	var wireRegistry struct {
		Version              string            `json:"version"`
		SemanticState        string            `json:"semantic_state"`
		Capabilities         map[string]string `json:"capabilities"`
		SecurityEquivalences []string          `json:"security_equivalences,omitempty"`
	}
	registryBytes, e := read(*registryPath)
	if e != nil {
		return fail("input_read_error")
	}
	if e := parse.Decode(registryBytes, "json", &wireRegistry, lim); e != nil {
		return resultError(e, "invalid_registry")
	}
	registryDigest, e := artifact.Hash(strings.NewReader(string(registryBytes)))
	if e != nil {
		return fail("invalid_registry")
	}
	// No producer-controlled trust input or CLI trust elevation is accepted.
	actual := *digest
	if *artifactPath != "" {
		f, e := os.Open(*artifactPath)
		if e != nil {
			return fail("artifact_read_error")
		}
		actual, e = artifact.Hash(f)
		f.Close()
		if e != nil {
			return resultError(e, "artifact_read_error")
		}
	}
	if actual == "" {
		return fail("artifact_binding_required")
	}
	r := evaluate.Check(b, p, model.Context{EvaluationTime: at, ArtifactDigest: actual, Limits: lim, Registry: model.Registry{Version: wireRegistry.Version, Digest: registryDigest, SemanticState: wireRegistry.SemanticState, Capabilities: wireRegistry.Capabilities, SecurityEquivalences: wireRegistry.SecurityEquivalences}})
	r.Gating = *mode == "enforce"
	if json.NewEncoder(out).Encode(r) != nil {
		return 2
	}
	return evaluate.ExitCode(r, *mode)
}
