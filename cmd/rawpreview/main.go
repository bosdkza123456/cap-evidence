// rawpreview validates research inputs; it never emits targets or authorization.
package main

import (
	"capevidence/adapters/raw-event-preview"
	"capevidence/internal/model"
	"capevidence/internal/parse"
	"encoding/json"
	"flag"
	"io"
	"os"
)

type binding struct {
	RunID          string         `json:"run_id"`
	ArtifactDigest string         `json:"artifact_digest"`
	PayloadDigest  string         `json:"payload_digest"`
	Analyzer       model.Analyzer `json:"analyzer"`
	TraceDigest    string         `json:"trace_digest"`
	SourceDigest   string         `json:"source_digest"`
	StartedAt      string         `json:"started_at"`
	EndedAt        string         `json:"ended_at"`
}

func read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, model.Diagnostic{ReasonCode: "input_unavailable"}
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return nil, model.Diagnostic{ReasonCode: "input_unavailable"}
	}
	if len(b) > 1<<20 {
		return nil, model.Diagnostic{ReasonCode: "resource_limit"}
	}
	return b, nil
}
func run() int {
	payload := flag.String("payload", "", "payload file")
	context := flag.String("binding", "", "protected local binding file")
	flag.Parse()
	code := "invalid_arguments"
	var out raweventpreview.Preview
	if *payload != "" && *context != "" && flag.NArg() == 0 {
		b, e := read(*payload)
		if e == nil {
			var raw []byte
			raw, e = read(*context)
			if e == nil {
				var bind binding
				e = parse.Decode(raw, "json", &bind, model.DefaultLimits())
				if e == nil {
					out, e = raweventpreview.Inspect(b, raweventpreview.Binding{RunID: bind.RunID, ArtifactDigest: bind.ArtifactDigest, PayloadDigest: bind.PayloadDigest, AnalyzerName: bind.Analyzer.Name, AnalyzerVersion: bind.Analyzer.Version}, model.DefaultLimits())
				}
			}
		}
		if e == nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"authorization_ready": false, "candidates": len(out.Candidates), "diagnostics": out.Diagnostics})
			return 0
		}
		if d, ok := e.(model.Diagnostic); ok {
			code = d.ReasonCode
		} else {
			code = "preview_failed"
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"authorization_ready": false, "blocker": code})
	return 2
}
func main() { os.Exit(run()) }
