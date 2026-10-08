package cli

import (
	"bytes"
	"capevidence/internal/model"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func args() []string {
	return []string{"policy", "check", "--evidence", "../../spec/v0.1/examples/evidence.json", "--policy", "../../spec/v0.1/examples/policy.yaml", "--registry", "../../spec/v0.1/examples/registry.json", "--artifact", "../../spec/v0.1/examples/artifact.txt", "--evaluation-time", "2026-10-08T10:00:00Z"}
}
func TestCLI(t *testing.T) {
	var out bytes.Buffer
	if got := Run(args(), &out); got != 1 {
		t.Fatal(got, out.String())
	}
	var r model.Result
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Decision != model.Review || r.Failure != nil {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "api.example.com") {
		t.Fatal("target leaked")
	}
	out.Reset()
	a := append(args(), "--mode", "audit")
	if Run(a, &out) != 0 {
		t.Fatal(out.String())
	}
	out.Reset()
	a = append(args(), "--allow-not-observed")
	if Run(a, &out) != 2 {
		t.Fatal("bypass flag accepted")
	}
	out.Reset()
	a = append(args(), "--artifact-digest", "sha256:bad")
	if Run(a, &out) != 2 {
		t.Fatal("ambiguous artifact options")
	}
}

func TestRegistryModification(t *testing.T) {
	raw, e := os.ReadFile("../../spec/v0.1/examples/registry.json")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if e = os.WriteFile(path, append(raw, ' '), 0600); e != nil {
		t.Fatal(e)
	}
	a := args()
	for i := range a {
		if a[i] == "--registry" {
			a[i+1] = path
		}
	}
	var out bytes.Buffer
	if Run(a, &out) != 2 || !strings.Contains(out.String(), "unsupported_version") {
		t.Fatal("registry modification escaped pin", out.String())
	}
}
func TestSensitiveErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	raw := []byte(`{"version":"0.1","artifact":{"digest":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},"evidence":[{"version":"0.1","capability":"network.outbound","basis":"observed","outcome":"present","target":{"family":"network","host":"https://user:SECRET@private.example.com"},"scope":{}}]}`)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	a := args()
	for i := range a {
		if a[i] == "--evidence" {
			a[i+1] = path
		}
	}
	var out bytes.Buffer
	if Run(a, &out) != 2 || strings.Contains(out.String(), "SECRET") || strings.Contains(out.String(), "private.example.com") {
		t.Fatal("sensitive error output", out.String())
	}
}
