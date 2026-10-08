package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"testing"
)

func TestHarnessContainerBoundaries(t *testing.T) {
	b, e := os.ReadFile("../../docker-compose.yml")
	if e != nil {
		t.Fatal(e)
	}
	var config struct {
		Services map[string]struct {
			Privileged *bool    `yaml:"privileged"`
			CapAdd     []string `yaml:"cap_add"`
			CapDrop    []string `yaml:"cap_drop"`
			Security   []string `yaml:"security_opt"`
			ReadOnly   bool     `yaml:"read_only"`
			Network    string   `yaml:"network_mode"`
			User       string   `yaml:"user"`
			Volumes    []any    `yaml:"volumes"`
			Ports      []any    `yaml:"ports"`
		}
	}
	if e = yaml.Unmarshal(b, &config); e != nil {
		t.Fatal(e)
	}
	s, ok := config.Services["collector-harness"]
	if !ok || len(config.Services) != 1 || s.Privileged == nil || *s.Privileged {
		t.Fatal("privileged profile")
	}
	if len(s.CapAdd) != 2 || s.CapAdd[0] != "SYS_PTRACE" || s.CapAdd[1] != "NET_ADMIN" || len(s.CapDrop) != 1 || s.CapDrop[0] != "ALL" {
		t.Fatal("capability boundary changed")
	}
	if len(s.Security) != 1 || s.Security[0] != "no-new-privileges:true" || !s.ReadOnly || s.Network != "none" || s.User != "10001:10001" || len(s.Volumes) != 0 || len(s.Ports) != 0 {
		t.Fatal("isolation boundary changed")
	}
	docker, e := os.ReadFile("../../Dockerfile")
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{"USER 10001:10001", "CGO_ENABLED=0", "harness.py", "strace bubblewrap"} {
		if !strings.Contains(string(docker), required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, bad := range []string{"seccomp=unconfined", "apparmor=unconfined", "--privileged"} {
		if strings.Contains(string(b), bad) || strings.Contains(string(docker), bad) {
			t.Fatal("sandbox policy bypass")
		}
	}
}
func TestCIRequiresRealHarnessStatus(t *testing.T) {
	b, e := os.ReadFile("../../.github/workflows/ci.yml")
	if e != nil {
		t.Fatal(e)
	}
	var config struct {
		Jobs map[string]struct {
			Steps []struct {
				Run      string `yaml:"run"`
				Continue bool   `yaml:"continue-on-error"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if e = yaml.Unmarshal(b, &config); e != nil {
		t.Fatal(e)
	}
	job, ok := config.Jobs["live-harness"]
	if !ok {
		t.Fatal("missing live harness job")
	}
	found := false
	for _, s := range job.Steps {
		if strings.Contains(s.Run, "harness.py") {
			found = true
			if s.Continue || strings.Contains(s.Run, "|| true") {
				t.Fatal("BLOCKED hidden as pass")
			}
		}
	}
	if !found {
		t.Fatal("missing live invocation")
	}
	text := string(b)
	for _, req := range []string{"-v -race ./...", "FuzzInspect", "FuzzCanonicalConflictHost", "CAP_PREVIEW_TEST_BIN", "python3 -m unittest"} {
		if !strings.Contains(text, req) {
			t.Fatalf("missing CI check %s", req)
		}
	}
}
