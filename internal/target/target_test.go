package target

import (
	"capevidence/internal/model"
	"testing"
)

func TestTargets(t *testing.T) {
	for _, s := range []string{"127.1", "0x7f.1", "010.0.0.1", "fe80::1%eth0", "a_b.example.com", "_sip._tcp.example.com", "é.example.com", "example.com:443", "https://a.example.com", "a..com"} {
		if _, e := Host(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, s := range []string{"api.example.com", "_dmarc.example.com", "127.0.0.1", "::ffff:127.0.0.1", "2001:db8::1", "xn--bcher-kva.example"} {
		if _, e := Host(s); e != nil {
			t.Fatalf("rejected %q: %v", s, e)
		}
	}
}
func TestGlob(t *testing.T) {
	for _, s := range []string{"*", "*.*", "*.com", "ab*.example.com", "[a].example.com", "{a,b}.example.com"} {
		if Pattern(s, model.Allow) == nil {
			t.Fatal("unsafe allow")
		}
	}
	for _, s := range []string{"api.example.com", "example.com", "a.b.example.com", "_dmarc.example.com"} {
		got, e := MatchHost("*.example.com", s, model.Allow)
		if e != nil || got != (s == "api.example.com") {
			t.Fatal(s, got, e)
		}
	}
}
func TestPaths(t *testing.T) {
	for _, s := range []string{"relative/file", "~/.ssh", "C:foo", "/a\x00b"} {
		if _, e := RawPath(s); e == nil {
			t.Fatal("accepted unsafe path")
		}
	}
	parent, e := RawPath("/tmp/../a")
	if e != nil || !parent {
		t.Fatal("lost raw parent")
	}
}
func FuzzHost(f *testing.F) {
	for _, s := range []string{"api.example.com", "127.1", "::ffff:127.0.0.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1024 {
			return
		}
		_, _ = Host(s)
		_, _ = MatchHost("*.example.com", s, model.Allow)
	})
}
