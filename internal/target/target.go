// Package target implements pure host primitives and raw path checks. Path matching is blocked.
package target

import (
	"capevidence/internal/model"
	"net/netip"
	"strings"
	"unicode"
)

func invalid() error { return model.Diagnostic{ReasonCode: "invalid_target"} }
func Host(s string) (string, error) {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "%/\\@[]") {
		return "", invalid()
	}
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.String(), nil
	}
	if strings.Contains(s, ":") {
		return "", model.Diagnostic{ReasonCode: "unresolved_semantics", DecisionID: "DEC-PORT-001"}
	}
	labels := strings.Split(s, ".")
	numeric := true
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			numeric = false
		}
	}
	if numeric {
		return "", invalid()
	}
	for i, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return "", invalid()
		}
		if strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0X") {
			return "", invalid()
		}
		if strings.HasPrefix(l, "_") {
			if i != 0 || len(l) == 1 {
				return "", invalid()
			}
			l = l[1:]
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", invalid()
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", invalid()
			}
		}
	}
	return strings.ToLower(s), nil
}
func Pattern(p string, effect model.Decision) error {
	if len(p) == 0 || len(p) > 253 {
		return model.Diagnostic{ReasonCode: "invalid_policy"}
	}
	if !strings.Contains(p, "*") {
		_, e := Host(p)
		if e != nil {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		return nil
	}
	labels := strings.Split(p, ".")
	suffix := 0
	for _, l := range labels {
		if l == "*" {
			suffix = 0
			continue
		}
		if strings.Contains(l, "*") {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		if _, e := Host(l); e != nil {
			return model.Diagnostic{ReasonCode: "invalid_policy"}
		}
		suffix++
	}
	if effect == model.Allow && suffix < 2 {
		return model.Diagnostic{ReasonCode: "invalid_policy"}
	}
	return nil
}
func MatchHost(pattern, host string, effect model.Decision) (bool, error) {
	if e := Pattern(pattern, effect); e != nil {
		return false, e
	}
	h, e := Host(host)
	if e != nil {
		return false, e
	}
	p := strings.ToLower(pattern)
	if !strings.Contains(p, "*") {
		canonicalPattern, e := Host(p)
		if e != nil {
			return false, e
		}
		return canonicalPattern == h, nil
	}
	// IP addresses never match DNS wildcard patterns.
	if _, e := netip.ParseAddr(h); e == nil {
		return false, nil
	}
	a, b := strings.Split(p, "."), strings.Split(h, ".")
	if len(a) != len(b) {
		return false, nil
	}
	for i := range a {
		if a[i] == "*" {
			if strings.HasPrefix(b[i], "_") {
				return false, nil
			}
			continue
		}
		if a[i] != b[i] {
			return false, nil
		}
	}
	return true, nil
}

const MappedIPRestrictiveV1 = "ipv4_mapped_ipv6_restrictive_v1"

func MatchRegisteredHost(pattern, host string, effect model.Decision, equivalences []string) (bool, error) {
	matched, err := MatchHost(pattern, host, effect)
	if err != nil || matched || effect == model.Allow {
		return matched, err
	}
	enabled := false
	for _, id := range equivalences {
		if id == MappedIPRestrictiveV1 {
			enabled = true
		}
	}
	if !enabled {
		return false, nil
	}
	left, e := netip.ParseAddr(pattern)
	if e != nil {
		return false, nil
	}
	right, e := netip.ParseAddr(host)
	if e != nil {
		return false, nil
	}
	return left.Unmap() == right.Unmap(), nil
}
func RawPath(s string) (bool, error) {
	if s == "" {
		return false, invalid()
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false, invalid()
		}
	}
	parent := false
	for _, part := range strings.FieldsFunc(s, func(c rune) bool { return c == '/' || c == '\\' }) {
		if part == ".." {
			parent = true
		}
	}
	absolute := strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\\\") || (len(s) >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
	if !absolute {
		return parent, invalid()
	}
	return parent, nil
}

// PathCanonicalizer is an unresolved semantic boundary: DEC-PATH-001/002, DEC-UNICODE-001.
type PathCanonicalizer interface {
	CanonicalPath(raw, os string) (string, error)
}

// ExecutableMatcher is blocked by DEC-CMD-001; executable.name cannot authorize.
type ExecutableMatcher interface {
	Match(evidence model.Target, rule model.Target, effect model.Decision) (bool, error)
}

func Validate(t model.Target) error {
	switch t.Family {
	case "network":
		if t.Path != "" || t.Name != "" {
			return invalid()
		}
		_, e := Host(t.Host)
		return e
	case "filesystem":
		if t.Host != "" || t.Name != "" {
			return invalid()
		}
		_, e := RawPath(t.Path)
		return e
	case "executable":
		if t.Host != "" || t.Path != "" || t.Name == "" {
			return invalid()
		}
		for _, c := range t.Name {
			if unicode.IsControl(c) {
				return invalid()
			}
		}
		return nil
	default:
		return invalid()
	}
}
