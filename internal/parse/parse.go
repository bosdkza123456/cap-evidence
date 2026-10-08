// Package parse applies identical bounded, strict semantics to JSON and YAML authoring input.
package parse

import (
	"bytes"
	"capevidence/internal/model"
	"encoding/hex"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func failure(code string) error { return model.Diagnostic{ReasonCode: code} }
func Decode(data []byte, format string, out any, lim model.Limits) error {
	if lim.InputBytes <= 0 || lim.Depth <= 0 || lim.Keys <= 0 || lim.Items <= 0 {
		return failure("resource_limit")
	}
	if len(data) > lim.InputBytes {
		return failure("resource_limit")
	}
	if !utf8.Valid(data) {
		return failure("invalid_encoding")
	}
	var raw any
	var err error
	if format == "json" {
		if !validSurrogates(data) {
			return failure("invalid_encoding")
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		keys, items := 0, 0
		raw, err = readJSON(d, 0, &keys, &items, lim)
		if err == nil {
			_, e := d.Token()
			if e != io.EOF {
				err = failure("trailing_input")
			}
		}
	} else if format == "yaml" {
		var n yaml.Node
		d := yaml.NewDecoder(bytes.NewReader(data))
		err = d.Decode(&n)
		if err == nil {
			var extra yaml.Node
			if d.Decode(&extra) != io.EOF {
				err = failure("trailing_input")
			}
		}
		if err == nil {
			k, i := 0, 0
			raw, err = readYAML(&n, 0, &k, &i, lim)
		}
	} else {
		return failure("unsupported_format")
	}
	if err != nil {
		if _, ok := err.(model.Diagnostic); ok {
			return err
		}
		return failure("parse_error")
	}
	// Reject restrictive OS fields by presence, including explicit empty/null values.
	// A plain Go string cannot distinguish these wire inputs from an omitted field.
	if _, isPolicy := out.(*model.Policy); isPolicy {
		if root, ok := raw.(map[string]any); ok {
			if rules, ok := root["rules"].([]any); ok {
				for _, value := range rules {
					if rule, ok := value.(map[string]any); ok {
						effect, _ := rule["effect"].(string)
						if _, present := rule["os"]; present && (effect == "deny" || effect == "review") {
							return failure("invalid_policy")
						}
					}
				}
			}
		}
	}
	normalized, err := json.Marshal(raw)
	if err != nil {
		return failure("parse_error")
	}
	d := json.NewDecoder(bytes.NewReader(normalized))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		switch out.(type) {
		case *model.Bundle:
			return failure("invalid_evidence")
		case *model.Policy:
			return failure("invalid_policy")
		}
		return failure("schema_error")
	}
	return nil
}
func readJSON(d *json.Decoder, depth int, keys, items *int, lim model.Limits) (any, error) {
	if depth > lim.Depth {
		return nil, failure("resource_limit")
	}
	*items++
	if *items > lim.Items {
		return nil, failure("resource_limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			t, e := d.Token()
			if e != nil {
				return nil, e
			}
			k, ok := t.(string)
			if !ok {
				return nil, failure("parse_error")
			}
			if _, ok = m[k]; ok {
				return nil, failure("duplicate_key")
			}
			*keys++
			if *keys > lim.Keys {
				return nil, failure("resource_limit")
			}
			v, e := readJSON(d, depth+1, keys, items, lim)
			if e != nil {
				return nil, e
			}
			m[k] = v
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('}') {
			return nil, failure("parse_error")
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := readJSON(d, depth+1, keys, items, lim)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		t, err = d.Token()
		if err != nil || t != json.Delim(']') {
			return nil, failure("parse_error")
		}
		return a, nil
	default:
		return nil, failure("parse_error")
	}
}
func readYAML(n *yaml.Node, depth int, keys, items *int, lim model.Limits) (any, error) {
	if depth > lim.Depth {
		return nil, failure("resource_limit")
	}
	*items++
	if *items > lim.Items {
		return nil, failure("resource_limit")
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
		return nil, failure("unsafe_yaml")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, failure("parse_error")
		}
		return readYAML(n.Content[0], depth, keys, items, lim)
	case yaml.MappingNode:
		m := map[string]any{}
		for j := 0; j < len(n.Content); j += 2 {
			kn := n.Content[j]
			if kn.Tag != "!!str" || kn.Anchor != "" || kn.Style&yaml.TaggedStyle != 0 {
				return nil, failure("unsafe_yaml")
			}
			k := kn.Value
			if k == "<<" {
				return nil, failure("unsafe_yaml")
			}
			if _, ok := m[k]; ok {
				return nil, failure("duplicate_key")
			}
			*keys++
			if *keys > lim.Keys {
				return nil, failure("resource_limit")
			}
			v, e := readYAML(n.Content[j+1], depth+1, keys, items, lim)
			if e != nil {
				return nil, e
			}
			m[k] = v
		}
		return m, nil
	case yaml.SequenceNode:
		a := []any{}
		for _, child := range n.Content {
			v, e := readYAML(child, depth+1, keys, items, lim)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!null":
			if n.Value != "null" && n.Value != "~" && n.Value != "" {
				return nil, failure("unsafe_yaml")
			}
			return nil, nil
		case "!!bool":
			if n.Value == "true" {
				return true, nil
			}
			if n.Value == "false" {
				return false, nil
			}
			return nil, failure("unsafe_yaml")
		case "!!int", "!!float":
			if strings.ContainsAny(n.Value, "_+xXoObB") {
				return nil, failure("unsafe_yaml")
			}
			var v any
			d := json.NewDecoder(strings.NewReader(n.Value))
			d.UseNumber()
			if d.Decode(&v) != nil {
				return nil, failure("unsafe_yaml")
			}
			if _, ok := v.(json.Number); !ok {
				return nil, failure("unsafe_yaml")
			}
			if _, e := strconv.ParseFloat(n.Value, 64); e != nil {
				return nil, failure("unsafe_yaml")
			}
			if d.Decode(new(any)) != io.EOF {
				return nil, failure("unsafe_yaml")
			}
			return v, nil
		default:
			return nil, failure("unsafe_yaml")
		}
	default:
		return nil, failure("parse_error")
	}
}

// encoding/json replaces unpaired UTF-16 escapes. Reject them before decoding so
// invalid identity-bearing strings cannot silently normalize to a replacement rune.
func validSurrogates(b []byte) bool {
	quoted := false
	code := func(i int) (uint16, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		var dst [2]byte
		_, e := hex.Decode(dst[:], b[i:i+4])
		return uint16(dst[0])<<8 | uint16(dst[1]), e == nil
	}
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		v, ok := code(i + 1)
		if !ok {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, ok := code(i + 3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
