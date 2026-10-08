package parse

import (
	"bytes"
	"capevidence/internal/model"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictParsing(t *testing.T) {
	cases := []struct{ name, format, input string }{
		{"TEST-PARSE-001_duplicate_JSON", "json", `{"x":1,"x":2}`},
		{"TEST-PARSE-002_duplicate_YAML", "yaml", "x: 1\nx: 2\n"},
		{"TEST-PARSE-003_alias", "yaml", "x: &a 1\ny: *a\n"},
		{"TEST-PARSE-004_tag", "yaml", "x: !custom hi\n"},
		{"TEST-PARSE-005_implicit", "yaml", "x: 2020-01-01\n"},
		{"TEST-PARSE-006_trailing", "json", `{} {}`},
		{"TEST-PARSE-007_nonJSON_number", "yaml", "x: 0x10\n"},
		{"TEST-PARSE-008_trailing_YAML", "yaml", "x: 1\n---\nx: 2"},
		{"TEST-PARSE-009_invalid_UTF8", "json", string([]byte{123, 34, 120, 34, 58, 34, 255, 34, 125})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var x any
			if Decode([]byte(c.input), c.format, &x, model.DefaultLimits()) == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	var x any
	for _, format := range []string{"json", "yaml"} {
		input := `{"x":"yes","n":10}`
		if format == "yaml" {
			input = "x: yes\nn: 10"
		}
		if e := Decode([]byte(input), format, &x, model.DefaultLimits()); e != nil {
			t.Fatal(e)
		}
	}
}
func TestResourceLimits(t *testing.T) {
	for _, input := range []string{strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40), `{"x":[1,2,3]}`} {
		l := model.DefaultLimits()
		l.Items = 3
		var x any
		if Decode([]byte(input), "json", &x, l) == nil {
			t.Fatal("resource limit bypass")
		}
	}
	l := model.DefaultLimits()
	l.InputBytes = 2
	var x any
	if Decode([]byte(`{"x":1}`), "json", &x, l) == nil {
		t.Fatal("size limit bypass")
	}
}
func TestJSONYAMLParity(t *testing.T) {
	var a, b any
	l := model.DefaultLimits()
	if Decode([]byte(`{"x":[true,null,"yes",2]}`), "json", &a, l) != nil || Decode([]byte("x: [true, null, yes, 2]"), "yaml", &b, l) != nil {
		t.Fatal("decode failed")
	}
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if !bytes.Equal(aa, bb) {
		t.Fatal("parser differential")
	}
}
func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{}`, `{"x":1,"x":2}`, "x: &a []", `[1,null,"x"]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var out any
		_ = Decode(b, "json", &out, model.DefaultLimits())
		_ = Decode(b, "yaml", &out, model.DefaultLimits())
	})
}

func TestSurrogateEscapes(t *testing.T) {
	for _, s := range []string{`{"x":"\ud800"}`, `{"x":"\udfff"}`, `{"x":"\ud800\u0020"}`} {
		var out any
		if Decode([]byte(s), "json", &out, model.DefaultLimits()) == nil {
			t.Fatal("silently repaired surrogate")
		}
	}
	for _, s := range []string{`{"x":"\ud83d\ude00"}`, `{"x":"\\ud800"}`} {
		var out any
		if e := Decode([]byte(s), "json", &out, model.DefaultLimits()); e != nil {
			t.Fatal(e)
		}
	}
}
