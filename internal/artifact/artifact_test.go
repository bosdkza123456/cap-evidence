package artifact

import (
	"strings"
	"testing"
)

func TestRawHash(t *testing.T) {
	d, e := Hash(strings.NewReader("abc"))
	if e != nil || d != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(d, e)
	}
	if Bind(d, "md5:abc") == nil || Bind(d, "sha256:"+strings.Repeat("0", 64)) == nil {
		t.Fatal("weak/mismatched binding")
	}
}
