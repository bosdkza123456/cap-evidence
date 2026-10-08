// Package artifact hashes raw bytes without unpacking or executing input.
package artifact

import (
	"capevidence/internal/model"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

func ValidDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, e := hex.DecodeString(s[7:])
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func Hash(r io.Reader) (string, error) {
	h := sha256.New()
	if _, e := io.Copy(h, r); e != nil {
		return "", model.Diagnostic{ReasonCode: "artifact_read_error"}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func Bind(expected, actual string) error {
	if !ValidDigest(expected) || !ValidDigest(actual) {
		return model.Diagnostic{ReasonCode: "invalid_artifact_digest"}
	}
	if expected != actual {
		return model.Diagnostic{ReasonCode: "artifact_mismatch"}
	}
	return nil
}
