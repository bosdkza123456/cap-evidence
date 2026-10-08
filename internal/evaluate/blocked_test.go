package evaluate

import "testing"

func TestBlockedConformance(t *testing.T) {
	t.Run("PROP-002", func(t *testing.T) { t.Skip("blocked_by: DEC-HASH-001") })
	t.Run("PROP-024", func(t *testing.T) { t.Skip("blocked_by: DEC-PATH-001") })
	t.Run("PROP-025", func(t *testing.T) { t.Skip("blocked_by: DEC-HASH-001") })
	t.Run("PROP-027", func(t *testing.T) { t.Skip("blocked_by: DEC-PATH-001") })
}
