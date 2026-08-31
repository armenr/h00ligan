package shape

import "testing"

// TestAlpha is an EXPORTED, uppercase-first function in a `_test.go` file. It
// MUST be flagged `is_test_only` by the extractor (Go's file-suffix convention,
// which the downstream Rust `/tests/` OR does not catch) so it lands in the test
// population, NOT the primary exported cross-tab.
func TestAlpha(t *testing.T) {
	if Alpha() != 1 {
		t.Fatal("Alpha")
	}
}
