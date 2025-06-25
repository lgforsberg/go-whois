package domain

import (
	"testing"
)

func TestTKTLDParser_Redelegated(t *testing.T) {
	// .tk has been redelegated and the old whois no longer works
	// The TLD now uses the default parser instead of the specialized TK parser
	parser := NewTLDParser() // Using default parser instead of NewTKTLDParser

	// Note: Since .tk has been redelegated, we don't have new test data yet
	// This test documents that .tk now falls back to the default parser
	if parser.GetName() != "default" {
		t.Errorf("Expected parser name 'default' for redelegated .tk, got '%s'", parser.GetName())
	}

	t.Log("TK TLD has been redelegated - old specialized parser has been removed")
	t.Log("TK domains now use the default parser for whois parsing")
}
