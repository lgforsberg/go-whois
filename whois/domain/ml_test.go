package domain

import (
	"os"
	"testing"
)

// Helper function to assert domain basic fields
func assertDomainBasicFields(t *testing.T, result *ParsedWhois, expectedDomain, expectedCreated, expectedExpiry string) {
	t.Helper()
	if result.DomainName != expectedDomain {
		t.Errorf("Expected domain '%s', got '%s'", expectedDomain, result.DomainName)
	}
	if expectedCreated != "" && result.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected creation date '%s', got '%s'", expectedCreated, result.CreatedDateRaw)
	}
	if expectedExpiry != "" && result.ExpiredDateRaw != expectedExpiry {
		t.Errorf("Expected expiry date '%s', got '%s'", expectedExpiry, result.ExpiredDateRaw)
	}
}

// Helper function to assert domain statuses
func assertDomainStatuses(t *testing.T, result *ParsedWhois, expectedStatuses []string) {
	t.Helper()
	if len(result.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(result.Statuses), result.Statuses)
		return
	}
	for i, expected := range expectedStatuses {
		if result.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, result.Statuses[i])
		}
	}
}

// Helper function to assert domain nameservers
func assertDomainNameServers(t *testing.T, result *ParsedWhois, expectedNS []string) {
	t.Helper()
	if len(result.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d: %v", len(expectedNS), len(result.NameServers), result.NameServers)
		return
	}
	for i, expected := range expectedNS {
		if result.NameServers[i] != expected {
			t.Errorf("Expected nameserver %d to be '%s', got '%s'", i, expected, result.NameServers[i])
		}
	}
}

// Helper function to assert domain registrar
func assertDomainRegistrar(t *testing.T, result *ParsedWhois, expectedRegistrar string) {
	t.Helper()
	if result.Registrar == nil || result.Registrar.Name != expectedRegistrar {
		t.Errorf("Expected registrar '%s', got %v", expectedRegistrar, result.Registrar)
	}
}

func TestMLTLDParser_RegisteredDomain_NicML(t *testing.T) {
	// .ml has been redelegated and now uses default parser
	parser := NewTLDParser()

	data, err := os.ReadFile("testdata/ml/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read case1.txt: %v", err)
	}

	result, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse case1.txt: %v", err)
	}

	// Verify registered domain parsing
	assertDomainBasicFields(t, result, "nic.ml", "2023-06-19T00:00:00Z", "2024-06-19T00:00:00Z")
	assertDomainStatuses(t, result, []string{"active", "serverRenewProhibited"})
	assertDomainNameServers(t, result, []string{"b.nic.ml", "c.nic.ml", "d.nic.ml", "ns1.gouv.ml"})
	assertDomainRegistrar(t, result, "NIC Réservé")
}

func TestMLTLDParser_RegisteredDomain_GoogleML(t *testing.T) {
	// .ml has been redelegated and now uses default parser
	parser := NewTLDParser()

	data, err := os.ReadFile("testdata/ml/case2.txt")
	if err != nil {
		t.Fatalf("Failed to read case2.txt: %v", err)
	}

	result, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse case2.txt: %v", err)
	}

	assertDomainBasicFields(t, result, "google.ml", "", "")
	assertDomainRegistrar(t, result, "Markmonitor, Inc.")
}

func TestMLTLDParser_NotFoundDomain(t *testing.T) {
	// .ml has been redelegated and now uses default parser
	parser := NewTLDParser()

	data, err := os.ReadFile("testdata/ml/case3.txt")
	if err != nil {
		t.Fatalf("Failed to read case3.txt: %v", err)
	}

	result, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse case3.txt: %v", err)
	}

	// For not found domains, should have "not_found" status
	assertDomainStatuses(t, result, []string{"not_found"})

	// Domain name should be empty for not found
	if result.DomainName != "" {
		t.Errorf("Expected empty domain name for not found domain, got '%s'", result.DomainName)
	}
}
