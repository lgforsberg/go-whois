package domain

import (
	"os"
	"testing"
)

func TestTMParser(t *testing.T) {
	parser := NewTMTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/tm/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertTMRegisteredDomain(t, result)
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/tm/case8.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertTMUnregisteredDomain(t, result)
	})
}

func assertTMRegisteredDomain(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "google.tm" {
		t.Errorf("Expected domain name 'google.tm', got '%s'", result.DomainName)
	}
	if result.ExpiredDate != "2026-01-30T00:00:00+00:00" {
		t.Errorf("Expected expired date '2026-01-30T00:00:00+00:00', got '%s'", result.ExpiredDate)
	}
	if len(result.Statuses) == 0 || result.Statuses[0] != "Client Updt+Delt Lock" {
		t.Errorf("Expected status 'Client Updt+Delt Lock', got '%v'", result.Statuses)
	}
	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualTM(t, result.NameServers, expectedNS, "nameserver")
	if result.Contacts.Registrant == nil || result.Contacts.Registrant.Name != "Domain Administrator" {
		t.Errorf("Expected registrant name 'Domain Administrator', got '%v'", result.Contacts.Registrant)
	}
	if result.Contacts.Registrant != nil && result.Contacts.Registrant.Organization != "Google LLC" {
		t.Errorf("Expected registrant organization 'Google LLC', got '%s'", result.Contacts.Registrant.Organization)
	}
	if result.Contacts.Registrant != nil && len(result.Contacts.Registrant.Street) < 4 {
		t.Errorf("Expected at least 4 address lines, got %d", len(result.Contacts.Registrant.Street))
	}
}

func assertTMUnregisteredDomain(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "" {
		t.Errorf("Expected empty domain name for unregistered domain, got '%s'", result.DomainName)
	}
	if result.Contacts.Registrant != nil {
		t.Errorf("Expected nil registrant for unregistered domain, got '%v'", result.Contacts.Registrant)
	}
	if len(result.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %d", len(result.NameServers))
	}
}

func assertStringSliceEqualTM(t *testing.T, actual, expected []string, label string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d %s(s), got %d", len(expected), label, len(actual))
		return
	}
	for i, v := range expected {
		if i < len(actual) && actual[i] != v {
			t.Errorf("Expected %s '%s', got '%s'", label, v, actual[i])
		}
	}
}
