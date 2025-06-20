package domain

import (
	"os"
	"testing"
)

func TestTHParser(t *testing.T) {
	parser := NewTHTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/th/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertTHRegisteredDomain(t, result)
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/th/case10.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertTHUnregisteredDomain(t, result)
	})
}

func assertTHRegisteredDomain(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "GOOGLE.TH" {
		t.Errorf("Expected domain name 'GOOGLE.TH', got '%s'", result.DomainName)
	}
	if result.CreatedDateRaw != "17 Jul 2014" {
		t.Errorf("Expected created date '17 Jul 2014', got '%s'", result.CreatedDateRaw)
	}
	if result.ExpiredDate != "2025-07-16T00:00:00+00:00" {
		t.Errorf("Expected expired date '2025-07-16T00:00:00+00:00', got '%s'", result.ExpiredDate)
	}
	if result.Registrar == nil || result.Registrar.Name != "THNIC" {
		t.Errorf("Expected registrar 'THNIC', got '%v'", result.Registrar)
	}
	if len(result.Statuses) == 0 || result.Statuses[0] != "ACTIVE" {
		t.Errorf("Expected status 'ACTIVE', got '%v'", result.Statuses)
	}
	if result.Dnssec != "unsigned" {
		t.Errorf("Expected DNSSEC 'unsigned', got '%s'", result.Dnssec)
	}
	expectedNS := []string{"NS4.GOOGLE.COM", "NS3.GOOGLE.COM", "NS2.GOOGLE.COM", "NS1.GOOGLE.COM"}
	assertStringSliceEqualTH(t, result.NameServers, expectedNS, "nameserver")
	if result.Contacts.Registrant == nil || result.Contacts.Registrant.Organization != "Google LLC (กูเกิล แอลแอลซี)" {
		t.Errorf("Expected registrant organization 'Google LLC (กูเกิล แอลแอลซี)', got '%v'", result.Contacts.Registrant)
	}
	if result.Contacts.Registrant != nil && result.Contacts.Registrant.Country != "US" {
		t.Errorf("Expected registrant country 'US', got '%s'", result.Contacts.Registrant.Country)
	}
}

func assertTHUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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

func assertStringSliceEqualTH(t *testing.T, actual, expected []string, label string) {
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
