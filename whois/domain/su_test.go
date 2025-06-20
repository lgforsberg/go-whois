package domain

import (
	"os"
	"testing"
)

func TestSUParser(t *testing.T) {
	parser := NewSUTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/su/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSURegisteredDomain(t, result)
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/su/case10.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSUUnregisteredDomain(t, result)
	})
}

func assertSURegisteredDomain(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "GOOGLE.SU" {
		t.Errorf("Expected domain name 'GOOGLE.SU', got '%s'", result.DomainName)
	}
	if result.CreatedDateRaw != "2005-10-15T20:00:00Z" {
		t.Errorf("Expected created date '2005-10-15T20:00:00Z', got '%s'", result.CreatedDateRaw)
	}
	if result.ExpiredDate != "2025-10-15T21:00:00+00:00" {
		t.Errorf("Expected expired date '2025-10-15T21:00:00+00:00', got '%s'", result.ExpiredDate)
	}
	if result.Registrar == nil || result.Registrar.Name != "RUCENTER-SU" {
		t.Errorf("Expected registrar 'RUCENTER-SU', got '%v'", result.Registrar)
	}
	if len(result.Statuses) == 0 || result.Statuses[0] != "REGISTERED, DELEGATED" {
		t.Errorf("Expected status 'REGISTERED, DELEGATED', got '%v'", result.Statuses)
	}
	expectedNS := []string{"ns3.nic.ru.", "ns4.nic.ru.", "ns8.nic.ru."}
	assertStringSliceEqualSU(t, result.NameServers, expectedNS, "nameserver")
	if result.Contacts.Registrant == nil || result.Contacts.Registrant.Name != "Private Person" {
		t.Errorf("Expected registrant name 'Private Person', got '%v'", result.Contacts.Registrant)
	}
	if result.Contacts.Registrant != nil && result.Contacts.Registrant.Email != "astra@astra.moscow" {
		t.Errorf("Expected registrant email 'astra@astra.moscow', got '%s'", result.Contacts.Registrant.Email)
	}
}

func assertSUUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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

func assertStringSliceEqualSU(t *testing.T, actual, expected []string, label string) {
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
