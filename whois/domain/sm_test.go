package domain

import (
	"os"
	"testing"
)

func TestSMParser(t *testing.T) {
	parser := NewSMTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/sm/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSMRegisteredDomain(t, result)
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/sm/case10.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSMUnregisteredDomain(t, result)
	})
}

func assertSMRegisteredDomain(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "google.sm" {
		t.Errorf("Expected domain name 'google.sm', got '%s'", result.DomainName)
	}
	if result.CreatedDateRaw != "03/04/2003" {
		t.Errorf("Expected created date '03/04/2003', got '%s'", result.CreatedDateRaw)
	}
	if len(result.Statuses) == 0 || result.Statuses[0] != "Active" {
		t.Errorf("Expected status 'Active', got '%v'", result.Statuses)
	}
	if result.Contacts.Registrant == nil || result.Contacts.Registrant.Name != "Google Llc" {
		t.Errorf("Expected registrant name 'Google Llc', got '%v'", result.Contacts.Registrant)
	}
	if result.Contacts.Registrant != nil && result.Contacts.Registrant.Email != "dns-admin@google.com" {
		t.Errorf("Expected registrant email 'dns-admin@google.com', got '%s'", result.Contacts.Registrant.Email)
	}
	if result.Contacts.Tech == nil || result.Contacts.Tech.Name != "Matt Serlin" {
		t.Errorf("Expected tech contact name 'Matt Serlin', got '%v'", result.Contacts.Tech)
	}
	if result.Contacts.Tech != nil && result.Contacts.Tech.Email != "ccops@markmonitor.com" {
		t.Errorf("Expected tech contact email 'ccops@markmonitor.com', got '%s'", result.Contacts.Tech.Email)
	}
	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualSM(t, result.NameServers, expectedNS, "nameserver")
}

func assertSMUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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

func assertStringSliceEqualSM(t *testing.T, actual, expected []string, label string) {
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
