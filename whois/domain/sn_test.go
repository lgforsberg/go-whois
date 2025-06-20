package domain

import (
	"os"
	"testing"
)

func TestSNParser(t *testing.T) {
	parser := NewSNTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/sn/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSNBasicFields(t, result)
		assertSNContacts(t, result)
		assertSNNameServers(t, result)
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/sn/case10.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		assertSNUnregisteredDomain(t, result)
	})
}

func assertSNBasicFields(t *testing.T, result *ParsedWhois) {
	if result.DomainName != "google.sn" {
		t.Errorf("Expected domain name 'google.sn', got '%s'", result.DomainName)
	}
	if result.CreatedDateRaw != "2003-03-22T00:00:00Z" {
		t.Errorf("Expected created date '2003-03-22T00:00:00Z', got '%s'", result.CreatedDateRaw)
	}
	if result.ExpiredDate != "2025-12-31T12:00:00+00:00" {
		t.Errorf("Expected expired date '2025-12-31T12:00:00+00:00', got '%s'", result.ExpiredDate)
	}
	if result.Registrar == nil || result.Registrar.Name != "MARKMONITOR Inc." {
		t.Errorf("Expected registrar 'MARKMONITOR Inc.', got '%v'", result.Registrar)
	}
	if len(result.Statuses) == 0 || result.Statuses[0] != "actif" {
		t.Errorf("Expected status 'actif', got '%v'", result.Statuses)
	}
}

func assertSNContacts(t *testing.T, result *ParsedWhois) {
	if result.Contacts.Registrant == nil || result.Contacts.Registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name 'Google LLC', got '%v'", result.Contacts.Registrant)
	}
	if result.Contacts.Tech == nil || result.Contacts.Tech.Name != "Google LLC" {
		t.Errorf("Expected tech contact name 'Google LLC', got '%v'", result.Contacts.Tech)
	}
	if result.Contacts.Admin == nil || result.Contacts.Admin.Name != "Google LLC" {
		t.Errorf("Expected admin contact name 'Google LLC', got '%v'", result.Contacts.Admin)
	}
	if result.Contacts.Billing == nil || result.Contacts.Billing.Name != "MarkMonitor" {
		t.Errorf("Expected billing contact name 'MarkMonitor', got '%v'", result.Contacts.Billing)
	}
}

func assertSNNameServers(t *testing.T, result *ParsedWhois) {
	expectedNS := []string{"ns3.google.com", "ns2.google.com", "ns1.google.com", "ns4.google.com"}
	if len(result.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(result.NameServers))
		return
	}
	for _, ns := range expectedNS {
		found := false
		for _, got := range result.NameServers {
			if got == ns {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected nameserver '%s' not found in result", ns)
		}
	}
}

func assertSNUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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
