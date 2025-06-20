package domain

import (
	"os"
	"testing"
)

func TestSIParser(t *testing.T) {
	parser := NewSITLDParser()

	// Test registered domain
	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/si/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}

		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}

		// Check domain name
		if result.DomainName != "google.si" {
			t.Errorf("Expected domain name 'google.si', got '%s'", result.DomainName)
		}

		// Check registrar
		if result.Registrar == nil || result.Registrar.Name != "Markmonitor Inc." {
			t.Errorf("Expected registrar 'Markmonitor Inc.', got '%v'", result.Registrar)
		}

		// Check registrar URL
		if result.Registrar.URL != "http://www.markmonitor.com" {
			t.Errorf("Expected registrar URL 'http://www.markmonitor.com', got '%s'", result.Registrar.URL)
		}

		// Check nameservers
		expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
		if len(result.NameServers) != len(expectedNS) {
			t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(result.NameServers))
		}
		for i, ns := range expectedNS {
			if i < len(result.NameServers) && result.NameServers[i] != ns {
				t.Errorf("Expected nameserver '%s', got '%s'", ns, result.NameServers[i])
			}
		}

		// Check registrant
		if result.Contacts.Registrant == nil || result.Contacts.Registrant.ID != "G830057" {
			t.Errorf("Expected registrant ID 'G830057', got '%v'", result.Contacts.Registrant)
		}

		// Check statuses
		expectedStatuses := []string{"client_delete_prohibited", "client_update_prohibited"}
		if len(result.Statuses) != len(expectedStatuses) {
			t.Errorf("Expected %d statuses, got %d", len(expectedStatuses), len(result.Statuses))
		}
		for i, status := range expectedStatuses {
			if i < len(result.Statuses) && result.Statuses[i] != status {
				t.Errorf("Expected status '%s', got '%s'", status, result.Statuses[i])
			}
		}

		// Check dates
		if result.CreatedDateRaw != "2005-04-04" {
			t.Errorf("Expected created date '2005-04-04', got '%s'", result.CreatedDateRaw)
		}
		if result.ExpiredDate != "2026-07-19T00:00:00+00:00" {
			t.Errorf("Expected expired date '2026-07-19T00:00:00+00:00', got '%s'", result.ExpiredDate)
		}
	})

	// Test unregistered domain
	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/si/case8.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}

		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}

		// Check that domain name is empty for unregistered domain
		if result.DomainName != "" {
			t.Errorf("Expected empty domain name for unregistered domain, got '%s'", result.DomainName)
		}

		// Check that registrar is empty
		if result.Registrar == nil || result.Registrar.Name != "" {
			t.Errorf("Expected empty registrar for unregistered domain, got '%v'", result.Registrar)
		}

		// Check that nameservers are empty
		if len(result.NameServers) != 0 {
			t.Errorf("Expected no nameservers for unregistered domain, got %d", len(result.NameServers))
		}
	})
}
