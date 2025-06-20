package domain

import (
	"os"
	"testing"
)

func TestTGParser(t *testing.T) {
	parser := NewTGTLDParser()

	t.Run("registered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/tg/case1.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		if result.DomainName != "google.tg" {
			t.Errorf("Expected domain name 'google.tg', got '%s'", result.DomainName)
		}
		if result.CreatedDateRaw != "2024-12-03" {
			t.Errorf("Expected created date '2024-12-03', got '%s'", result.CreatedDateRaw)
		}
		if result.ExpiredDate != "2025-08-12T00:00:00+00:00" {
			t.Errorf("Expected expired date '2025-08-12T00:00:00+00:00', got '%s'", result.ExpiredDate)
		}
		if result.Registrar == nil || result.Registrar.Name != "NETMASTER SARL" {
			t.Errorf("Expected registrar 'NETMASTER SARL', got '%v'", result.Registrar)
		}
		if len(result.Statuses) == 0 || result.Statuses[0] != "Activ&eacute;" {
			t.Errorf("Expected status 'Activ&eacute;', got '%v'", result.Statuses)
		}
		expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
		if len(result.NameServers) != len(expectedNS) {
			t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(result.NameServers))
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
		if result.Contacts.Registrant == nil || result.Contacts.Registrant.Name != "Google Inc" {
			t.Errorf("Expected registrant name 'Google Inc', got '%v'", result.Contacts.Registrant)
		}
		if result.Contacts.Registrant != nil && result.Contacts.Registrant.Email != "dns-admin@google.com" {
			t.Errorf("Expected registrant email 'dns-admin@google.com', got '%s'", result.Contacts.Registrant.Email)
		}
		if result.Contacts.Admin == nil || result.Contacts.Admin.Name != "Google Inc" {
			t.Errorf("Expected admin contact name 'Google Inc', got '%v'", result.Contacts.Admin)
		}
		if result.Contacts.Tech == nil || result.Contacts.Tech.Name != "Google Inc" {
			t.Errorf("Expected tech contact name 'Google Inc', got '%v'", result.Contacts.Tech)
		}
	})

	t.Run("unregistered domain", func(t *testing.T) {
		data, err := os.ReadFile("testdata/tg/case10.txt")
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}
		result, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Fatalf("Failed to parse whois data: %v", err)
		}
		if result.DomainName != "" {
			t.Errorf("Expected empty domain name for unregistered domain, got '%s'", result.DomainName)
		}
		if result.Contacts.Registrant != nil {
			t.Errorf("Expected nil registrant for unregistered domain, got '%v'", result.Contacts.Registrant)
		}
		if len(result.NameServers) != 0 {
			t.Errorf("Expected no nameservers for unregistered domain, got %d", len(result.NameServers))
		}
	})
}
