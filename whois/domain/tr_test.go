package domain

import (
	"testing"
)

func TestTRTLDParser(t *testing.T) {
	parser := NewTRTLDParser()
	if parser.GetName() != "tr" {
		t.Errorf("Expected parser name to be 'tr', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `** Domain Name: google.tr
Domain Status: Active
Frozen Status: -
Transfer Status: The domain is LOCKED to transfer. 

** Registrant:
   Google LLC
   Hidden upon user request
   Hidden upon user request
   Hidden upon user request
   Hidden upon user request


** Registrar:
NIC Handle		: ogv40
Organization Name	: ODTÜ GELİŞTİRME VAKFI BİLGİ TEKNOLOJİLERİ SAN. VE TİC. A.Ş.
Address			: Mustafa Kemal Mahallesi Dumlupınar Bulvarı
	  No:280G/1104 Çankaya
	  06800 Ankara Türkiye
Phone			: 90-312-9881106-
Fax			: - 


** Domain Servers:
ns1.googledomains.com
ns2.googledomains.com
ns3.googledomains.com
ns4.googledomains.com


** Additional Info:
Created on..............: 2024-Aug-26.
Expires on..............: 2025-Aug-25.


** Whois Server:
Last Update Time: 2025-06-19T03:33:35+03:00
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertTRRegisteredDomain(t, parsed)
}

func TestTRTLDParserUnregistered(t *testing.T) {
	parser := NewTRTLDParser()
	whoisText := `No match found for nic.tr`
	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	assertTRUnregisteredDomain(t, parsed)
}

func assertTRRegisteredDomain(t *testing.T, parsed *ParsedWhois) {
	if parsed.DomainName != "google.tr" {
		t.Errorf("Expected domain name 'google.tr', got '%s'", parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "2024-Aug-26." {
		t.Errorf("Expected creation date '2024-Aug-26.', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "2025-Aug-25." {
		t.Errorf("Expected expiry date '2025-Aug-25.', got '%s'", parsed.ExpiredDateRaw)
	}

	if len(parsed.Statuses) < 1 || parsed.Statuses[0] != "Active" {
		t.Errorf("Expected status 'Active', got %v", parsed.Statuses)
	}

	if parsed.Registrar.IanaID != "ogv40" {
		t.Errorf("Expected registrar IanaID 'ogv40', got '%s'", parsed.Registrar.IanaID)
	}
	if parsed.Registrar.Name != "ODTÜ GELİŞTİRME VAKFI BİLGİ TEKNOLOJİLERİ SAN. VE TİC. A.Ş." {
		t.Errorf("Expected registrar name, got '%s'", parsed.Registrar.Name)
	}
	if parsed.Registrar.AbuseContactPhone != "90-312-9881106-" {
		t.Errorf("Expected registrar phone '90-312-9881106-', got '%s'", parsed.Registrar.AbuseContactPhone)
	}

	expectedNS := []string{"ns1.googledomains.com", "ns2.googledomains.com", "ns3.googledomains.com", "ns4.googledomains.com"}
	assertStringSliceEqualTR(t, parsed.NameServers, expectedNS, "nameserver")

	if parsed.Contacts.Registrant == nil || parsed.Contacts.Registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name 'Google LLC', got '%v'", parsed.Contacts.Registrant)
	}
	if parsed.Contacts.Admin == nil || len(parsed.Contacts.Admin.Street) == 0 {
		t.Errorf("Expected registrar address in admin contact, got '%v'", parsed.Contacts.Admin)
	}
}

func assertTRUnregisteredDomain(t *testing.T, parsed *ParsedWhois) {
	if parsed.DomainName != "" {
		t.Errorf("Expected empty domain name for unregistered domain, got '%s'", parsed.DomainName)
	}
	if parsed.CreatedDateRaw != "" {
		t.Errorf("Expected empty creation date for unregistered domain, got '%s'", parsed.CreatedDateRaw)
	}

	// During Phase 2 migration, expect dual status for backward compatibility
	expectedStatuses := []string{"not_found"}
	if len(parsed.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsed.Statuses), parsed.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsed.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsed.Statuses[i])
		}
	}

	if parsed.Registrar.Name != "" {
		t.Errorf("Expected empty registrar for unregistered domain, got '%s'", parsed.Registrar.Name)
	}
	if len(parsed.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %v", parsed.NameServers)
	}
	if parsed.Contacts.Registrant != nil {
		t.Error("Expected no registrant contact for unregistered domain")
	}
	if parsed.Contacts.Admin != nil {
		t.Error("Expected no admin contact for unregistered domain")
	}
}

func assertStringSliceEqualTR(t *testing.T, actual, expected []string, label string) {
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
