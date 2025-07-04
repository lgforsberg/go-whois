package domain

import (
	"testing"
)

func TestDKTLDParser(t *testing.T) {
	parser := NewDKTLDParser()
	if parser.GetName() != "dk" {
		t.Errorf("Expected parser name to be 'dk', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `# Hello 63.35.110.58. Your session has been logged.
#
# Copyright (c) 2002 - 2025 by Punktum dk A/S
#
# Version: 5.4.0
#
# The data in the DK Whois database is provided by Punktum dk A/S
# for information purposes only, and to assist persons in obtaining
# information about or related to a domain name registration record.
# We do not guarantee its accuracy. We will reserve the right to remove
# access for entities abusing the data, without notice.
#
# Any use of this material to target advertising or similar activities
# are explicitly forbidden and will be prosecuted. Punktum dk A/S
# requests to be notified of any such activities or suspicions thereof.

Domain:               google.dk
DNS:                  google.dk
Registered:           1999-01-10
Expires:              2026-03-31
Registrar:            MarkMonitor Inc.
Registration period:  1 year
VID:                  no
DNSSEC:               Unsigned delegation
Status:               Active

Registrant
Handle:               ***N/A***
Name:                 Google LLC
Attention:            Domain Administrator
Address:              1600 Amphitheatre Parkway
Postalcode:           94043
City:                 Mountain View
Country:              US
Phone:                +1 650-253-0000

Nameservers
Hostname:             ns1.google.com
Hostname:             ns2.google.com
Hostname:             ns3.google.com
Hostname:             ns4.google.com`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertDKBasicFields(t, parsedWhois)
	assertDKContacts(t, parsedWhois)
	assertDKNameServers(t, parsedWhois)

	// Test unregistered domain (case8)
	rawtextFree := `# Hello 63.35.110.58. Your session has been logged.
#
# Copyright (c) 2002 - 2025 by Punktum dk A/S
#
# Version: 5.4.0
#
# The data in the DK Whois database is provided by Punktum dk A/S
# for information purposes only, and to assist persons in obtaining
# information about or related to a domain name registration record.
# We do not guarantee its accuracy. We will reserve the right to remove
# access for entities abusing the data, without notice.
#
# Any use of this material to target advertising or similar activities
# are explicitly forbidden and will be prosecuted. Punktum dk A/S
# requests to be notified of any such activities or suspicions thereof.

No entries found for the selected source.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertDKUnregisteredDomain(t, parsedWhoisFree)
}

func assertDKBasicFields(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.dk" {
		t.Errorf("Expected domain name to be 'google.dk', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "Active" {
		t.Errorf("Expected status to be 'Active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != "1999-01-10" {
		t.Errorf("Expected created date raw to be '1999-01-10', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2026-03-31" {
		t.Errorf("Expected expired date raw to be '2026-03-31', got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertDKContacts(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact to be parsed")
		return
	}

	registrant := parsedWhois.Contacts.Registrant
	if registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name to be 'Google LLC', got '%s'", registrant.Name)
	}

	if len(registrant.Street) != 1 || registrant.Street[0] != "1600 Amphitheatre Parkway" {
		t.Errorf("Expected registrant street to be '1600 Amphitheatre Parkway', got %v", registrant.Street)
	}

	if registrant.Postal != "94043" {
		t.Errorf("Expected registrant postal to be '94043', got '%s'", registrant.Postal)
	}

	if registrant.City != "Mountain View" {
		t.Errorf("Expected registrant city to be 'Mountain View', got '%s'", registrant.City)
	}

	if registrant.Country != "US" {
		t.Errorf("Expected registrant country to be 'US', got '%s'", registrant.Country)
	}

	if registrant.Phone != "+1 650-253-0000" {
		t.Errorf("Expected registrant phone to be '+1 650-253-0000', got '%s'", registrant.Phone)
	}
}

func assertDKNameServers(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
		return
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}
}

func assertDKUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	expectedStatuses := []string{"not_found"}
	if len(parsedWhois.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsedWhois.Statuses), parsedWhois.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsedWhois.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsedWhois.Statuses[i])
		}
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}
}
