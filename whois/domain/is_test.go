package domain

import (
	"os"
	"testing"
)

func TestISTLDParser_Parse(t *testing.T) {
	parser := NewISTLDParser()

	// Test registered domain
	data, err := os.ReadFile("testdata/is/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	assertISRegisteredDomain(t, parsedWhois, "google.is", "May 22 2002", "May 22 2026", []string{"ns1.google.com", "ns2.google.com"})
	assertISRegistrantContact(t, parsedWhois, "Google LLC", "ccops@markmonitor.com")

	// Test unregistered domain
	data, err = os.ReadFile("testdata/is/case10.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err = parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	assertISUnregisteredDomain(t, parsedWhois)
}

func assertISRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain, expectedCreated, expectedExpired string, expectedNS []string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}
	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expired date '%s', got '%s'", expectedExpired, parsedWhois.ExpiredDateRaw)
	}
	assertStringSliceEqualIS(t, parsedWhois.NameServers, expectedNS, "name server")
}

func assertISRegistrantContact(t *testing.T, parsedWhois *ParsedWhois, expectedOrg, expectedEmail string) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
		return
	}

	reg := parsedWhois.Contacts.Registrant
	if reg.Organization != expectedOrg {
		t.Errorf("Expected registrant organization '%s', got '%s'", expectedOrg, reg.Organization)
	}
	if reg.Email != expectedEmail {
		t.Errorf("Expected registrant email '%s', got '%s'", expectedEmail, reg.Email)
	}
}

func assertISUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) == 0 || parsedWhois.Statuses[0] != "not_found" {
		t.Errorf("Expected status 'not_found' for unregistered domain, got %v", parsedWhois.Statuses)
	}
}

func assertStringSliceEqualIS(t *testing.T, actual, expected []string, label string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d %s(s), got %d", len(expected), label, len(actual))
		return
	}
	for i, v := range expected {
		if i < len(actual) && actual[i] != v {
			t.Errorf("Expected %s %d to be '%s', got '%s'", label, i, v, actual[i])
		}
	}
}
