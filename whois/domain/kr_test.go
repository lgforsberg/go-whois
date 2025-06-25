package domain

import (
	"os"
	"testing"
)

func TestKRTLDParser_Parse(t *testing.T) {
	parser := NewKRTLDParser()

	// Test registered domain
	data, err := os.ReadFile("testdata/kr/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	assertKRRegisteredDomain(t, parsedWhois, "google.kr", "2007. 03. 02.", "2026. 03. 02.", []string{"ns1.google.com", "ns2.google.com"})
	assertKRRegistrantContact(t, parsedWhois, "Google Korea, LLC")

	// Test unregistered domain
	data, err = os.ReadFile("testdata/kr/case3.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err = parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	assertKRUnregisteredDomain(t, parsedWhois)
}

func assertKRRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain, expectedCreated, expectedExpired string, expectedNS []string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}
	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expired date '%s', got '%s'", expectedExpired, parsedWhois.ExpiredDateRaw)
	}
	assertKRNameservers(t, parsedWhois.NameServers, expectedNS)
}

func assertKRRegistrantContact(t *testing.T, parsedWhois *ParsedWhois, expectedName string) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
		return
	}

	reg := parsedWhois.Contacts.Registrant
	if reg.Name != expectedName {
		t.Errorf("Expected registrant name '%s', got '%s'", expectedName, reg.Name)
	}
}

func assertKRUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) == 0 || parsedWhois.Statuses[0] != "not_found" {
		t.Errorf("Expected status 'not_found' for unregistered domain, got %v", parsedWhois.Statuses)
	}
}

func assertKRNameservers(t *testing.T, actual, expected []string) {
	if len(actual) < len(expected) {
		t.Errorf("Expected at least %d nameservers, got %d", len(expected), len(actual))
		return
	}
	for i, expectedNS := range expected {
		if i < len(actual) && actual[i] != expectedNS {
			t.Errorf("Expected nameserver %d to be '%s', got '%s'", i, expectedNS, actual[i])
		}
	}
}
