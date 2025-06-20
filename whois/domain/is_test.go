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

	if parsedWhois.DomainName != "google.is" {
		t.Errorf("Expected domain name 'google.is', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.CreatedDateRaw != "May 22 2002" {
		t.Errorf("Expected created date 'May 22 2002', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != "May 22 2026" {
		t.Errorf("Expected expired date 'May 22 2026', got '%s'", parsedWhois.ExpiredDateRaw)
	}
	if len(parsedWhois.NameServers) != 2 || parsedWhois.NameServers[0] != "ns1.google.com" || parsedWhois.NameServers[1] != "ns2.google.com" {
		t.Errorf("Expected name servers ['ns1.google.com', 'ns2.google.com'], got %v", parsedWhois.NameServers)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
	} else {
		reg := parsedWhois.Contacts.Registrant
		if reg.Organization != "Google LLC" {
			t.Errorf("Expected registrant organization 'Google LLC', got '%s'", reg.Organization)
		}
		if reg.Email != "ccops@markmonitor.com" {
			t.Errorf("Expected registrant email 'ccops@markmonitor.com', got '%s'", reg.Email)
		}
	}

	// Test unregistered domain
	data, err = os.ReadFile("testdata/is/case10.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err = parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if len(parsedWhois.Statuses) == 0 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free' for unregistered domain, got %v", parsedWhois.Statuses)
	}
}
