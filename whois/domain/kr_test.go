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

	if parsedWhois.DomainName != "google.kr" {
		t.Errorf("Expected domain name 'google.kr', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.CreatedDateRaw != "2007. 03. 02." {
		t.Errorf("Expected created date '2007. 03. 02.', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != "2026. 03. 02." {
		t.Errorf("Expected expired date '2026. 03. 02.', got '%s'", parsedWhois.ExpiredDateRaw)
	}
	if len(parsedWhois.NameServers) < 2 || parsedWhois.NameServers[0] != "ns1.google.com" || parsedWhois.NameServers[1] != "ns2.google.com" {
		t.Errorf("Expected name servers ['ns1.google.com', 'ns2.google.com'], got %v", parsedWhois.NameServers)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
	} else {
		reg := parsedWhois.Contacts.Registrant
		if reg.Name != "Google Korea, LLC" {
			t.Errorf("Expected registrant name 'Google Korea, LLC', got '%s'", reg.Name)
		}
	}

	// Test unregistered domain
	data, err = os.ReadFile("testdata/kr/case3.txt")
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
