package domain

import (
	"os"
	"testing"
)

func TestHUTLDParser_Parse(t *testing.T) {
	parser := NewHUTLDParser()

	// Test registered domain
	data, err := os.ReadFile("testdata/hu/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if parsedWhois.DomainName != "google.hu" {
		t.Errorf("Expected domain name 'google.hu', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.CreatedDateRaw != "2000-03-03" {
		t.Errorf("Expected created date '2000-03-03', got '%s'", parsedWhois.CreatedDateRaw)
	}

	// Test unregistered domain
	data, err = os.ReadFile("testdata/hu/case7.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err = parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if len(parsedWhois.Statuses) == 0 || parsedWhois.Statuses[0] != "not_found" {
		t.Errorf("Expected status 'not_found' for unregistered domain, got %v", parsedWhois.Statuses)
	}
}
