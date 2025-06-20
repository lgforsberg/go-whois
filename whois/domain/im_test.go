package domain

import (
	"os"
	"testing"
)

func TestIMTLDParser_Parse(t *testing.T) {
	parser := NewIMTLDParser()

	// Test registered domain
	data, err := os.ReadFile("testdata/im/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if parsedWhois.DomainName != "google.im" {
		t.Errorf("Expected domain name 'google.im', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.ExpiredDateRaw != "14/08/2025 23:59:41" {
		t.Errorf("Expected expired date '14/08/2025 23:59:41', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	// Verify name servers
	expectedNS := []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."}
	if len(parsedWhois.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d name servers, got %d", len(expectedNS), len(parsedWhois.NameServers))
	} else {
		for i, ns := range expectedNS {
			if parsedWhois.NameServers[i] != ns {
				t.Errorf("Expected name server '%s', got '%s'", ns, parsedWhois.NameServers[i])
			}
		}
	}

	// Test domain with non-redacted registrar
	data, err = os.ReadFile("testdata/im/case3.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err = parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if parsedWhois.DomainName != "nic.im" {
		t.Errorf("Expected domain name 'nic.im', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "The IM Registry" {
		t.Errorf("Expected registrar 'The IM Registry', got '%v'", parsedWhois.Registrar)
	}
}
