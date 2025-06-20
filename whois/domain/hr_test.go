package domain

import (
	"os"
	"testing"
)

func TestHRTLDParser_Parse(t *testing.T) {
	parser := NewHRTLDParser()

	data, err := os.ReadFile("testdata/hr/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	if parsedWhois.DomainName != "google.hr" {
		t.Errorf("Expected domain name 'google.hr', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "Sayber d.o.o." {
		t.Errorf("Expected registrar 'Sayber d.o.o.', got '%v'", parsedWhois.Registrar)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
	} else {
		reg := parsedWhois.Contacts.Registrant
		if reg.Name != "Google Hrvatska d.o.o." {
			t.Errorf("Expected registrant name 'Google Hrvatska d.o.o.', got '%s'", reg.Name)
		}
		if reg.Email != "dns-admin@google.com" {
			t.Errorf("Expected registrant email 'dns-admin@google.com', got '%s'", reg.Email)
		}
		if reg.Country != "HR" {
			t.Errorf("Expected registrant country 'HR', got '%s'", reg.Country)
		}
	}
	if len(parsedWhois.NameServers) != 2 || parsedWhois.NameServers[0] != "ns1.google.com" || parsedWhois.NameServers[1] != "ns2.google.com" {
		t.Errorf("Expected name servers ['ns1.google.com', 'ns2.google.com'], got %v", parsedWhois.NameServers)
	}
}
