package domain

import (
	"encoding/json"
	"os"
	"testing"
)

func TestHKTLDParser_Parse(t *testing.T) {
	parser := NewHKTLDParser()

	// Test registered domain
	data, err := os.ReadFile("testdata/hk/case1.txt")
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	parsedWhois, err := parser.GetParsedWhois(string(data))
	if err != nil {
		t.Fatalf("Failed to parse whois data: %v", err)
	}

	// Verify domain name
	if parsedWhois.DomainName != "GOOGLE.HK" {
		t.Errorf("Expected domain name 'GOOGLE.HK', got '%s'", parsedWhois.DomainName)
	}

	// Verify status
	if len(parsedWhois.Statuses) == 0 || parsedWhois.Statuses[0] != "Active" {
		t.Errorf("Expected status 'Active', got %v", parsedWhois.Statuses)
	}

	// Verify registrar
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "MARKMONITOR INC." {
		t.Errorf("Expected registrar 'MARKMONITOR INC.', got %v", parsedWhois.Registrar)
	}

	// Verify created date
	if parsedWhois.CreatedDateRaw != "06-04-2004" {
		t.Errorf("Expected created date '06-04-2004', got '%s'", parsedWhois.CreatedDateRaw)
	}

	// Verify expired date
	if parsedWhois.ExpiredDateRaw != "31-03-2026" {
		t.Errorf("Expected expired date '31-03-2026', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	// Verify registrant contact
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact, got nil")
	} else {
		registrant := parsedWhois.Contacts.Registrant
		if registrant.Organization != "GOOGLE LLC" {
			t.Errorf("Expected registrant organization 'GOOGLE LLC', got '%s'", registrant.Organization)
		}
		if registrant.Email != "dns-admin@google.com" {
			t.Errorf("Expected registrant email 'dns-admin@google.com', got '%s'", registrant.Email)
		}
		if registrant.Country != "United States (US)" {
			t.Errorf("Expected registrant country 'United States (US)', got '%s'", registrant.Country)
		}
	}

	// Verify admin contact
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Admin == nil {
		t.Errorf("Expected admin contact, got nil")
	} else {
		admin := parsedWhois.Contacts.Admin
		if admin.Name != "DOMAIN ADMINISTRATOR" {
			t.Errorf("Expected admin name 'DOMAIN ADMINISTRATOR', got '%s'", admin.Name)
		}
		if admin.Organization != "GOOGLE LLC" {
			t.Errorf("Expected admin organization 'GOOGLE LLC', got '%s'", admin.Organization)
		}
		if admin.Phone != "+1-6502530000" {
			t.Errorf("Expected admin phone '+1-6502530000', got '%s'", admin.Phone)
		}
	}

	// Verify tech contact
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Tech == nil {
		t.Errorf("Expected tech contact, got nil")
	} else {
		tech := parsedWhois.Contacts.Tech
		if tech.Name != "DOMAIN ADMINISTRATOR" {
			t.Errorf("Expected tech name 'DOMAIN ADMINISTRATOR', got '%s'", tech.Name)
		}
		if tech.Email != "dns-admin@google.com" {
			t.Errorf("Expected tech email 'dns-admin@google.com', got '%s'", tech.Email)
		}
	}

	// Verify name servers
	expectedNS := []string{"NS1.GOOGLE.COM", "NS2.GOOGLE.COM", "NS3.GOOGLE.COM", "NS4.GOOGLE.COM"}
	if len(parsedWhois.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d name servers, got %d", len(expectedNS), len(parsedWhois.NameServers))
	} else {
		for i, ns := range expectedNS {
			if parsedWhois.NameServers[i] != ns {
				t.Errorf("Expected name server '%s', got '%s'", ns, parsedWhois.NameServers[i])
			}
		}
	}

	// Print JSON for registered domain
	jsonData, _ := json.MarshalIndent(parsedWhois, "", "  ")
	t.Logf("Registered domain parsed whois data: %s", string(jsonData))

	// Test unregistered domain
	data, err = os.ReadFile("testdata/hk/case3.txt")
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

	// Print JSON for unregistered domain
	jsonData, _ = json.MarshalIndent(parsedWhois, "", "  ")
	t.Logf("Unregistered domain parsed whois data: %s", string(jsonData))
}
