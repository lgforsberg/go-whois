package domain

import (
	"testing"
)

func TestEETLDParser(t *testing.T) {
	parser := NewEETLDParser()
	if parser.GetName() != "ee" {
		t.Errorf("Expected parser name to be 'ee', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `Search results may not be used for commercial, advertising, recompilation,
repackaging, redistribution, reuse, obscuring or other similar activities.

Estonia .ee Top Level Domain WHOIS server

Domain:
name:       google.ee
status:     ok (paid and in zone)
registered: 2010-07-04 04:34:46 +03:00
changed:    2024-10-11 19:50:15 +03:00
expire:     2025-11-09
outzone:    
delete:     

Registrant:
name:       Google LLC
org id:     3582691
country:    US
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
phone:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
changed:    2024-10-11 19:50:15 +03:00

Administrative contact:
name:       Not Disclosed - Visit www.internet.ee for webbased WHOIS
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
changed:    Not Disclosed - Visit www.internet.ee for webbased WHOIS

Technical contact:
name:       Not Disclosed - Visit www.internet.ee for webbased WHOIS
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
changed:    Not Disclosed - Visit www.internet.ee for webbased WHOIS

Registrar:
name:       Zone Media OÜ
url:        http://www.zone.ee
phone:      +372 6886886
changed:    2020-07-01 13:55:58 +03:00

Name servers:
nserver:   ns4.google.com
nserver:   ns3.google.com
nserver:   ns2.google.com
nserver:   ns1.google.com
changed:   2010-11-10 14:15:06 +02:00


Estonia .ee Top Level Domain WHOIS server
More information at http://internet.ee`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertEEBasicFields(t, parsedWhois)
	assertEEContacts(t, parsedWhois)
	assertEERegistrar(t, parsedWhois)
	assertEENameServers(t, parsedWhois)

	// Test unregistered domain (case10)
	rawtextFree := `
Domain not found

Estonia .ee Top Level Domain WHOIS server
More information at http://internet.ee`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertEEUnregisteredDomain(t, parsedWhoisFree)
}

func assertEEBasicFields(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.ee" {
		t.Errorf("Expected domain name to be 'google.ee', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "ok (paid and in zone)" {
		t.Errorf("Expected status to be 'ok (paid and in zone)', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != "2010-07-04 04:34:46 +03:00" {
		t.Errorf("Expected created date raw to be '2010-07-04 04:34:46 +03:00', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "2024-10-11 19:50:15 +03:00" {
		t.Errorf("Expected updated date raw to be '2024-10-11 19:50:15 +03:00', got '%s'", parsedWhois.UpdatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2025-11-09" {
		t.Errorf("Expected expiration date raw to be '2025-11-09', got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertEEContacts(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact to be present")
		return
	}

	registrant := parsedWhois.Contacts.Registrant
	if registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name to be 'Google LLC', got '%s'", registrant.Name)
	}
	if registrant.ID != "3582691" {
		t.Errorf("Expected registrant org id to be '3582691', got '%s'", registrant.ID)
	}
	if registrant.Country != "US" {
		t.Errorf("Expected registrant country to be 'US', got '%s'", registrant.Country)
	}
}

func assertEERegistrar(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "Zone Media OÜ" {
		t.Errorf("Expected registrar name to be 'Zone Media OÜ', got '%s'", func() string {
			if parsedWhois.Registrar == nil {
				return "nil"
			}
			return parsedWhois.Registrar.Name
		}())
	}

	if parsedWhois.Registrar.URL != "http://www.zone.ee" {
		t.Errorf("Expected registrar URL to be 'http://www.zone.ee', got '%s'", parsedWhois.Registrar.URL)
	}
}

func assertEENameServers(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
		return
	}

	expectedNS := []string{"ns4.google.com", "ns3.google.com", "ns2.google.com", "ns1.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}
}

func assertEEUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhois.UpdatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expiration date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}
}
