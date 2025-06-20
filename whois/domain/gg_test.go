package domain

import (
	"testing"
)

func TestGGTLDParser(t *testing.T) {
	parser := NewGGTLDParser()
	if parser.GetName() != "gg" {
		t.Errorf("Expected parser name to be 'gg', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `Domain:
     google.gg

Domain Status:
     Active
     Delete Prohibited by Registrar
     Update Prohibited by Registrar
     Transfer Prohibited by Registrar

Registrant:
     Google LLC

Registrar:
     MarkMonitor Inc. (http://www.markmonitor.com)

Relevant dates:
     Registered on 30th April 2003 at 00:00:00.000
     Registry fee due on 30th April each year

Registration status:
     Registered until cancelled

Name servers:
     ns1.google.com
     ns2.google.com
     ns3.google.com
     ns4.google.com
     

WHOIS lookup made on Thu, 19 Jun 2025 at 1:11:01 BST

This WHOIS information is provided for free by CIDR, operator of
the backend registry for domain names ending in GG, JE, and AS.

Copyright (c) and database right Island Networks 1996 - 2025.

You may not access this WHOIS server or use any data from it except
as permitted by our Terms and Conditions which are published
at http://www.channelisles.net/legal/whoisterms

They include restrictions and prohibitions on

- using or re-using the data for advertising;
- using or re-using the service for commercial purposes without a licence;
- repackaging, recompilation, redistribution or reuse;
- obscuring, removing or hiding any or all of this notice;
- exceeding query rate or volume limits.

The data is provided on an 'as-is' basis and may lag behind the
register. Access may be withdrawn or restricted at any time. 
`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertGGRegisteredDomain(t, parsedWhois)

	// Test unregistered domain (case10)
	rawtextFree := `NOT FOUND`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertGGUnregisteredDomain(t, parsedWhoisFree)
}

func assertGGRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.gg" {
		t.Errorf("Expected domain name to be 'google.gg', got '%s'", parsedWhois.DomainName)
	}

	expectedStatuses := []string{
		"Active",
		"Delete Prohibited by Registrar",
		"Update Prohibited by Registrar",
		"Transfer Prohibited by Registrar",
	}
	assertStringSliceEqualGG(t, parsedWhois.Statuses, expectedStatuses, "status")

	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact to be present")
	} else {
		if parsedWhois.Contacts.Registrant.Name != "Google LLC" {
			t.Errorf("Expected registrant name to be 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Name)
		}
	}

	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "MarkMonitor Inc." {
		t.Errorf("Expected registrar name to be 'MarkMonitor Inc.', got '%s'", func() string {
			if parsedWhois.Registrar == nil {
				return "nil"
			}
			return parsedWhois.Registrar.Name
		}())
	}

	if parsedWhois.Registrar.URL != "http://www.markmonitor.com" {
		t.Errorf("Expected registrar URL to be 'http://www.markmonitor.com', got '%s'", parsedWhois.Registrar.URL)
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualGG(t, parsedWhois.NameServers, expectedNS, "name server")

	if parsedWhois.CreatedDateRaw != "30th April 2003 at 00:00:00.000" {
		t.Errorf("Expected created date raw to be '30th April 2003 at 00:00:00.000', got '%s'", parsedWhois.CreatedDateRaw)
	}
}

func assertGGUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}
}

func assertStringSliceEqualGG(t *testing.T, actual, expected []string, label string) {
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
