package domain

import (
	"testing"
)

func TestVUParser(t *testing.T) {
	parser := NewVUTLDParser()
	if parser.GetName() != "vu" {
		t.Errorf("Expected parser name to be 'vu', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `
#
# -- /usr/local/bin/mywhois --
#
First Name:     Valentine
Last Name:      Nguyen
Adress:         OGCIO OFfice
City:           Port Vila
Country:        Vanuatu
Date Created:   Tue Aug 2000 00:00:00
Expiry date:    Sun Nov 2025 03:31:55
DNS servers1:    ns2.tldns.vu : 37.209.194.6
DNS servers2:    ns1.tldns.vu : 37.209.192.6
DNS servers3:    ns3.tldns.vu : 37.209.196.6
DNS servers4:    ns4.tldns.vu : 37.209.198.6
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertVURegistrantContact(t, parsed, "Valentine Nguyen", "OGCIO OFfice", "Port Vila", "Vanuatu")
	assertVUNameservers(t, parsed, []string{"ns2.tldns.vu", "ns1.tldns.vu", "ns3.tldns.vu", "ns4.tldns.vu"})
	assertVUDates(t, parsed, "Tue Aug 2000 00:00:00", "Sun Nov 2025 03:31:55")
}

func TestVUParserUnregistered(t *testing.T) {
	parser := NewVUTLDParser()

	// Test unregistered domain
	whoisText := `
#
# -- /usr/local/bin/mywhois --
#
The domain google.vu
 is not valid! 
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertVUUnregisteredDomain(t, parsed, "google.vu")
}

func TestVUParserEmptyFields(t *testing.T) {
	parser := NewVUTLDParser()

	// Test domain with empty contact fields
	whoisText := `
#
# -- /usr/local/bin/mywhois --
#
First Name:     
Last Name:      
Adress:         
City:           
Country:        
Date Created:   Thu Jan 1970 11:00:00
Expiry date:    Thu Jan 1970 11:00:00
DNS servers1:    ns3.tldns.vu : 37.209.196.6
DNS servers2:    ns2.tldns.vu : 37.209.194.6
DNS servers3:    ns1.tldns.vu : 37.209.192.6
DNS servers4:    ns4.tldns.vu : 37.209.198.6
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertVUEmptyRegistrantContact(t, parsed)
	assertVUNameservers(t, parsed, []string{"ns3.tldns.vu", "ns2.tldns.vu", "ns1.tldns.vu", "ns4.tldns.vu"})
	assertVUDates(t, parsed, "Thu Jan 1970 11:00:00", "Thu Jan 1970 11:00:00")
}

func assertVURegistrantContact(t *testing.T, parsed *ParsedWhois, expectedName, expectedAddress, expectedCity, expectedCountry string) {
	if parsed.Contacts == nil || parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
		return
	}

	if parsed.Contacts.Registrant.Name != expectedName {
		t.Errorf("Expected registrant name '%s', got '%s'", expectedName, parsed.Contacts.Registrant.Name)
	}
	if len(parsed.Contacts.Registrant.Street) == 0 || parsed.Contacts.Registrant.Street[0] != expectedAddress {
		t.Errorf("Expected registrant address '%s', got '%v'", expectedAddress, parsed.Contacts.Registrant.Street)
	}
	if parsed.Contacts.Registrant.City != expectedCity {
		t.Errorf("Expected registrant city '%s', got '%s'", expectedCity, parsed.Contacts.Registrant.City)
	}
	if parsed.Contacts.Registrant.Country != expectedCountry {
		t.Errorf("Expected registrant country '%s', got '%s'", expectedCountry, parsed.Contacts.Registrant.Country)
	}
}

func assertVUEmptyRegistrantContact(t *testing.T, parsed *ParsedWhois) {
	if parsed.Contacts == nil || parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
		return
	}

	if parsed.Contacts.Registrant.Name != "" {
		t.Errorf("Expected empty registrant name, got '%s'", parsed.Contacts.Registrant.Name)
	}
	if len(parsed.Contacts.Registrant.Street) != 0 {
		t.Errorf("Expected empty registrant address, got '%v'", parsed.Contacts.Registrant.Street)
	}
	if parsed.Contacts.Registrant.City != "" {
		t.Errorf("Expected empty registrant city, got '%s'", parsed.Contacts.Registrant.City)
	}
	if parsed.Contacts.Registrant.Country != "" {
		t.Errorf("Expected empty registrant country, got '%s'", parsed.Contacts.Registrant.Country)
	}
}

func assertVUNameservers(t *testing.T, parsed *ParsedWhois, expectedNS []string) {
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
		return
	}

	// Check that all expected nameservers are present (unordered)
	for _, expectedNS := range expectedNS {
		found := false
		for _, actualNS := range parsed.NameServers {
			if actualNS == expectedNS {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected nameserver '%s' not found in %v", expectedNS, parsed.NameServers)
		}
	}
}

func assertVUDates(t *testing.T, parsed *ParsedWhois, expectedCreated, expectedExpired string) {
	if parsed.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date '%s', got '%s'", expectedCreated, parsed.CreatedDateRaw)
	}
	if parsed.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expiry date '%s', got '%s'", expectedExpired, parsed.ExpiredDateRaw)
	}
}

func assertVUUnregisteredDomain(t *testing.T, parsed *ParsedWhois, expectedDomain string) {
	if parsed.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsed.DomainName)
	}
	if parsed.CreatedDateRaw != "" {
		t.Errorf("Expected empty creation date for unregistered domain, got '%s'", parsed.CreatedDateRaw)
	}
	if len(parsed.Statuses) != 0 {
		t.Errorf("Expected no statuses for unregistered domain, got %v", parsed.Statuses)
	}
	if parsed.Registrar != nil && parsed.Registrar.Name != "" {
		t.Errorf("Expected empty registrar for unregistered domain, got '%s'", parsed.Registrar.Name)
	}
	if len(parsed.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %v", parsed.NameServers)
	}
	if parsed.Contacts != nil && parsed.Contacts.Registrant != nil {
		t.Error("Expected no registrant contact for unregistered domain")
	}
}
