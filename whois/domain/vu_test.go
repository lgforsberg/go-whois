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

	// Check registrant contact
	if parsed.Contacts == nil || parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
	} else {
		if parsed.Contacts.Registrant.Name != "Valentine Nguyen" {
			t.Errorf("Expected registrant name 'Valentine Nguyen', got '%s'", parsed.Contacts.Registrant.Name)
		}
		if len(parsed.Contacts.Registrant.Street) == 0 || parsed.Contacts.Registrant.Street[0] != "OGCIO OFfice" {
			t.Errorf("Expected registrant address 'OGCIO OFfice', got '%v'", parsed.Contacts.Registrant.Street)
		}
		if parsed.Contacts.Registrant.City != "Port Vila" {
			t.Errorf("Expected registrant city 'Port Vila', got '%s'", parsed.Contacts.Registrant.City)
		}
		if parsed.Contacts.Registrant.Country != "Vanuatu" {
			t.Errorf("Expected registrant country 'Vanuatu', got '%s'", parsed.Contacts.Registrant.Country)
		}
	}

	expectedNS := []string{"ns2.tldns.vu", "ns1.tldns.vu", "ns3.tldns.vu", "ns4.tldns.vu"}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}

	// Check that all expected nameservers are present
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

	if parsed.CreatedDateRaw != "Tue Aug 2000 00:00:00" {
		t.Errorf("Expected created date 'Tue Aug 2000 00:00:00', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "Sun Nov 2025 03:31:55" {
		t.Errorf("Expected expiry date 'Sun Nov 2025 03:31:55', got '%s'", parsed.ExpiredDateRaw)
	}
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

	if parsed.DomainName != "google.vu" {
		t.Errorf("Expected domain name 'google.vu', got '%s'", parsed.DomainName)
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

	// Check registrant contact with empty fields
	if parsed.Contacts == nil || parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
	} else {
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

	expectedNS := []string{"ns3.tldns.vu", "ns2.tldns.vu", "ns1.tldns.vu", "ns4.tldns.vu"}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}

	if parsed.CreatedDateRaw != "Thu Jan 1970 11:00:00" {
		t.Errorf("Expected created date 'Thu Jan 1970 11:00:00', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "Thu Jan 1970 11:00:00" {
		t.Errorf("Expected expiry date 'Thu Jan 1970 11:00:00', got '%s'", parsed.ExpiredDateRaw)
	}
}
