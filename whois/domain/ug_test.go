package domain

import (
	"testing"
)

func TestUGTLDParser(t *testing.T) {
	parser := NewUGTLDParser()
	if parser.GetName() != "ug" {
		t.Errorf("Expected parser name to be 'ug', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `
**********************************************************
*            The UG ccTLD Registry Database              *
**********************************************************

Domain name:                    google.ug
Status:                         ACTIVE
Expires On:                     2026-03-18
Registered On:                  2004-08-03
Renewed On:                     2025-03-04
Nameserver:                     ns1.google.com
Nameserver:                     ns2.google.com
Nameserver:                     ns3.google.com


Registrant Contact Information:  
Registrant Name:                Domain Administrator
Registrant Organization:        Google LLC
Registrant Country:             US
Registrant State / Province:    CA
Registrant City:                Mountain View
Registrant Address:             1600 Amphitheatre Parkway
Registrant Postal Code:         94043
Registrant Phone:               +1.6502530000
Registrant Email:               ccops@markmonitor.com

Administrative Contact Information:  
Admin Name:                     Domain Administrator
Admin Organization:             Google LLC
Admin Country:                  US
Admin State / Province:         CA
Admin City:                     Mountain View
Admin Address:                  1600 Amphitheatre Parkway
Admin Postal Code:              94043
Admin Phone:                    +1.6502530000
Admin Email:                    ccops@markmonitor.com

Technical Contact Information:  
Tech Name:                      Domain Administrator
Tech Organization:              Google LLC
Tech Country:                   US
Tech State / Province:          CA
Tech City:                      Mountain View
Tech Address:                   1600 Amphitheatre Parkway
Tech Postal Code:               94043
Tech Phone:                     +1.6502530000
Tech Email:                     ccops@markmonitor.com

Information Last Updated:       2025-03-04 21:48:52
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "google.ug" {
		t.Errorf("Expected domain name 'google.ug', got '%s'", parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "2004-08-03" {
		t.Errorf("Expected created date '2004-08-03', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDate != "2026-03-18T00:00:00+00:00" {
		t.Errorf("Expected expiry date '2026-03-18T00:00:00+00:00', got '%s'", parsed.ExpiredDate)
	}

	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "ACTIVE" {
		t.Errorf("Expected status 'ACTIVE', got %v", parsed.Statuses)
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com"}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}
	for i, ns := range expectedNS {
		if parsed.NameServers[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, parsed.NameServers[i])
		}
	}

	// Check registrant contact
	if parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
	} else {
		if parsed.Contacts.Registrant.Name != "Domain Administrator" {
			t.Errorf("Expected registrant name 'Domain Administrator', got '%s'", parsed.Contacts.Registrant.Name)
		}
		if parsed.Contacts.Registrant.Organization != "Google LLC" {
			t.Errorf("Expected registrant organization 'Google LLC', got '%s'", parsed.Contacts.Registrant.Organization)
		}
		if parsed.Contacts.Registrant.Country != "US" {
			t.Errorf("Expected registrant country 'US', got '%s'", parsed.Contacts.Registrant.Country)
		}
		if parsed.Contacts.Registrant.Email != "ccops@markmonitor.com" {
			t.Errorf("Expected registrant email 'ccops@markmonitor.com', got '%s'", parsed.Contacts.Registrant.Email)
		}
	}

	// Check admin contact
	if parsed.Contacts.Admin == nil {
		t.Error("Expected admin contact to be present")
	} else {
		if parsed.Contacts.Admin.Name != "Domain Administrator" {
			t.Errorf("Expected admin name 'Domain Administrator', got '%s'", parsed.Contacts.Admin.Name)
		}
		if parsed.Contacts.Admin.Organization != "Google LLC" {
			t.Errorf("Expected admin organization 'Google LLC', got '%s'", parsed.Contacts.Admin.Organization)
		}
	}

	// Check tech contact
	if parsed.Contacts.Tech == nil {
		t.Error("Expected tech contact to be present")
	} else {
		if parsed.Contacts.Tech.Name != "Domain Administrator" {
			t.Errorf("Expected tech name 'Domain Administrator', got '%s'", parsed.Contacts.Tech.Name)
		}
		if parsed.Contacts.Tech.Organization != "Google LLC" {
			t.Errorf("Expected tech organization 'Google LLC', got '%s'", parsed.Contacts.Tech.Organization)
		}
	}
}

func TestUGTLDParserUnregistered(t *testing.T) {
	parser := NewUGTLDParser()

	// Test unregistered domain
	whoisText := `
                **********************************************************
                *            The UG ccTLD Registry Database              *
                **********************************************************

                Domain Name: sdfasdf-sdf-sdf-sdf-sdf.ug
                >>> The domain contains special characters not allowed.
                >>> This domain violates registry policy.
                >>> Last update of WHOIS database: 2025-06-19T00:46:35 <<<
            `

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "" {
		t.Errorf("Expected empty domain name for unregistered domain, got '%s'", parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "" {
		t.Errorf("Expected empty creation date for unregistered domain, got '%s'", parsed.CreatedDateRaw)
	}

	if len(parsed.Statuses) != 0 {
		t.Errorf("Expected no statuses for unregistered domain, got %v", parsed.Statuses)
	}

	if parsed.Registrar.Name != "" {
		t.Errorf("Expected empty registrar for unregistered domain, got '%s'", parsed.Registrar.Name)
	}

	if len(parsed.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %v", parsed.NameServers)
	}

	if parsed.Contacts.Registrant != nil {
		t.Error("Expected no registrant contact for unregistered domain")
	}

	if parsed.Contacts.Admin != nil {
		t.Error("Expected no admin contact for unregistered domain")
	}

	if parsed.Contacts.Tech != nil {
		t.Error("Expected no tech contact for unregistered domain")
	}
}
