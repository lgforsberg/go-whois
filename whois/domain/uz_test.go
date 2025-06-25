package domain

import (
	"testing"
)

func TestUZParser(t *testing.T) {
	parser := NewUZTLDParser()
	if parser.GetName() != "uz" {
		t.Errorf("Expected parser name to be 'uz', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `
% Uzbekistan Whois Server Version 1.0

% Domain names in the .uz domain can now be registered
% with many different competing registrars. Go to http://www.cctld.uz/
% for detailed information.

   Domain Name: GOOGLE.UZ
   Registrar: Tomas
   Whois Server: www.whois.uz
   Referral URL: http://www.cctld.uz/
   Name Server: ns1.google.com. <no value>
   Name Server: ns2.google.com. <no value>
   Name Server: not.defined. <no value>
   Name Server: not.defined. <no value>
   Status: ACTIVE
   Updated Date: 25-Apr-2025
   Creation Date: 13-Apr-2006
   Expiration Date: 01-May-2026

% >>> Last update of whois database: Thu, 19 Jun 2025 05:52:24 +0500 <<<
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertUZRegisteredDomain(t, parsed, "GOOGLE.UZ", "Tomas", []string{"ns1.google.com.", "ns2.google.com.", "not.defined.", "not.defined."}, "13-Apr-2006", "25-Apr-2025", "01-May-2026")
}

func TestUZParserUnregistered(t *testing.T) {
	parser := NewUZTLDParser()

	// Test unregistered domain
	whoisText := `
% Uzbekistan Whois Server Version 1.0

% Domain names in the .uz domain can now be registered
% with many different competing registrars. Go to http://www.cctld.uz/
% for detailed information.

Sorry, but domain: "jthsitshtkckthst124312.uz", not found in database

%  The Whois Server (ver. 1.0) of ccTLD.UZ
%  (c) 2017, Center UZINFOCOM
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertUZUnregisteredDomain(t, parsed, "jthsitshtkckthst124312.uz")
}

func assertUZRegisteredDomain(t *testing.T, parsed *ParsedWhois, expectedDomain, expectedRegistrar string, expectedNS []string, expectedCreated, expectedUpdated, expectedExpired string) {
	if parsed.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsed.DomainName)
	}

	if parsed.Registrar == nil || parsed.Registrar.Name != expectedRegistrar {
		t.Errorf("Expected registrar name '%s', got '%v'", expectedRegistrar, parsed.Registrar)
	}

	assertUZNameservers(t, parsed, expectedNS)

	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "ACTIVE" {
		t.Errorf("Expected status 'ACTIVE', got %v", parsed.Statuses)
	}

	if parsed.UpdatedDateRaw != expectedUpdated {
		t.Errorf("Expected updated date '%s', got '%s'", expectedUpdated, parsed.UpdatedDateRaw)
	}

	if parsed.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date '%s', got '%s'", expectedCreated, parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expiry date '%s', got '%s'", expectedExpired, parsed.ExpiredDateRaw)
	}
}

func assertUZUnregisteredDomain(t *testing.T, parsed *ParsedWhois, expectedDomain string) {
	if parsed.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "" {
		t.Errorf("Expected empty creation date for unregistered domain, got '%s'", parsed.CreatedDateRaw)
	}

	expectedStatuses := []string{"not_found"}
	if len(parsed.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsed.Statuses), parsed.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsed.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsed.Statuses[i])
		}
	}

	if parsed.Registrar != nil && parsed.Registrar.Name != "" {
		t.Errorf("Expected empty registrar for unregistered domain, got '%s'", parsed.Registrar.Name)
	}

	if len(parsed.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %v", parsed.NameServers)
	}
}

func assertUZNameservers(t *testing.T, parsed *ParsedWhois, expectedNS []string) {
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
