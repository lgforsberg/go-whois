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

	if parsed.DomainName != "GOOGLE.UZ" {
		t.Errorf("Expected domain name 'GOOGLE.UZ', got '%s'", parsed.DomainName)
	}

	if parsed.Registrar == nil || parsed.Registrar.Name != "Tomas" {
		t.Errorf("Expected registrar name 'Tomas', got '%v'", parsed.Registrar)
	}

	// Check that all expected nameservers are present (order may vary due to sorting)
	expectedNS := []string{"ns1.google.com.", "ns2.google.com.", "not.defined.", "not.defined."}
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

	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "ACTIVE" {
		t.Errorf("Expected status 'ACTIVE', got %v", parsed.Statuses)
	}

	if parsed.UpdatedDateRaw != "25-Apr-2025" {
		t.Errorf("Expected updated date '25-Apr-2025', got '%s'", parsed.UpdatedDateRaw)
	}

	if parsed.CreatedDateRaw != "13-Apr-2006" {
		t.Errorf("Expected created date '13-Apr-2006', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "01-May-2026" {
		t.Errorf("Expected expiry date '01-May-2026', got '%s'", parsed.ExpiredDateRaw)
	}
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

	if parsed.DomainName != "jthsitshtkckthst124312.uz" {
		t.Errorf("Expected domain name 'jthsitshtkckthst124312.uz', got '%s'", parsed.DomainName)
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
}
