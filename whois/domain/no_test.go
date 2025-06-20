package domain

import (
	"testing"
)

func TestNOTLDParser(t *testing.T) {
	parser := NewNOTLDParser()
	if parser.GetName() != "no" {
		t.Errorf("Expected parser name to be 'no', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `% By looking up information in the domain registration directory
% service, you confirm that you accept the terms and conditions of the
% service:
% https://www.norid.no/en/domeneoppslag/vilkar/
%
% Norid AS holds the copyright to the lookup service, content,
% layout and the underlying collections of information used in the
% service (cf. the Act on Intellectual Property of May 2, 1961, No.
% 2). Any commercial use of information from the service, including
% targeted marketing, is prohibited. Using information from the domain
% registration directory service in violation of the terms and
% conditions may result in legal prosecution.
%
% The whois service at port 43 is intended to contribute to resolving
% technical problems where individual domains threaten the
% functionality, security and stability of other domains or the
% internet as an infrastructure. It does not give any information
% about who the holder of a domain is. To find information about a
% domain holder, please visit our website:
% https://www.norid.no/en/domeneoppslag/

Domain Information

NORID Handle...............: GOO371D-NORID
Domain Name................: google.no
Registrar Handle...........: REG466-NORID
Tech-c Handle..............: GL14R-NORID
Name Server Handle.........: NSGO26H-NORID
Name Server Handle.........: NSGO27H-NORID
Name Server Handle.........: NSGO28H-NORID
Name Server Handle.........: NSGO29H-NORID

Additional information:
Created:         2001-02-26
Last updated:    2025-01-27`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertNORegisteredDomain(t, parsedWhois, "google.no", []string{"NSGO26H-NORID", "NSGO27H-NORID", "NSGO28H-NORID", "NSGO29H-NORID"}, "2001-02-26", "2025-01-27")

	// Test unregistered domain (case8)
	rawtextFree := `% By looking up information in the domain registration directory
% service, you confirm that you accept the terms and conditions of the
% service:
% https://www.norid.no/en/domeneoppslag/vilkar/
%
% Norid AS holds the copyright to the lookup service, content,
% layout and the underlying collections of information used in the
% service (cf. the Act on Intellectual Property of May 2, 1961, No.
% 2). Any commercial use of information from the service, including
% targeted marketing, is prohibited. Using information from the domain
% registration directory service in violation of the terms and
% conditions may result in legal prosecution.
%
% The whois service at port 43 is intended to contribute to resolving
% technical problems where individual domains threaten the
% functionality, security and stability of other domains or the
% internet as an infrastructure. It does not give any information
% about who the holder of a domain is. To find information about a
% domain holder, please visit our website:
% https://www.norid.no/en/domeneoppslag/

% No match
`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertNOUnregisteredDomain(t, parsedWhoisFree)
}

func assertNORegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain string, expectedNS []string, expectedCreated, expectedUpdated string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	assertStringSliceEqualNO(t, parsedWhois.NameServers, expectedNS, "name server")

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date raw to be '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != expectedUpdated {
		t.Errorf("Expected updated date raw to be '%s', got '%s'", expectedUpdated, parsedWhois.UpdatedDateRaw)
	}
}

func assertNOUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhois.UpdatedDateRaw)
	}
}

func assertStringSliceEqualNO(t *testing.T, actual, expected []string, label string) {
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
