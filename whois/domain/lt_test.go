package domain

import (
	"testing"
)

func TestLTTLDParser_Parse(t *testing.T) {
	parser := NewLTTLDParser()

	rawtext := `% Hello, this is the DOMREG whois service.
%
% By submitting a query you agree not to use the information made
% available to:
% - allow, enable or otherwise support the transmission of unsolicited,
%   commercial advertising or other solicitations whether via email or
%   otherwise;
% - target advertising in any possible way;
% - to cause nuisance in any possible way to the registrants by sending
%   (whether by automated, electronic processes capable of enabling
%   high volumes or other possible means) messages to them.
%
% Version 0.4
%
% For more information please visit https://whois.lt
%
Domain:            google.lt
Status:            registered
Registered:        2018-12-07
Expires:           2025-12-08
%
Registrar:         MarkMonitor, Inc.
Registrar website: http://www.markmonitor.com
Registrar email:   ccops@markmonitor.com
%
Contact organization: Markmonitor Inc.
Contact email:     ccops@markmonitor.com
%
Nameserver:        ns1.google.com
Nameserver:        ns2.google.com
Nameserver:        ns3.google.com
`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	assertLTRegisteredDomain(t, parsedWhois, "google.lt", "2018-12-07", "2025-12-08", []string{"ns1.google.com", "ns2.google.com", "ns3.google.com"})
	assertLTRegistrar(t, parsedWhois, "MarkMonitor, Inc.", "http://www.markmonitor.com")
	assertLTRegistrantContact(t, parsedWhois, "Markmonitor Inc.", "ccops@markmonitor.com")
}

func TestLTTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewLTTLDParser()

	rawtext := `% Hello, this is the DOMREG whois service.
%
% By submitting a query you agree not to use the information made
% available to:
% - allow, enable or otherwise support the transmission of unsolicited,
%   commercial advertising or other solicitations whether via email or
%   otherwise;
% - target advertising in any possible way;
% - to cause nuisance in any possible way to the registrants by sending
%   (whether by automated, electronic processes capable of enabling
%   high volumes or other possible means) messages to them.
%
% Version 0.4
%
% For more information please visit https://whois.lt
%
Domain:            jthsitshtkckthst124312.lt
Status:            available
`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	assertLTUnregisteredDomain(t, parsedWhois)
}

func TestLTTLDParser_GetName(t *testing.T) {
	parser := NewLTTLDParser()
	if parser.GetName() != "lt" {
		t.Errorf("Expected parser name 'lt', got '%s'", parser.GetName())
	}
}

func assertLTRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain, expectedCreated, expectedExpired string, expectedNS []string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "registered" {
		t.Errorf("Expected status 'registered', got '%v'", parsedWhois.Statuses)
	}
	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expired date '%s', got '%s'", expectedExpired, parsedWhois.ExpiredDateRaw)
	}
	assertStringSliceEqualLT(t, parsedWhois.NameServers, expectedNS, "nameserver")
}

func assertLTRegistrar(t *testing.T, parsedWhois *ParsedWhois, expectedName, expectedURL string) {
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != expectedName {
		t.Errorf("Expected registrar name '%s', got '%v'", expectedName, parsedWhois.Registrar)
	}
	if parsedWhois.Registrar.URL != expectedURL {
		t.Errorf("Expected registrar URL '%s', got '%s'", expectedURL, parsedWhois.Registrar.URL)
	}
}

func assertLTRegistrantContact(t *testing.T, parsedWhois *ParsedWhois, expectedOrg, expectedEmail string) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Organization != expectedOrg {
		t.Errorf("Expected registrant organization '%s', got '%s'", expectedOrg, parsedWhois.Contacts.Registrant.Organization)
	}
	if parsedWhois.Contacts.Registrant.Email != expectedEmail {
		t.Errorf("Expected registrant email '%s', got '%s'", expectedEmail, parsedWhois.Contacts.Registrant.Email)
	}
}

func assertLTUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free', got '%v'", parsedWhois.Statuses)
	}
}

func assertStringSliceEqualLT(t *testing.T, actual, expected []string, label string) {
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
