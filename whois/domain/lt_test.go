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

	if parsedWhois.DomainName != "google.lt" {
		t.Errorf("Expected domain name 'google.lt', got '%s'", parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "registered" {
		t.Errorf("Expected status 'registered', got '%v'", parsedWhois.Statuses)
	}
	if parsedWhois.CreatedDateRaw != "2018-12-07" {
		t.Errorf("Expected created date '2018-12-07', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != "2025-12-08" {
		t.Errorf("Expected expired date '2025-12-08', got '%s'", parsedWhois.ExpiredDateRaw)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "MarkMonitor, Inc." {
		t.Errorf("Expected registrar name 'MarkMonitor, Inc.', got '%v'", parsedWhois.Registrar)
	}
	if parsedWhois.Registrar.URL != "http://www.markmonitor.com" {
		t.Errorf("Expected registrar URL 'http://www.markmonitor.com', got '%s'", parsedWhois.Registrar.URL)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Organization != "Markmonitor Inc." {
		t.Errorf("Expected registrant organization 'Markmonitor Inc.', got '%s'", parsedWhois.Contacts.Registrant.Organization)
	}
	if parsedWhois.Contacts.Registrant.Email != "ccops@markmonitor.com" {
		t.Errorf("Expected registrant email 'ccops@markmonitor.com', got '%s'", parsedWhois.Contacts.Registrant.Email)
	}
	if len(parsedWhois.NameServers) != 3 {
		t.Errorf("Expected 3 nameservers, got %d", len(parsedWhois.NameServers))
	}
	if parsedWhois.NameServers[0] != "ns1.google.com" {
		t.Errorf("Expected first nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[0])
	}
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
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free', got '%v'", parsedWhois.Statuses)
	}
}

func TestLTTLDParser_GetName(t *testing.T) {
	parser := NewLTTLDParser()
	if parser.GetName() != "lt" {
		t.Errorf("Expected parser name 'lt', got '%s'", parser.GetName())
	}
}
