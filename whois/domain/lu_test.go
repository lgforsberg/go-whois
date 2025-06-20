package domain

import (
	"strings"
	"testing"
)

func TestLUTLDParser_Parse(t *testing.T) {
	parser := NewLUTLDParser()

	rawtext := `% Access to RESTENA DNS-LU WHOIS information is provided to assist persons
% ...
% WHOIS google.lu
domainname:     google.lu
domaintype:     ACTIVE
nserver:        ns1.google.com
nserver:        ns2.google.com
nserver:        ns3.google.com
nserver:        ns4.google.com
ownertype:      ORGANISATION
org-country:    US
registrar-name:         Markmonitor
registrar-email:        ccops@markmonitor.com
registrar-url:          http://www.markmonitor.com/
registrar-country:      GB
whois-web:         https://www.dns.lu/en/support/domainname-availability/whois-gateway/
`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if parsedWhois.DomainName != "google.lu" {
		t.Errorf("Expected domain name 'google.lu', got '%s'", parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "ACTIVE" {
		t.Errorf("Expected status 'ACTIVE', got '%v'", parsedWhois.Statuses)
	}
	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 nameservers, got %d", len(parsedWhois.NameServers))
	}
	if parsedWhois.NameServers[0] != "ns1.google.com" {
		t.Errorf("Expected first nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[0])
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Country != "US" {
		t.Errorf("Expected registrant country 'US', got '%s'", parsedWhois.Contacts.Registrant.Country)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "Markmonitor" {
		t.Errorf("Expected registrar name 'Markmonitor', got '%v'", parsedWhois.Registrar)
	}
	if parsedWhois.Registrar.URL != "http://www.markmonitor.com/" {
		t.Errorf("Expected registrar URL 'http://www.markmonitor.com/', got '%s'", parsedWhois.Registrar.URL)
	}
}

func TestLUTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewLUTLDParser()

	rawtext := `% Access to RESTENA DNS-LU WHOIS information is provided to assist persons
% ...
% WHOIS notregistered.lu
`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free', got '%v'", parsedWhois.Statuses)
	}
}

func TestLUTLDParser_ParseRateLimit(t *testing.T) {
	parser := NewLUTLDParser()

	rawtext := `% Access to RESTENA DNS-LU WHOIS information is provided to assist persons
% ...
% WHOIS google.lu
%% Maximum query rate reached
`

	_, err := parser.GetParsedWhois(rawtext)
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("Expected rate limit error, got %v", err)
	}
}

func TestLUTLDParser_GetName(t *testing.T) {
	parser := NewLUTLDParser()
	if parser.GetName() != "lu" {
		t.Errorf("Expected parser name 'lu', got '%s'", parser.GetName())
	}
}
