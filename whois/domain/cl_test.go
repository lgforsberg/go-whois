package domain

import (
	"testing"
)

func TestCLTLDParser(t *testing.T) {
	parser := NewCLTLDParser()
	if parser.GetName() != "cl" {
		t.Errorf("Expected parser name to be 'cl', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `%%
%% This is the NIC Chile Whois server (whois.nic.cl).
%%
%% Rights restricted by copyright.
%% See https://www.nic.cl/normativa/politica-publicacion-de-datos-cl.pdf
%%

Domain name: google.cl
Registrant name: Google LLC
Registrant organisation: Google LLC
Registrar name: MarkMonitor Inc.
Registrar URL: https://markmonitor.com/
Creation date: 2002-10-22 17:48:23 CLST
Expiration date: 2025-11-20 14:48:02 CLST
Name server: ns1.google.com
Name server: ns2.google.com
Name server: ns3.google.com
Name server: ns4.google.com

%%
%% For communication with domain contacts please use website.
%% See https://www.nic.cl/registry/Whois.do?d=google.cl
%%
%% Registry Abuse Contact Email: abuse@nic.cl
%%`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertCLRegisteredDomain(t, parsedWhois)

	// Test unregistered domain (case8)
	rawtextFree := `%%
%% This is the NIC Chile Whois server (whois.nic.cl).
%%
%% Rights restricted by copyright.
%% See https://www.nic.cl/normativa/politica-publicacion-de-datos-cl.pdf
%%

sdfsdfsdfsdfsdfsdf1212.cl: no entries found.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertCLUnregisteredDomain(t, parsedWhoisFree)
}

func assertCLRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.cl" {
		t.Errorf("Expected domain name to be 'google.cl', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Errorf("Expected registrant contact to be present")
	} else {
		if parsedWhois.Contacts.Registrant.Name != "Google LLC" {
			t.Errorf("Expected registrant name to be 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Name)
		}
		if parsedWhois.Contacts.Registrant.Organization != "Google LLC" {
			t.Errorf("Expected registrant organization to be 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Organization)
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

	if parsedWhois.Registrar.URL != "https://markmonitor.com/" {
		t.Errorf("Expected registrar URL to be 'https://markmonitor.com/', got '%s'", parsedWhois.Registrar.URL)
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualCL(t, parsedWhois.NameServers, expectedNS, "name server")

	if parsedWhois.CreatedDateRaw != "2002-10-22 17:48:23 CLST" {
		t.Errorf("Expected created date raw to be '2002-10-22 17:48:23 CLST', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2025-11-20 14:48:02 CLST" {
		t.Errorf("Expected expiration date raw to be '2025-11-20 14:48:02 CLST', got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertCLUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expiration date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertStringSliceEqualCL(t *testing.T, actual, expected []string, label string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d %ss, got %d", len(expected), label, len(actual))
		return
	}
	for i, v := range expected {
		if i < len(actual) && actual[i] != v {
			t.Errorf("Expected %s %d to be '%s', got '%s'", label, i, v, actual[i])
		}
	}
}
