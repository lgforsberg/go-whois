package domain

import (
	"testing"
)

func TestTZTLDParser(t *testing.T) {
	parser := NewTZTLDParser()
	if parser.GetName() != "tz" {
		t.Errorf("Expected parser name to be 'tz', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `%  
%  TZNIC WHOIS data and services are subject to the Terms of Use
%  available at: https://www.tznic.or.tz/Whois_tou.pdf
% 
%  You may also use our WHOIS Web service available at:
%  https://whois.tznic.or.tz/whois
% 
% 
% Whoisd Server Version: 3.10.2
% Timestamp: Thu Jun 19 03:46:04 2025

domain:       google.tz
registrant:   GDA-ITFARM
admin-c:      KP1-ITFARM
admin-c:      GLK-ITFARM
nsset:        NS-GOOGLEDOMAINS-COM
registrar:    REG-ITFARM
registered:   05.03.2022 08:48:34
expire:       05.03.2026

contact:      GDA-ITFARM
registrar:    REG-ITFARM
created:      18.05.2011 12:22:33
changed:      08.12.2018 10:10:55

contact:      KP1-ITFARM
registrar:    REG-ITFARM
created:      10.07.2010 11:26:44
changed:      03.03.2017 10:57:29

contact:      GLK-ITFARM
registrar:    REG-ITFARM
created:      26.02.2010 20:57:29
changed:      19.09.2019 07:32:42

nsset:        NS-GOOGLEDOMAINS-COM
nserver:      ns1.googledomains.com 
nserver:      ns2.googledomains.com 
nserver:      ns3.googledomains.com 
nserver:      ns4.googledomains.com 
tech-c:       GLK-ITFARM
registrar:    REG-ITFARM
created:      01.03.2022 03:11:24
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "google.tz" {
		t.Errorf("Expected domain name 'google.tz', got '%s'", parsed.DomainName)
	}
	if parsed.CreatedDateRaw != "05.03.2022 08:48:34" {
		t.Errorf("Expected created date '05.03.2022 08:48:34', got '%s'", parsed.CreatedDateRaw)
	}
	if parsed.ExpiredDate != "2026-05-03T00:00:00+00:00" {
		t.Errorf("Expected expiry date '2026-05-03T00:00:00+00:00', got '%s'", parsed.ExpiredDate)
	}
	if parsed.Registrar.Name != "REG-ITFARM" {
		t.Errorf("Expected registrar 'REG-ITFARM', got '%s'", parsed.Registrar.Name)
	}
	expectedNS := []string{"ns1.googledomains.com", "ns2.googledomains.com", "ns3.googledomains.com", "ns4.googledomains.com"}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}
	for i, ns := range expectedNS {
		if parsed.NameServers[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, parsed.NameServers[i])
		}
	}
	if parsed.Contacts.Registrant == nil || parsed.Contacts.Registrant.ID != "GDA-ITFARM" {
		t.Errorf("Expected registrant ID 'GDA-ITFARM', got '%v'", parsed.Contacts.Registrant)
	}
	if parsed.Contacts.Admin == nil || parsed.Contacts.Admin.ID != "KP1-ITFARM" {
		t.Errorf("Expected admin ID 'KP1-ITFARM', got '%v'", parsed.Contacts.Admin)
	}
}

func TestTZTLDParserUnregistered(t *testing.T) {
	parser := NewTZTLDParser()
	whoisText := `%  
%  TZNIC WHOIS data and services are subject to the Terms of Use
%  available at: https://www.tznic.or.tz/Whois_tou.pdf
% 
%  You may also use our WHOIS Web service available at:
%  https://whois.tznic.or.tz/whois
% 
% 
% Whoisd Server Version: 3.10.2

%ERROR:101: no entries found
% 
% No entries found.

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
}
