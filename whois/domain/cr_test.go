package domain

import (
	"testing"
)

func TestCRTLDParser(t *testing.T) {
	parser := NewCRTLDParser()
	if parser.GetName() != "cr" {
		t.Errorf("Expected parser name to be 'cr', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `% Domain Information over Whois protocol
% 
% Whoisd Server Version: 3.15.0
% Timestamp: Wed Jun 18 23:52:03 2025

domain:       google.cr
registrant:   CN_10
admin-c:      CN_10
nsset:        NS_GOOGLE_CR
registrar:    NIC-REG1
status:       Administratively blocked
status:       Deletion forbidden
status:       Sponsoring registrar change forbidden
status:       Update forbidden
status:       Registrant change forbidden
registered:   02.03.2008 18:00:00
changed:      26.05.2025 04:32:09
expire:       03.03.2026

contact:      CN_10
org:          MarkMonitor Inc.
name:         MarkMonitor Inc
address:      1120 S. Rackham Way, Suite 300
address:      Meridian
address:      83642
address:      Idaho
address:      US
phone:        +1.2083895740
e-mail:       ccops@markmonitor.com
registrar:    NIC-REG1
created:      14.03.2024 10:33:28
changed:      28.05.2024 12:44:39

nsset:        NS_GOOGLE_CR
nserver:      ns1.google.com 
nserver:      ns2.google.com 
nserver:      ns3.google.com 
nserver:      ns4.google.com 
tech-c:       CN_10
registrar:    NIC-REG1
created:      14.03.2024 11:16:43`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsedWhois.DomainName != "google.cr" {
		t.Errorf("Expected domain name to be 'google.cr', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 5 {
		t.Errorf("Expected 5 statuses, got %d", len(parsedWhois.Statuses))
	}

	expectedStatuses := []string{
		"Administratively blocked",
		"Deletion forbidden",
		"Sponsoring registrar change forbidden",
		"Update forbidden",
		"Registrant change forbidden",
	}
	for i, status := range expectedStatuses {
		if parsedWhois.Statuses[i] != status {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, status, parsedWhois.Statuses[i])
		}
	}

	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "NIC-REG1" {
		t.Errorf("Expected registrar name to be 'NIC-REG1', got '%s'", func() string {
			if parsedWhois.Registrar == nil {
				return "nil"
			}
			return parsedWhois.Registrar.Name
		}())
	}

	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	if parsedWhois.CreatedDateRaw != "02.03.2008 18:00:00" {
		t.Errorf("Expected created date raw to be '02.03.2008 18:00:00', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "26.05.2025 04:32:09" {
		t.Errorf("Expected updated date raw to be '26.05.2025 04:32:09', got '%s'", parsedWhois.UpdatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "03.03.2026" {
		t.Errorf("Expected expiration date raw to be '03.03.2026', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	// Test unregistered domain (case4)
	rawtextFree := `% Domain Information over Whois protocol
% 
% Whoisd Server Version: 3.15.0

%ERROR:101: no entries found
% 
% No entries found.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	if len(parsedWhoisFree.Statuses) != 1 || parsedWhoisFree.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhoisFree.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhoisFree.NameServers))
	}

	if parsedWhoisFree.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhoisFree.CreatedDateRaw)
	}

	if parsedWhoisFree.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhoisFree.UpdatedDateRaw)
	}

	if parsedWhoisFree.ExpiredDateRaw != "" {
		t.Errorf("Expected no expiration date for free domain, got '%s'", parsedWhoisFree.ExpiredDateRaw)
	}
}
