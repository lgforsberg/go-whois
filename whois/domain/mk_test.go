package domain

import (
	"testing"
)

const mkTestRawtext = `% Domain Information over Whois protocol
% 
% Whoisd Server Version: 3.9.0
% Timestamp: Thu Jun 19 02:21:43 2025

domain:       google.mk
registrant:   UNET-R11
admin-c:      UNET-C12
nsset:        UNET-NS191
registrar:    UNET-REG
registered:   13.05.2008 14:00:00
changed:      17.04.2014 12:50:32
expire:       13.05.2026

contact:      UNET-R11
org:          Google LLC
name:         Google LLC
address:      Amphiteatre Parkway 1600
address:      Mountain View
address:      94043
address:      US
phone:        +1.6502530000
fax-no:       +1.6502530000
e-mail:       ccops@markmonitor.com
registrar:    UNET-REG
created:      25.03.2014 11:48:02
changed:      29.09.2021 16:26:23

contact:      UNET-C12
name:         MarkMonitor Inc..
address:      3540 East Longwing Lane Suite 300
address:      Meridian
address:      83646
address:      US
phone:        +1.2083895740
e-mail:       ccops@markmonitor.com
registrar:    UNET-REG
created:      25.03.2014 11:48:00
changed:      18.11.2024 22:26:24

nsset:        UNET-NS191
nserver:      ns2.google.com 
nserver:      ns1.google.com 
tech-c:       UNET-C12
registrar:    UNET-REG
created:      17.04.2014 12:50:22
changed:      17.04.2014 21:02:14
`

func TestMKTLDParser_Parse_DomainFields(t *testing.T) {
	parser := NewMKTLDParser()
	parsedWhois, err := parser.GetParsedWhois(mkTestRawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if parsedWhois.DomainName != "google.mk" {
		t.Errorf("Expected domain name 'google.mk', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "UNET-REG" {
		t.Errorf("Expected registrar name 'UNET-REG', got '%v'", parsedWhois.Registrar)
	}
	if parsedWhois.CreatedDateRaw != "13.05.2008 14:00:00" {
		t.Errorf("Expected created date '13.05.2008 14:00:00', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != "13.05.2026" {
		t.Errorf("Expected expired date '13.05.2026', got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func TestMKTLDParser_Parse_Contacts(t *testing.T) {
	parser := NewMKTLDParser()
	parsedWhois, err := parser.GetParsedWhois(mkTestRawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Name)
	}
	if parsedWhois.Contacts.Registrant.Organization != "Google LLC" {
		t.Errorf("Expected registrant organization 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Organization)
	}
	if parsedWhois.Contacts.Registrant.Email != "ccops@markmonitor.com" {
		t.Errorf("Expected registrant email 'ccops@markmonitor.com', got '%s'", parsedWhois.Contacts.Registrant.Email)
	}
}

func TestMKTLDParser_Parse_Nameservers(t *testing.T) {
	parser := NewMKTLDParser()
	parsedWhois, err := parser.GetParsedWhois(mkTestRawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(parsedWhois.NameServers) != 2 {
		t.Errorf("Expected 2 nameservers, got %d", len(parsedWhois.NameServers))
	}
	if parsedWhois.NameServers[0] != "ns2.google.com" {
		t.Errorf("Expected first nameserver 'ns2.google.com', got '%s'", parsedWhois.NameServers[0])
	}
	if parsedWhois.NameServers[1] != "ns1.google.com" {
		t.Errorf("Expected second nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[1])
	}
}

func TestMKTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewMKTLDParser()

	rawtext := `% Domain Information over Whois protocol
% 
% Whoisd Server Version: 3.9.0

%ERROR:101: no entries found
% 
% No entries found.`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expectedStatuses := []string{"not_found"}
	if len(parsedWhois.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsedWhois.Statuses), parsedWhois.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsedWhois.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsedWhois.Statuses[i])
		}
	}
}

func TestMKTLDParser_GetName(t *testing.T) {
	parser := NewMKTLDParser()
	if parser.GetName() != "mk" {
		t.Errorf("Expected parser name 'mk', got '%s'", parser.GetName())
	}
}
