package domain

import (
	"testing"
)

func TestMDTLDParser_Parse(t *testing.T) {
	parser := NewMDTLDParser()

	rawtext := `Domain  name    google.md
Domain state    OK

Registered on   2006-05-02
Expires    on   2026-05-02

Nameserver      ns1.google.com
Nameserver      ns2.google.com`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if parsedWhois.DomainName != "google.md" {
		t.Errorf("Expected domain name 'google.md', got '%s'", parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "OK" {
		t.Errorf("Expected status 'OK', got '%v'", parsedWhois.Statuses)
	}
	if parsedWhois.CreatedDateRaw != "2006-05-02" {
		t.Errorf("Expected created date '2006-05-02', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.ExpiredDateRaw != "2026-05-02" {
		t.Errorf("Expected expired date '2026-05-02', got '%s'", parsedWhois.ExpiredDateRaw)
	}
	if len(parsedWhois.NameServers) != 2 {
		t.Errorf("Expected 2 nameservers, got %d", len(parsedWhois.NameServers))
	}
	if parsedWhois.NameServers[0] != "ns1.google.com" {
		t.Errorf("Expected first nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[0])
	}
	if parsedWhois.NameServers[1] != "ns2.google.com" {
		t.Errorf("Expected second nameserver 'ns2.google.com', got '%s'", parsedWhois.NameServers[1])
	}
}

func TestMDTLDParser_ParseWithRegistrant(t *testing.T) {
	parser := NewMDTLDParser()

	rawtext := `Domain  name    facebook.md
Domain state    OK
Registrant      Meta Platforms, Inc.

Registered on   2012-08-27
Expires    on   2025-08-27

Nameserver      a.ns.facebook.com
Nameserver      b.ns.facebook.com
Nameserver      c.ns.facebook.com
Nameserver      d.ns.facebook.com`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if parsedWhois.DomainName != "facebook.md" {
		t.Errorf("Expected domain name 'facebook.md', got '%s'", parsedWhois.DomainName)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Name != "Meta Platforms, Inc." {
		t.Errorf("Expected registrant name 'Meta Platforms, Inc.', got '%s'", parsedWhois.Contacts.Registrant.Name)
	}
	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 nameservers, got %d", len(parsedWhois.NameServers))
	}
}

func TestMDTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewMDTLDParser()

	rawtext := `No match for`

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

func TestMDTLDParser_GetName(t *testing.T) {
	parser := NewMDTLDParser()
	if parser.GetName() != "md" {
		t.Errorf("Expected parser name 'md', got '%s'", parser.GetName())
	}
}
