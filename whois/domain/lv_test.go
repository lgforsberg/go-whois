package domain

import (
	"testing"
)

func TestLVTLDParser_Parse(t *testing.T) {
	parser := NewLVTLDParser()

	rawtext := `[Domain]
Domain: google.lv
Status: active

[Holder]
Type: Legal person
Country: US
Name: Google LLC
Address: 1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA
RegNr: None
Visit: https://www.nic.lv/whois/contact/google.lv to contact.

[Tech]
Type: Natural person
Visit: https://www.nic.lv/whois/contact/google.lv to contact.

[Registrar]
Type: Legal person
Name: MarkMonitor Inc.
Address: 1120 S. Rackham Way, Suite 300, Meridian, ID, 83642, USA
RegNr: 82-0513468
Visit: https://www.nic.lv/whois/contact/google.lv to contact.

[Nservers]
Nserver: ns1.google.com
Nserver: ns2.google.com
Nserver: ns3.google.com
Nserver: ns4.google.com

[Whois]
Updated: 2025-06-18T23:12:30.974138+00:00

[Disclaimer]
% The WHOIS service is provided solely for informational purposes.
% ...`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	assertLVRegisteredDomain(t, parsedWhois, "google.lv", "MarkMonitor Inc.", []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}, "2025-06-18T23:12:30.974138+00:00")
	assertLVRegistrantContact(t, parsedWhois, "Google LLC", "US", "1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA")
}

func TestLVTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewLVTLDParser()

	rawtext := `[Domain]
Domain: sdfasdf-sdf-sdf-sdf-sdf.lv
Status: free

[Whois]
Updated: 2025-06-18T23:12:30.974138+00:00`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	assertLVUnregisteredDomain(t, parsedWhois)
}

func TestLVTLDParser_GetName(t *testing.T) {
	parser := NewLVTLDParser()
	if parser.GetName() != "lv" {
		t.Errorf("Expected parser name 'lv', got '%s'", parser.GetName())
	}
}

func assertLVRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain, expectedRegistrar string, expectedNS []string, expectedUpdated string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status 'active', got '%v'", parsedWhois.Statuses)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != expectedRegistrar {
		t.Errorf("Expected registrar name '%s', got '%v'", expectedRegistrar, parsedWhois.Registrar)
	}
	assertStringSliceEqualLV(t, parsedWhois.NameServers, expectedNS, "nameserver")
	if parsedWhois.UpdatedDateRaw != expectedUpdated {
		t.Errorf("Expected updated date '%s', got '%s'", expectedUpdated, parsedWhois.UpdatedDateRaw)
	}
}

func assertLVRegistrantContact(t *testing.T, parsedWhois *ParsedWhois, expectedName, expectedCountry, expectedAddress string) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Name != expectedName {
		t.Errorf("Expected registrant name '%s', got '%s'", expectedName, parsedWhois.Contacts.Registrant.Name)
	}
	if parsedWhois.Contacts.Registrant.Country != expectedCountry {
		t.Errorf("Expected registrant country '%s', got '%s'", expectedCountry, parsedWhois.Contacts.Registrant.Country)
	}
	if len(parsedWhois.Contacts.Registrant.Street) != 1 || parsedWhois.Contacts.Registrant.Street[0] != expectedAddress {
		t.Errorf("Expected registrant address '%s', got '%v'", expectedAddress, parsedWhois.Contacts.Registrant.Street)
	}
}

func assertLVUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
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

func assertStringSliceEqualLV(t *testing.T, actual, expected []string, label string) {
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
