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

	if parsedWhois.DomainName != "google.lv" {
		t.Errorf("Expected domain name 'google.lv', got '%s'", parsedWhois.DomainName)
	}
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status 'active', got '%v'", parsedWhois.Statuses)
	}
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	if parsedWhois.Contacts.Registrant.Name != "Google LLC" {
		t.Errorf("Expected registrant name 'Google LLC', got '%s'", parsedWhois.Contacts.Registrant.Name)
	}
	if parsedWhois.Contacts.Registrant.Country != "US" {
		t.Errorf("Expected registrant country 'US', got '%s'", parsedWhois.Contacts.Registrant.Country)
	}
	if len(parsedWhois.Contacts.Registrant.Street) != 1 || parsedWhois.Contacts.Registrant.Street[0] != "1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA" {
		t.Errorf("Expected registrant address '1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA', got '%v'", parsedWhois.Contacts.Registrant.Street)
	}
	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "MarkMonitor Inc." {
		t.Errorf("Expected registrar name 'MarkMonitor Inc.', got '%v'", parsedWhois.Registrar)
	}
	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 nameservers, got %d", len(parsedWhois.NameServers))
	}
	if parsedWhois.NameServers[0] != "ns1.google.com" {
		t.Errorf("Expected first nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[0])
	}
	if parsedWhois.UpdatedDateRaw != "2025-06-18T23:12:30.974138+00:00" {
		t.Errorf("Expected updated date '2025-06-18T23:12:30.974138+00:00', got '%s'", parsedWhois.UpdatedDateRaw)
	}
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
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free', got '%v'", parsedWhois.Statuses)
	}
}

func TestLVTLDParser_GetName(t *testing.T) {
	parser := NewLVTLDParser()
	if parser.GetName() != "lv" {
		t.Errorf("Expected parser name 'lv', got '%s'", parser.GetName())
	}
}
