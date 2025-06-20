package domain

import (
	"testing"
)

func TestKZTLDParser_Parse(t *testing.T) {
	parser := NewKZTLDParser()

	// Test registered domain
	rawtext := `Whois Server for the KZ top level domain name.
This server is maintained by KazNIC Organization, a ccTLD manager for Kazakhstan Republic.

Domain Name............: google.kz

Organization Using Domain Name
Name...................: Google Inc.
Organization Name......: Google Inc.
Street Address.........: 2400 E. Bayshore Pkwy
City...................: Mountain View
State..................: CA
Postal Code............: 94043
Country................: US

Administrative Contact/Agent
NIC Handle.............: C000000197393-KZ
Name...................: DNS Admin
Phone Number...........: +1.6502530000 
Fax Number.............: +1.6506188571 
Email Address..........: ccops@markmonitor.com

Nameserver in listed order

Primary server.........: ns1.google.com
Primary ip address.....: 216.239.32.10

Secondary server.......: ns2.google.com
Secondary ip address...: 216.239.34.10


Domain created: 1999-06-07 14:01:43 (GMT+0:00)
Last modified : 2012-11-28 04:16:59 (GMT+0:00)
Domain status : ok - Normal state.
                
Registar created: KAZNIC
Current Registar: KAZNIC`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	assertKZBasicFields(t, parsedWhois)
	assertKZContacts(t, parsedWhois)
	assertKZNameServers(t, parsedWhois)
}

func assertKZBasicFields(t *testing.T, parsedWhois *ParsedWhois) {
	// Check domain name
	if parsedWhois.DomainName != "google.kz" {
		t.Errorf("Expected domain name 'google.kz', got '%s'", parsedWhois.DomainName)
	}

	// Check dates
	if parsedWhois.CreatedDateRaw != "1999-06-07 14:01:43 (GMT+0:00)" {
		t.Errorf("Expected created date '1999-06-07 14:01:43 (GMT+0:00)', got '%s'", parsedWhois.CreatedDateRaw)
	}
	if parsedWhois.UpdatedDateRaw != "2012-11-28 04:16:59 (GMT+0:00)" {
		t.Errorf("Expected updated date '2012-11-28 04:16:59 (GMT+0:00)', got '%s'", parsedWhois.UpdatedDateRaw)
	}

	// Check status
	if len(parsedWhois.Statuses) != 1 {
		t.Errorf("Expected 1 status, got %d", len(parsedWhois.Statuses))
	}
	if parsedWhois.Statuses[0] != "ok - Normal state." {
		t.Errorf("Expected status 'ok - Normal state.', got '%s'", parsedWhois.Statuses[0])
	}

	// Check registrar
	if parsedWhois.Registrar == nil {
		t.Fatal("Expected registrar to be parsed")
	}
	if parsedWhois.Registrar.Name != "KAZNIC" {
		t.Errorf("Expected registrar name 'KAZNIC', got '%s'", parsedWhois.Registrar.Name)
	}
}

func assertKZContacts(t *testing.T, parsedWhois *ParsedWhois) {
	assertKZRegistrant(t, parsedWhois)
	assertKZAdmin(t, parsedWhois)
}

func assertKZRegistrant(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}
	registrant := parsedWhois.Contacts.Registrant
	if registrant.Name != "Google Inc." {
		t.Errorf("Expected registrant name 'Google Inc.', got '%s'", registrant.Name)
	}
	if registrant.Organization != "Google Inc." {
		t.Errorf("Expected registrant organization 'Google Inc.', got '%s'", registrant.Organization)
	}
	if registrant.Street[0] != "2400 E. Bayshore Pkwy" {
		t.Errorf("Expected registrant street '2400 E. Bayshore Pkwy', got '%s'", registrant.Street[0])
	}
	if registrant.City != "Mountain View" {
		t.Errorf("Expected registrant city 'Mountain View', got '%s'", registrant.City)
	}
	if registrant.State != "CA" {
		t.Errorf("Expected registrant state 'CA', got '%s'", registrant.State)
	}
	if registrant.Postal != "94043" {
		t.Errorf("Expected registrant postal '94043', got '%s'", registrant.Postal)
	}
	if registrant.Country != "US" {
		t.Errorf("Expected registrant country 'US', got '%s'", registrant.Country)
	}
}

func assertKZAdmin(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts.Admin == nil {
		t.Fatal("Expected admin contact to be parsed")
	}
	admin := parsedWhois.Contacts.Admin
	if admin.Name != "DNS Admin" {
		t.Errorf("Expected admin name 'DNS Admin', got '%s'", admin.Name)
	}
	if admin.Phone != "+1.6502530000" {
		t.Errorf("Expected admin phone '+1.6502530000', got '%s'", admin.Phone)
	}
	if admin.Fax != "+1.6506188571" {
		t.Errorf("Expected admin fax '+1.6506188571', got '%s'", admin.Fax)
	}
	if admin.Email != "ccops@markmonitor.com" {
		t.Errorf("Expected admin email 'ccops@markmonitor.com', got '%s'", admin.Email)
	}
}

func assertKZNameServers(t *testing.T, parsedWhois *ParsedWhois) {
	// Check name servers
	if len(parsedWhois.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(parsedWhois.NameServers))
		return
	}
	if parsedWhois.NameServers[0] != "ns1.google.com" {
		t.Errorf("Expected first nameserver 'ns1.google.com', got '%s'", parsedWhois.NameServers[0])
	}
	if parsedWhois.NameServers[1] != "ns2.google.com" {
		t.Errorf("Expected second nameserver 'ns2.google.com', got '%s'", parsedWhois.NameServers[1])
	}
}

func TestKZTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewKZTLDParser()

	// Test unregistered domain
	rawtext := `Whois Server for the KZ top level domain name.
This server is maintained by KazNIC Organization, a ccTLD manager for Kazakhstan Republic.

*** Nothing found for this query.`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check status for unregistered domain
	if len(parsedWhois.Statuses) != 1 {
		t.Errorf("Expected 1 status, got %d", len(parsedWhois.Statuses))
	}
	if parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status 'free', got '%s'", parsedWhois.Statuses[0])
	}
}

func TestKZTLDParser_GetName(t *testing.T) {
	parser := NewKZTLDParser()
	if parser.GetName() != "kz" {
		t.Errorf("Expected parser name 'kz', got '%s'", parser.GetName())
	}
}
