package domain

import (
	"testing"
)

func TestTNTLDParser(t *testing.T) {
	parser := NewTNTLDParser()
	if parser.GetName() != "tn" {
		t.Errorf("Expected parser name to be 'tn', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `NIC Whois server for cTLDs : .tn , .تونس
All rights reserved
Copyright "Tunisian Internet Agency - https://whois.ati.tn
Supported ccTLDs : .tn , .تونس
Sectorial domains : .com.tn,.ens.tn,.fin.tn,.gov.tn,.ind.tn,.intl.tn,.nat.tn,.net.tn,.org.tn,.info.tn,.perso.tn,.tourism.tn,.mincom.tn

Domain name.........: google.tn
Details:
Creation date.......: 05-12-2018 11:02:02 GMT+1
Domain status.......: Active
Registrar...........: ELB

Owner Contact
Name................: Google LLC
First name..........: 
Address.............: 1600 Amphitheatre Parkway, Mountain View, CA 94043 US
address2............: 
City................: 
stateProvince.......: 
Zip code............: 
Country.............: 
Phone...............: +1.6502530000
Fax.................: +1.6502530001
Email...............: dns-admin@google.com

Administrativ contact
Name................: Abu ghazalah intellectual property
First name..........: 
Address.............: P.O.Box 1, Montplaisir 1073, Tunis, Tunisia
address2............: 
City................: 
stateProvince.......: 
Zip code............: 
Country.............: 
Phone...............: 71 90 3141
Fax.................: 71 90 9426
Email...............: tunisia@agip.com

Technical contact
Name................: MarkMonitor Inc.
First name..........: 
Address.............: 391 N. Ancestor Pl., Boise, ID 83704 US
address2............: 
City................: 
stateProvince.......: 
Zip code............: 
Country.............: 
Phone...............: +1.2083895740
Fax.................: +1.2083895771
Email...............: ccops@markmonitor.com
dnssec..............: unsigned

DNS servers
Name................: ns4.google.com.
Name................: ns1.google.com.
Name................: ns3.google.com.
Name................: ns2.google.com.
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertTNBasicFields(t, parsed)
	assertTNContacts(t, parsed)
	assertTNNameServers(t, parsed)
}

func assertTNBasicFields(t *testing.T, parsed *ParsedWhois) {
	if parsed.DomainName != "google.tn" {
		t.Errorf("Expected domain name 'google.tn', got '%s'", parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "05-12-2018 11:02:02 GMT+1" {
		t.Errorf("Expected created date '05-12-2018 11:02:02 GMT+1', got '%s'", parsed.CreatedDateRaw)
	}

	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "Active" {
		t.Errorf("Expected status 'Active', got %v", parsed.Statuses)
	}

	if parsed.Registrar.Name != "ELB" {
		t.Errorf("Expected registrar 'ELB', got '%s'", parsed.Registrar.Name)
	}

	if parsed.Dnssec != "unsigned" {
		t.Errorf("Expected DNSSEC 'unsigned', got '%s'", parsed.Dnssec)
	}
}

func assertTNContacts(t *testing.T, parsed *ParsedWhois) {
	assertTNRegistrantContact(t, parsed)
	assertTNAdminContact(t, parsed)
	assertTNTechContact(t, parsed)
}

func assertTNRegistrantContact(t *testing.T, parsed *ParsedWhois) {
	if parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
		return
	}

	registrant := parsed.Contacts.Registrant
	assertTNContactFields(t, registrant, "registrant", "Google LLC", "1600 Amphitheatre Parkway, Mountain View, CA 94043 US", "+1.6502530000", "dns-admin@google.com")
}

func assertTNAdminContact(t *testing.T, parsed *ParsedWhois) {
	if parsed.Contacts.Admin == nil {
		t.Error("Expected admin contact to be present")
		return
	}

	admin := parsed.Contacts.Admin
	assertTNContactFields(t, admin, "admin", "Abu ghazalah intellectual property", "P.O.Box 1, Montplaisir 1073, Tunis, Tunisia", "71 90 3141", "tunisia@agip.com")
}

func assertTNTechContact(t *testing.T, parsed *ParsedWhois) {
	if parsed.Contacts.Tech == nil {
		t.Error("Expected tech contact to be present")
		return
	}

	tech := parsed.Contacts.Tech
	assertTNContactFields(t, tech, "tech", "MarkMonitor Inc.", "391 N. Ancestor Pl., Boise, ID 83704 US", "+1.2083895740", "ccops@markmonitor.com")
}

func assertTNContactFields(t *testing.T, contact *Contact, contactType, expectedName, expectedAddress, expectedPhone, expectedEmail string) {
	if contact.Name != expectedName {
		t.Errorf("Expected %s name '%s', got '%s'", contactType, expectedName, contact.Name)
	}
	if len(contact.Street) == 0 || contact.Street[0] != expectedAddress {
		t.Errorf("Expected %s address '%s', got %v", contactType, expectedAddress, contact.Street)
	}
	if contact.Phone != expectedPhone {
		t.Errorf("Expected %s phone '%s', got '%s'", contactType, expectedPhone, contact.Phone)
	}
	if contact.Email != expectedEmail {
		t.Errorf("Expected %s email '%s', got '%s'", contactType, expectedEmail, contact.Email)
	}
}

func assertTNNameServers(t *testing.T, parsed *ParsedWhois) {
	expectedNS := []string{"ns4.google.com.", "ns1.google.com.", "ns3.google.com.", "ns2.google.com."}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
		return
	}
	for i, ns := range expectedNS {
		if parsed.NameServers[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, parsed.NameServers[i])
		}
	}
}

func TestTNTLDParserUnregistered(t *testing.T) {
	parser := NewTNTLDParser()

	// Test unregistered domain
	whoisText := `NIC Whois server for cTLDs : .tn , .تونس
All rights reserved
Copyright "Tunisian Internet Agency - https://whois.ati.tn
Supported ccTLDs : .tn , .تونس
Sectorial domains : .com.tn,.ens.tn,.fin.tn,.gov.tn,.ind.tn,.intl.tn,.nat.tn,.net.tn,.org.tn,.info.tn,.perso.tn,.tourism.tn,.mincom.tn

NO OBJECT FOUND!
object:.............sdfasdf-sdf-sdf-sdf-sdf.tn
type:...............domain
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

	if parsed.Contacts.Tech != nil {
		t.Error("Expected no tech contact for unregistered domain")
	}
}
