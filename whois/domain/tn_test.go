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

	// Check nameservers
	expectedNS := []string{"ns4.google.com.", "ns1.google.com.", "ns3.google.com.", "ns2.google.com."}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}
	for i, ns := range expectedNS {
		if parsed.NameServers[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, parsed.NameServers[i])
		}
	}

	// Check registrant contact
	if parsed.Contacts.Registrant == nil {
		t.Error("Expected registrant contact to be present")
	} else {
		if parsed.Contacts.Registrant.Name != "Google LLC" {
			t.Errorf("Expected registrant name 'Google LLC', got '%s'", parsed.Contacts.Registrant.Name)
		}
		if len(parsed.Contacts.Registrant.Street) == 0 || parsed.Contacts.Registrant.Street[0] != "1600 Amphitheatre Parkway, Mountain View, CA 94043 US" {
			t.Errorf("Expected registrant address '1600 Amphitheatre Parkway, Mountain View, CA 94043 US', got %v", parsed.Contacts.Registrant.Street)
		}
		if parsed.Contacts.Registrant.Phone != "+1.6502530000" {
			t.Errorf("Expected registrant phone '+1.6502530000', got '%s'", parsed.Contacts.Registrant.Phone)
		}
		if parsed.Contacts.Registrant.Email != "dns-admin@google.com" {
			t.Errorf("Expected registrant email 'dns-admin@google.com', got '%s'", parsed.Contacts.Registrant.Email)
		}
	}

	// Check admin contact
	if parsed.Contacts.Admin == nil {
		t.Error("Expected admin contact to be present")
	} else {
		if parsed.Contacts.Admin.Name != "Abu ghazalah intellectual property" {
			t.Errorf("Expected admin name 'Abu ghazalah intellectual property', got '%s'", parsed.Contacts.Admin.Name)
		}
		if len(parsed.Contacts.Admin.Street) == 0 || parsed.Contacts.Admin.Street[0] != "P.O.Box 1, Montplaisir 1073, Tunis, Tunisia" {
			t.Errorf("Expected admin address 'P.O.Box 1, Montplaisir 1073, Tunis, Tunisia', got %v", parsed.Contacts.Admin.Street)
		}
		if parsed.Contacts.Admin.Phone != "71 90 3141" {
			t.Errorf("Expected admin phone '71 90 3141', got '%s'", parsed.Contacts.Admin.Phone)
		}
		if parsed.Contacts.Admin.Email != "tunisia@agip.com" {
			t.Errorf("Expected admin email 'tunisia@agip.com', got '%s'", parsed.Contacts.Admin.Email)
		}
	}

	// Check tech contact
	if parsed.Contacts.Tech == nil {
		t.Error("Expected tech contact to be present")
	} else {
		if parsed.Contacts.Tech.Name != "MarkMonitor Inc." {
			t.Errorf("Expected tech name 'MarkMonitor Inc.', got '%s'", parsed.Contacts.Tech.Name)
		}
		if len(parsed.Contacts.Tech.Street) == 0 || parsed.Contacts.Tech.Street[0] != "391 N. Ancestor Pl., Boise, ID 83704 US" {
			t.Errorf("Expected tech address '391 N. Ancestor Pl., Boise, ID 83704 US', got %v", parsed.Contacts.Tech.Street)
		}
		if parsed.Contacts.Tech.Phone != "+1.2083895740" {
			t.Errorf("Expected tech phone '+1.2083895740', got '%s'", parsed.Contacts.Tech.Phone)
		}
		if parsed.Contacts.Tech.Email != "ccops@markmonitor.com" {
			t.Errorf("Expected tech email 'ccops@markmonitor.com', got '%s'", parsed.Contacts.Tech.Email)
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
