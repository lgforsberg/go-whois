package domain

import (
	"testing"
)

func TestBGTLDParser(t *testing.T) {
	parser := NewBGTLDParser()
	if parser.GetName() != "bg" {
		t.Errorf("Expected parser name to be 'bg', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `DOMAIN NAME: google.bg (google.bg)
registration status: busy, active

NAME SERVER INFORMATION:
ns2.google.com 
ns4.google.com 
ns3.google.com 
ns1.google.com 

DNSSEC: inactive

According to REGULATION (EU) 2016/679 OF THE EUROPEAN PARLIAMENT AND
OF THE COUNCIL (GDPR) personal data is not published.

If you would like to contact the persons responsible for the domain
name, please, use the online WHOIS contact form from the "Info / Whois" menu
at www.register.bg.`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsedWhois.DomainName != "google.bg" {
		t.Errorf("Expected domain name to be 'google.bg', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
	}

	expectedNS := []string{"ns2.google.com", "ns4.google.com", "ns3.google.com", "ns1.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	// Test another registered domain (case2)
	rawtext2 := `DOMAIN NAME: facebook.bg (facebook.bg)
registration status: busy, active

NAME SERVER INFORMATION:
ns87.icndns.net 
ns88.icndns.net 

DNSSEC: inactive

According to REGULATION (EU) 2016/679 OF THE EUROPEAN PARLIAMENT AND
OF THE COUNCIL (GDPR) personal data is not published.

If you would like to contact the persons responsible for the domain
name, please, use the online WHOIS contact form from the "Info / Whois" menu
at www.register.bg.`

	parsedWhois2, err := parser.GetParsedWhois(rawtext2)
	if err != nil {
		t.Errorf("Expected no error for second domain, got %v", err)
	}

	if parsedWhois2.DomainName != "facebook.bg" {
		t.Errorf("Expected domain name to be 'facebook.bg', got '%s'", parsedWhois2.DomainName)
	}

	if len(parsedWhois2.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(parsedWhois2.NameServers))
	}

	expectedNS2 := []string{"ns87.icndns.net", "ns88.icndns.net"}
	for i, ns := range expectedNS2 {
		if parsedWhois2.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois2.NameServers[i])
		}
	}

	// Test unregistered domain (empty response)
	rawtextFree := ""

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	if len(parsedWhoisFree.Statuses) != 1 || parsedWhoisFree.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree.Statuses)
	}

	// Verify that free domains have no nameservers
	if len(parsedWhoisFree.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhoisFree.NameServers))
	}
}
