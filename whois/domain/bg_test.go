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

	assertBGRegisteredDomain(t, parsedWhois, "google.bg", []string{"ns2.google.com", "ns4.google.com", "ns3.google.com", "ns1.google.com"})

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

	assertBGRegisteredDomain(t, parsedWhois2, "facebook.bg", []string{"ns87.icndns.net", "ns88.icndns.net"})

	// Test unregistered domain (empty response)
	rawtextFree := ""

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertBGUnregisteredDomain(t, parsedWhoisFree)
}

func assertBGRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain string, expectedNS []string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	assertStringSliceEqualBG(t, parsedWhois.NameServers, expectedNS, "name server")
}

func assertBGUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}
}

func assertStringSliceEqualBG(t *testing.T, actual, expected []string, label string) {
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
