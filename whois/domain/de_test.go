package domain

import (
	"testing"
)

func TestDETLDParser(t *testing.T) {
	parser := NewDETLDParser()
	if parser.GetName() != "de" {
		t.Errorf("Expected parser name to be 'de', got '%s'", parser.GetName())
	}

	// Test registered domain with 4 nameservers (case1)
	rawtext1 := `% Restricted rights.
% 
% Terms and Conditions of Use
% 
% The above data may only be used within the scope of technical or
% administrative necessities of Internet operation or to remedy legal
% problems.
% The use for other purposes, in particular for advertising, is not permitted.
% 
% The DENIC whois service on port 43 doesn't disclose any information concerning
% the domain holder, general request and abuse contact.
% This information can be obtained through use of our web-based whois service
% available at the DENIC website:
% http://www.denic.de/en/domains/whois-service/web-whois.html
% 
% 

Domain: google.de
Nserver: ns1.google.com
Nserver: ns2.google.com
Nserver: ns3.google.com
Nserver: ns4.google.com
Status: connect
Changed: 2018-03-12T21:44:25+01:00`

	parsedWhois1, err := parser.GetParsedWhois(rawtext1)
	if err != nil {
		t.Errorf("Expected no error for case1, got %v", err)
	}

	assertDERegisteredDomain(t, parsedWhois1, "google.de", []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}, "connect", "2018-03-12T21:44:25+01:00")

	// Test registered domain with 2 nameservers (case6)
	rawtext2 := `% Restricted rights.
% 
% Terms and Conditions of Use
% 
% The above data may only be used within the scope of technical or
% administrative necessities of Internet operation or to remedy legal
% problems.
% The use for other purposes, in particular for advertising, is not permitted.
% 
% The DENIC whois service on port 43 doesn't disclose any information concerning
% the domain holder, general request and abuse contact.
% This information can be obtained through use of our web-based whois service
% available at the DENIC website:
% http://www.denic.de/en/domains/whois-service/web-whois.html
% 
% 

Domain: org.de
Nserver: ns1.sedoparking.com
Nserver: ns2.sedoparking.com
Status: connect
Changed: 2019-04-24T18:48:13+02:00`

	parsedWhois2, err := parser.GetParsedWhois(rawtext2)
	if err != nil {
		t.Errorf("Expected no error for case6, got %v", err)
	}

	assertDERegisteredDomain(t, parsedWhois2, "org.de", []string{"ns1.sedoparking.com", "ns2.sedoparking.com"}, "connect", "2019-04-24T18:48:13+02:00")

	// Test registered domain with Dnskey field (case3)
	rawtext3 := `% Restricted rights.
% 
% Terms and Conditions of Use
% 
% The above data may only be used within the scope of technical or
% administrative necessities of Internet operation or to remedy legal
% problems.
% The use for other purposes, in particular for advertising, is not permitted.
% 
% The DENIC whois service on port 43 doesn't disclose any information concerning
% the domain holder, general request and abuse contact.
% This information can be obtained through use of our web-based whois service
% available at the DENIC website:
% http://www.denic.de/en/domains/whois-service/web-whois.html
% 
% 

Domain: nic.de
Nserver: ns1.denic.de
Nserver: ns2.denic.de
Nserver: ns3.denic.de
Nserver: ns4.denic.net
Dnskey: 257 3 8 AwEAAb/xrM2MD+xm84YNYby6TxkMaC6PtzF2bB9WBB7ux7iqzhViob4GKvQ6L7CkXjyAxfKbTzrdvXoAPpsAPW4pkThReDAVp3QxvUKrkBM8/uWRF3wpaUoPsAHm1dbcL9aiW3lqlLMZjDEwDfU6lxLcPg9d14fq4dc44FvPx6aYcymkgJoYvR6P1wECpxqlEAR2K1cvMtqCqvVESBQV/EUtWiALNuwR2PbhwtBWJd+e8BdFI7OLkit4uYYux6Yu35uyGQ==
Status: connect
Changed: 2020-05-28T14:29:55+02:00`

	parsedWhois3, err := parser.GetParsedWhois(rawtext3)
	if err != nil {
		t.Errorf("Expected no error for case3, got %v", err)
	}

	assertDERegisteredDomain(t, parsedWhois3, "nic.de", []string{"ns1.denic.de", "ns2.denic.de", "ns3.denic.de", "ns4.denic.net"}, "connect", "2020-05-28T14:29:55+02:00")

	// Test unregistered domain (case8)
	rawtextFree := `Domain: sdfsdfsdfsdfsdfsdf1212.de
Status: free`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertDEUnregisteredDomain(t, parsedWhoisFree, "sdfsdfsdfsdfsdfsdf1212.de")

	// Test another unregistered domain (case11)
	rawtextFree2 := `Domain: jthsitshtkckthst124312.de
Status: free`

	parsedWhoisFree2, err := parser.GetParsedWhois(rawtextFree2)
	if err != nil {
		t.Errorf("Expected no error for free domain case11, got %v", err)
	}

	assertDEUnregisteredDomain(t, parsedWhoisFree2, "jthsitshtkckthst124312.de")
}

func assertDERegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain string, expectedNS []string, expectedStatus string, expectedUpdatedDate string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	if len(parsedWhois.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d name servers, got %d", len(expectedNS), len(parsedWhois.NameServers))
	}

	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != expectedStatus {
		t.Errorf("Expected status to be '%s', got %v", expectedStatus, parsedWhois.Statuses)
	}

	if parsedWhois.UpdatedDateRaw != expectedUpdatedDate {
		t.Errorf("Expected updated date raw to be '%s', got '%s'", expectedUpdatedDate, parsedWhois.UpdatedDateRaw)
	}
}

func assertDEUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhois.UpdatedDateRaw)
	}
}
