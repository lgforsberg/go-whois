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

	if parsedWhois1.DomainName != "google.de" {
		t.Errorf("Expected domain name to be 'google.de', got '%s'", parsedWhois1.DomainName)
	}

	if len(parsedWhois1.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois1.NameServers))
	}

	expectedNS1 := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	for i, ns := range expectedNS1 {
		if parsedWhois1.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois1.NameServers[i])
		}
	}

	if len(parsedWhois1.Statuses) != 1 || parsedWhois1.Statuses[0] != "connect" {
		t.Errorf("Expected status to be 'connect', got %v", parsedWhois1.Statuses)
	}

	if parsedWhois1.UpdatedDateRaw != "2018-03-12T21:44:25+01:00" {
		t.Errorf("Expected updated date raw to be '2018-03-12T21:44:25+01:00', got '%s'", parsedWhois1.UpdatedDateRaw)
	}

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

	if parsedWhois2.DomainName != "org.de" {
		t.Errorf("Expected domain name to be 'org.de', got '%s'", parsedWhois2.DomainName)
	}

	if len(parsedWhois2.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(parsedWhois2.NameServers))
	}

	expectedNS2 := []string{"ns1.sedoparking.com", "ns2.sedoparking.com"}
	for i, ns := range expectedNS2 {
		if parsedWhois2.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois2.NameServers[i])
		}
	}

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

	if parsedWhois3.DomainName != "nic.de" {
		t.Errorf("Expected domain name to be 'nic.de', got '%s'", parsedWhois3.DomainName)
	}

	if len(parsedWhois3.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois3.NameServers))
	}

	expectedNS3 := []string{"ns1.denic.de", "ns2.denic.de", "ns3.denic.de", "ns4.denic.net"}
	for i, ns := range expectedNS3 {
		if parsedWhois3.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois3.NameServers[i])
		}
	}

	// Test unregistered domain (case8)
	rawtextFree := `Domain: sdfsdfsdfsdfsdfsdf1212.de
Status: free`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	if parsedWhoisFree.DomainName != "sdfsdfsdfsdfsdfsdf1212.de" {
		t.Errorf("Expected domain name to be 'sdfsdfsdfsdfsdfsdf1212.de', got '%s'", parsedWhoisFree.DomainName)
	}

	if len(parsedWhoisFree.Statuses) != 1 || parsedWhoisFree.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhoisFree.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhoisFree.NameServers))
	}

	if parsedWhoisFree.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhoisFree.UpdatedDateRaw)
	}

	// Test another unregistered domain (case11)
	rawtextFree2 := `Domain: jthsitshtkckthst124312.de
Status: free`

	parsedWhoisFree2, err := parser.GetParsedWhois(rawtextFree2)
	if err != nil {
		t.Errorf("Expected no error for free domain case11, got %v", err)
	}

	if parsedWhoisFree2.DomainName != "jthsitshtkckthst124312.de" {
		t.Errorf("Expected domain name to be 'jthsitshtkckthst124312.de', got '%s'", parsedWhoisFree2.DomainName)
	}

	if len(parsedWhoisFree2.Statuses) != 1 || parsedWhoisFree2.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree2.Statuses)
	}
}
