package domain

import (
	"testing"
)

func TestCNTLDParser(t *testing.T) {
	parser := NewCNTLDParser()
	if parser.GetName() != "cn" {
		t.Errorf("Expected parser name to be 'cn', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `Domain Name: google.cn
ROID: 20030311s10001s00033735-cn
Domain Status: clientDeleteProhibited
Domain Status: serverDeleteProhibited
Domain Status: serverUpdateProhibited
Domain Status: clientTransferProhibited
Domain Status: serverTransferProhibited
Registrant: 北京谷翔信息技术有限公司
Registrant Contact Email: dns-admin@google.com
Sponsoring Registrar: 厦门易名科技股份有限公司
Name Server: ns2.google.com
Name Server: ns1.google.com
Name Server: ns3.google.com
Name Server: ns4.google.com
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2026-03-17 12:48:36
DNSSEC: unsigned`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsedWhois.DomainName != "google.cn" {
		t.Errorf("Expected domain name to be 'google.cn', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
	}

	expectedNS := []string{"ns2.google.com", "ns1.google.com", "ns3.google.com", "ns4.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	if len(parsedWhois.Statuses) != 5 {
		t.Errorf("Expected 5 statuses, got %d", len(parsedWhois.Statuses))
	}

	expectedStatuses := []string{"clientDeleteProhibited", "serverDeleteProhibited", "serverUpdateProhibited", "clientTransferProhibited", "serverTransferProhibited"}
	for i, status := range expectedStatuses {
		if parsedWhois.Statuses[i] != status {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, status, parsedWhois.Statuses[i])
		}
	}

	if parsedWhois.CreatedDateRaw != "2003-03-17 12:20:05" {
		t.Errorf("Expected created date raw to be '2003-03-17 12:20:05', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2026-03-17 12:48:36" {
		t.Errorf("Expected expired date raw to be '2026-03-17 12:48:36', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.Dnssec != "unsigned" {
		t.Errorf("Expected dnssec to be 'unsigned', got '%s'", parsedWhois.Dnssec)
	}

	// Test unregistered domain (case11)
	rawtextFree := `No matching record.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	if len(parsedWhoisFree.Statuses) != 1 || parsedWhoisFree.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhoisFree.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhoisFree.NameServers))
	}

	if parsedWhoisFree.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhoisFree.CreatedDateRaw)
	}

	if parsedWhoisFree.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhoisFree.ExpiredDateRaw)
	}

	// Test another unregistered domain format (case3)
	rawtextFree2 := `the Domain Name you apply can not be registered online. Please consult your Domain Name registrar`

	parsedWhoisFree2, err := parser.GetParsedWhois(rawtextFree2)
	if err != nil {
		t.Errorf("Expected no error for free domain case3, got %v", err)
	}

	if len(parsedWhoisFree2.Statuses) != 1 || parsedWhoisFree2.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree2.Statuses)
	}
}
