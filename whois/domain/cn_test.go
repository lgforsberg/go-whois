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

	assertCNRegisteredDomain(t, parsedWhois)

	// Test unregistered domain (case11)
	rawtextFree := `No matching record.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertCNUnregisteredDomain(t, parsedWhoisFree)

	// Test another unregistered domain format (case3)
	rawtextFree2 := `the Domain Name you apply can not be registered online. Please consult your Domain Name registrar`

	parsedWhoisFree2, err := parser.GetParsedWhois(rawtextFree2)
	if err != nil {
		t.Errorf("Expected no error for free domain case3, got %v", err)
	}

	assertCNUnregisteredDomain(t, parsedWhoisFree2)
}

func assertCNRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.cn" {
		t.Errorf("Expected domain name to be 'google.cn', got '%s'", parsedWhois.DomainName)
	}

	expectedNS := []string{"ns2.google.com", "ns1.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualCN(t, parsedWhois.NameServers, expectedNS, "name server")

	expectedStatuses := []string{"clientDeleteProhibited", "serverDeleteProhibited", "serverUpdateProhibited", "clientTransferProhibited", "serverTransferProhibited"}
	assertStringSliceEqualCN(t, parsedWhois.Statuses, expectedStatuses, "status")

	if parsedWhois.CreatedDateRaw != "2003-03-17 12:20:05" {
		t.Errorf("Expected created date raw to be '2003-03-17 12:20:05', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2026-03-17 12:48:36" {
		t.Errorf("Expected expired date raw to be '2026-03-17 12:48:36', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.Dnssec != "unsigned" {
		t.Errorf("Expected dnssec to be 'unsigned', got '%s'", parsedWhois.Dnssec)
	}
}

func assertCNUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhois.Statuses)
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertStringSliceEqualCN(t *testing.T, actual, expected []string, label string) {
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
