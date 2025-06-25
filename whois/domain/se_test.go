package domain

import (
	"testing"
)

func TestSETLDParser(t *testing.T) {
	parser := NewSETLDParser()
	if parser.GetName() != "se" {
		t.Errorf("Expected parser name to be 'se', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `# Copyright (c) 1997- The Swedish Internet Foundation.
# All rights reserved.
# The information obtained through searches, or otherwise, is protected
# by the Swedish Copyright Act (1960:729) and international conventions.
# It is also subject to database protection according to the Swedish
# Copyright Act.
# Any use of this material to target advertising or
# similar activities is forbidden and will be prosecuted.
# If any of the information below is transferred to a third
# party, it must be done in its entirety. This server must
# not be used as a backend for a search engine.
# Result of search for registered domain names under
# the .se top level domain.
# This whois printout is printed with UTF-8 encoding.
#
state:            active
domain:           google.se
holder:           mmr8008-171440
created:          2003-08-27
modified:         2024-09-18
expires:          2025-10-20
transferred:      2009-03-06
nserver:          ns1.google.com
nserver:          ns2.google.com
nserver:          ns3.google.com
nserver:          ns4.google.com
dnssec:           unsigned delegation
registry-lock:    locked
status:           serverUpdateProhibited
status:           serverDeleteProhibited
status:           serverTransferProhibited
registrar:        MarkMonitor Inc`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertSERegisteredDomain(t, parsedWhois)

	// Test unregistered domain (case8)
	rawtextFree := `# Copyright (c) 1997- The Swedish Internet Foundation.
# All rights reserved.
# The information obtained through searches, or otherwise, is protected
# by the Swedish Copyright Act (1960:729) and international conventions.
# It is also subject to database protection according to the Swedish
# Copyright Act.
# Any use of this material to target advertising or
# similar activities is forbidden and will be prosecuted.
# If any of the information below is transferred to a third
# party, it must be done in its entirety. This server must
# not be used as a backend for a search engine.
# Result of search for registered domain names under
# the .se top level domain.
# This whois printout is printed with UTF-8 encoding.
#
domain "sdfsdfsdfsdfsdfsdf1212.se" not found.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertSEUnregisteredDomain(t, parsedWhoisFree)
}

func assertSERegisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.se" {
		t.Errorf("Expected domain name to be 'google.se', got '%s'", parsedWhois.DomainName)
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualSE(t, parsedWhois.NameServers, expectedNS, "name server")

	expectedStatuses := []string{"serverUpdateProhibited", "serverDeleteProhibited", "serverTransferProhibited"}
	assertStringSliceEqualSE(t, parsedWhois.Statuses, expectedStatuses, "status")

	if parsedWhois.CreatedDateRaw != "2003-08-27" {
		t.Errorf("Expected created date raw to be '2003-08-27', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "2024-09-18" {
		t.Errorf("Expected updated date raw to be '2024-09-18', got '%s'", parsedWhois.UpdatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2025-10-20" {
		t.Errorf("Expected expired date raw to be '2025-10-20', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.Dnssec != "unsigned delegation" {
		t.Errorf("Expected dnssec to be 'unsigned delegation', got '%s'", parsedWhois.Dnssec)
	}
}

func assertSEUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	// v2.0.0: Expect single "not_found" status for clean behavior
	expectedStatuses := []string{"not_found"}
	if len(parsedWhois.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsedWhois.Statuses), parsedWhois.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsedWhois.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsedWhois.Statuses[i])
		}
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhois.UpdatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertStringSliceEqualSE(t *testing.T, actual, expected []string, label string) {
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

func TestNUTLDParser(t *testing.T) {
	parser := NewSETLDParser()
	// Test registered domain (case1)
	rawtext := `# Copyright (c) 1997- The Swedish Internet Foundation.
# All rights reserved.
# The information obtained through searches, or otherwise, is protected
# by the Swedish Copyright Act (1960:729) and international conventions.
# It is also subject to database protection according to the Swedish
# Copyright Act.
# Any use of this material to target advertising or
# similar activities is forbidden and will be prosecuted.
# If any of the information below is transferred to a third
# party, it must be done in its entirety. This server must
# not be used as a backend for a search engine.
# Result of search for registered domain names under
# the .se top level domain.
# This whois printout is printed with UTF-8 encoding.
#
state:            active
domain:           google.nu
holder:           mmr-171440
created:          1999-06-07
modified:         2025-05-06
expires:          2026-06-07
nserver:          ns1.google.com
nserver:          ns2.google.com
nserver:          ns3.google.com
nserver:          ns4.google.com
dnssec:           unsigned delegation
registry-lock:    unlocked
status:           ok
registrar:        MarkMonitor Inc`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertNURegisteredDomain(t, parsedWhois)

	// Test unregistered domain (case8)
	rawtextFree := `# Copyright (c) 1997- The Swedish Internet Foundation.
# All rights reserved.
# The information obtained through searches, or otherwise, is protected
# by the Swedish Copyright Act (1960:729) and international conventions.
# It is also subject to database protection according to the Swedish
# Copyright Act.
# Any use of this material to target advertising or
# similar activities is forbidden and will be prosecuted.
# If any of the information below is transferred to a third
# party, it must be done in its entirety. This server must
# not be used as a backend for a search engine.
# Result of search for registered domain names under
# the .se top level domain.
# This whois printout is printed with UTF-8 encoding.
#
domain "sdfsdfsdfsdfsdfsdf1212.nu" not found.`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertNUUnregisteredDomain(t, parsedWhoisFree)
}

func assertNURegisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	if parsedWhois.DomainName != "google.nu" {
		t.Errorf("Expected domain name to be 'google.nu', got '%s'", parsedWhois.DomainName)
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	assertStringSliceEqualNU(t, parsedWhois.NameServers, expectedNS, "name server")

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "ok" {
		t.Errorf("Expected status to be 'ok', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != "1999-06-07" {
		t.Errorf("Expected created date raw to be '1999-06-07', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2026-06-07" {
		t.Errorf("Expected expired date raw to be '2026-06-07', got '%s'", parsedWhois.ExpiredDateRaw)
	}
}

func assertNUUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	// v2.0.0: Expect single "not_found" status for clean behavior
	expectedStatuses := []string{"not_found"}
	if len(parsedWhois.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsedWhois.Statuses), parsedWhois.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsedWhois.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsedWhois.Statuses[i])
		}
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

func assertStringSliceEqualNU(t *testing.T, actual, expected []string, label string) {
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
