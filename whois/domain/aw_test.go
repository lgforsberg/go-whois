package domain

import (
	"testing"
)

func TestAWTLDParser(t *testing.T) {
	parser := NewAWTLDParser()
	if parser.GetName() != "aw" {
		t.Errorf("Expected parser name to be 'aw', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `Domain name: google.aw
Status:      active

Registrar:
   SETAR N.V.
   Administration Building
   Seroe Blanco 29A
   Oranjestad
   Aruba

DNSSEC:      no

Domain nameservers:
   ns1.googledomains.com
   ns2.googledomains.com
   ns3.googledomains.com
   ns4.googledomains.com

Creation Date: 2017-09-13

Updated Date: 2018-05-21

Record maintained by: AW Domain Registry

Copyright notice: No part of this publication may be reproduced,
published, stored in a retrieval system, or transmitted, in any form
or by any means, electronic, mechanical, recording, or otherwise,
without prior permission of Setar. These restrictions apply equally to
registrars, except in that reproductions and publications are
permitted insofar as they are reasonable, necessary and solely in the
context of the registration activities referred to in the General
Terms and Conditions for Registrars. Any use of this material for
advertising, targeting commercial offers or similar activities is
explicitly forbidden and liable to result in legal action. Anyone who
is aware or suspects that such activities are taking place is asked to
inform Setar. (c) Setar Copyright Act, protection of authors' rights
(Section 10, subsection 1, clause 1).`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertAWRegisteredDomain(t, parsedWhois, "google.aw", "SETAR N.V.", []string{"ns1.googledomains.com", "ns2.googledomains.com", "ns3.googledomains.com", "ns4.googledomains.com"}, "2017-09-13", "2018-05-21")

	// Test unregistered domain (case2)
	rawtextFree := `facebook.aw is free`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertAWUnregisteredDomain(t, parsedWhoisFree)
}

func assertAWRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain, expectedRegistrar string, expectedNS []string, expectedCreated, expectedUpdated string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != expectedRegistrar {
		t.Errorf("Expected registrar name to be '%s', got '%s'", expectedRegistrar, func() string {
			if parsedWhois.Registrar == nil {
				return "nil"
			}
			return parsedWhois.Registrar.Name
		}())
	}

	assertStringSliceEqualAW(t, parsedWhois.NameServers, expectedNS, "name server")

	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date raw to be '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != expectedUpdated {
		t.Errorf("Expected updated date raw to be '%s', got '%s'", expectedUpdated, parsedWhois.UpdatedDateRaw)
	}
}

func assertAWUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
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
}

func assertStringSliceEqualAW(t *testing.T, actual, expected []string, label string) {
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
