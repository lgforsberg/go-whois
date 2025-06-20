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

	if parsedWhois.DomainName != "google.aw" {
		t.Errorf("Expected domain name to be 'google.aw', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "active" {
		t.Errorf("Expected status to be 'active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.Registrar == nil || parsedWhois.Registrar.Name != "SETAR N.V." {
		t.Errorf("Expected registrar name to be 'SETAR N.V.', got '%s'", func() string {
			if parsedWhois.Registrar == nil {
				return "nil"
			}
			return parsedWhois.Registrar.Name
		}())
	}

	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
	}

	expectedNS := []string{"ns1.googledomains.com", "ns2.googledomains.com", "ns3.googledomains.com", "ns4.googledomains.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	if parsedWhois.CreatedDateRaw != "2017-09-13" {
		t.Errorf("Expected created date raw to be '2017-09-13', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "2018-05-21" {
		t.Errorf("Expected updated date raw to be '2018-05-21', got '%s'", parsedWhois.UpdatedDateRaw)
	}

	// Test unregistered domain (case2)
	rawtextFree := `facebook.aw is free`

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

	if parsedWhoisFree.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhoisFree.UpdatedDateRaw)
	}
}
