package domain

import (
	"os"
	"testing"
)

func TestSATLDParser_Parse(t *testing.T) {
	parser := NewSATLDParser()
	if parser.GetName() != "sa" {
		t.Errorf("Expected parser name to be 'sa', got '%s'", parser.GetName())
	}

	testCases := []struct {
		file     string
		expected *ParsedWhois
	}{
		{
			file: "testdata/sa/case1.txt",
			expected: &ParsedWhois{
				DomainName: "google.sa",
				Contacts: &Contacts{
					Registrant: &Contact{
						Organization: "Google LLC",
						Street:       []string{"************************* *********", "***** *************", "Unknown"},
					},
					Admin: &Contact{
						Name:   "Dnet *****",
						Street: []string{"***** *****", "***** *****", "*****"},
					},
					Tech: &Contact{
						Name:   "Domain *****",
						Street: []string{"***** *****", "***** *****", "*****"},
					},
				},
				NameServers: []string{"ns1.markmonitor.com", "ns3.markmonitor.com"},
				Dnssec:      "No",
			},
		},
		{
			file: "testdata/sa/case3.txt",
			expected: &ParsedWhois{
				DomainName: "nic.sa",
				Contacts: &Contacts{
					Registrant: &Contact{
						Organization: "SaudiNIC- CITC المركز السعودي لمعلومات الشبكة - هيئة الاتصالات وتقنية المعلومات",
						Street:       []string{"***************", "***** ******", "Unknown"},
					},
					Admin: &Contact{
						Name:   "هشام ***** ***** *****",
						Street: []string{"***** *****", "***** *****", "*****"},
					},
					Tech: &Contact{
						Name:   "هشام ***** ***** *****",
						Street: []string{"***** *****", "***** *****", "*****"},
					},
				},
				NameServers: []string{"ns1.nic.sa", "ns2.nic.sa"},
				Dnssec:      "Yes",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			rawtext, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("Failed to read test file %s: %v", tc.file, err)
			}

			result, err := parser.GetParsedWhois(string(rawtext))
			if err != nil {
				t.Fatalf("Failed to parse whois data: %v", err)
			}

			assertSABasicFields(t, result, tc.expected)
			assertSAContacts(t, result, tc.expected)
		})
	}
}

func assertSABasicFields(t *testing.T, result, expected *ParsedWhois) {
	if result.DomainName != expected.DomainName {
		t.Errorf("Expected domain name '%s', got '%s'", expected.DomainName, result.DomainName)
	}
	if result.Dnssec != expected.Dnssec {
		t.Errorf("Expected DNSSEC '%s', got '%s'", expected.Dnssec, result.Dnssec)
	}
	assertSANameServers(t, result, expected)
}

func assertSANameServers(t *testing.T, result, expected *ParsedWhois) {
	if len(result.NameServers) != len(expected.NameServers) {
		t.Errorf("Expected %d nameservers, got %d", len(expected.NameServers), len(result.NameServers))
		return
	}
	for i, ns := range expected.NameServers {
		if result.NameServers[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, result.NameServers[i])
		}
	}
}

func assertSAContacts(t *testing.T, result, expected *ParsedWhois) {
	if expected.Contacts == nil {
		return
	}
	assertSAContactWithStreet(t, "registrant", result.Contacts.Registrant, expected.Contacts.Registrant)
	assertSAContactWithStreet(t, "admin", result.Contacts.Admin, expected.Contacts.Admin)
	assertSAContactWithStreet(t, "tech", result.Contacts.Tech, expected.Contacts.Tech)
}

func assertSAContactWithStreet(t *testing.T, contactType string, actual, expected *Contact) {
	if expected == nil {
		return
	}
	if actual == nil {
		t.Errorf("Expected %s contact, got nil", contactType)
		return
	}
	if expected.Organization != actual.Organization {
		t.Errorf("Expected %s organization '%s', got '%s'", contactType, expected.Organization, actual.Organization)
	}
	if expected.Name != actual.Name {
		t.Errorf("Expected %s name '%s', got '%s'", contactType, expected.Name, actual.Name)
	}
	assertSAStreetAddress(t, contactType, actual.Street, expected.Street)
}

func assertSAStreetAddress(t *testing.T, contactType string, actual, expected []string) {
	if len(expected) != len(actual) {
		t.Errorf("Expected %d %s street lines, got %d", len(expected), contactType, len(actual))
		return
	}
	for i, street := range expected {
		if actual[i] != street {
			t.Errorf("Expected %s street '%s', got '%s'", contactType, street, actual[i])
		}
	}
}

func TestSATLDParser_ParseUnregistered(t *testing.T) {
	parser := NewSATLDParser()

	testCases := []struct {
		file string
	}{
		{"testdata/sa/case2.txt"},
		{"testdata/sa/case4.txt"},
		{"testdata/sa/case5.txt"},
		{"testdata/sa/case6.txt"},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			rawtext, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("Failed to read test file %s: %v", tc.file, err)
			}

			result, err := parser.GetParsedWhois(string(rawtext))
			if err != nil {
				t.Fatalf("Failed to parse whois data: %v", err)
			}

			if len(result.Statuses) != 1 || result.Statuses[0] != "free" {
				t.Errorf("Expected status 'free', got %v", result.Statuses)
			}
		})
	}
}
