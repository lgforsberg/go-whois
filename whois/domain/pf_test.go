package domain

import (
	"os"
	"testing"
)

func TestPFTLDParser_Parse(t *testing.T) {
	parser := NewPFTLDParser()
	if parser.GetName() != "pf" {
		t.Errorf("Expected parser name to be 'pf', got '%s'", parser.GetName())
	}

	testCases := []struct {
		file     string
		expected *ParsedWhois
	}{
		{
			file: "testdata/pf/case1.txt",
			expected: &ParsedWhois{
				DomainName:     "google.pf",
				Statuses:       []string{"active"},
				CreatedDateRaw: "16/11/2010",
				UpdatedDateRaw: "12/11/2024",
				ExpiredDateRaw: "12/11/2025",
				NameServers:    []string{"ns3.google.com", "ns2.google.com", "ns4.google.com", "ns1.google.com"},
				Contacts: &Contacts{
					Registrant: &Contact{
						Organization: "GOOGLE LLC",
						Name:         "Christine Duvalis",
						Street:       []string{"Mountain View"},
						Postal:       "94043",
						City:         "California",
						Country:      "Etats Unis",
					},
					Tech: &Contact{
						Organization: "GOOGLE LLC",
						Name:         "Christine Duvalis",
						Street:       []string{"Mountain View"},
						Postal:       "94043",
						City:         "California",
						Country:      "Etats Unis",
					},
				},
				Registrar: &Registrar{
					Name: "ONATI SAS",
				},
			},
		},
		{
			file: "testdata/pf/case4.txt",
			expected: &ParsedWhois{
				DomainName:     "gov.pf",
				Statuses:       []string{"active"},
				CreatedDateRaw: "20/04/2015",
				UpdatedDateRaw: "17/04/2025",
				ExpiredDateRaw: "17/04/2026",
				NameServers:    []string{"services2.gov.pf", "services1.gov.pf"},
				Contacts: &Contacts{
					Registrant: &Contact{
						Organization: "DIRECTION DU SYSTEME D'INFORMATION - DSI",
						Name:         "Gouvernement de la  Polynésie Française",
						Email:        "secretariat.dsi@administration.gov.pf",
						Street:       []string{"BP 4574", "111 rue Dumont d'Urville, immeuble Toriki"},
						Postal:       "98713",
						City:         "PAPEETE",
						State:        "TAHITI",
						Country:      "Polynésie Française",
					},
					Tech: &Contact{
						Organization: "DIRECTION DU SYSTÈME D'INFORMATION - DSI",
						Name:         "Directeur  de la DSI",
						Email:        "secretariat.dsi@administration.gov.pf",
						Street:       []string{"BP 4574", "111 rue Dumont d'Urville, immeuble Toriki"},
						Postal:       "98713",
						City:         "PAPEETE",
						State:        "TAHITI",
						Country:      "Polynésie française",
					},
				},
				Registrar: &Registrar{
					Name: "ONATI SAS",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			file, err := os.Open(tc.file)
			if err != nil {
				t.Fatalf("Failed to open test file %s: %v", tc.file, err)
			}
			defer file.Close()

			rawtext, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("Failed to read test file %s: %v", tc.file, err)
			}

			result, err := parser.GetParsedWhois(string(rawtext))
			if err != nil {
				t.Fatalf("Failed to parse whois data: %v", err)
			}

			assertPFBasicFields(t, result, tc.expected)
			assertPFContacts(t, result, tc.expected)
			assertPFRegistrar(t, result, tc.expected)
		})
	}
}

func assertPFBasicFields(t *testing.T, result, expected *ParsedWhois) {
	if result.DomainName != expected.DomainName {
		t.Errorf("Expected domain name '%s', got '%s'", expected.DomainName, result.DomainName)
	}
	assertPFStatuses(t, result, expected)
	if result.CreatedDateRaw != expected.CreatedDateRaw {
		t.Errorf("Expected created date '%s', got '%s'", expected.CreatedDateRaw, result.CreatedDateRaw)
	}
	if result.UpdatedDateRaw != expected.UpdatedDateRaw {
		t.Errorf("Expected updated date '%s', got '%s'", expected.UpdatedDateRaw, result.UpdatedDateRaw)
	}
	if result.ExpiredDateRaw != expected.ExpiredDateRaw {
		t.Errorf("Expected expired date '%s', got '%s'", expected.ExpiredDateRaw, result.ExpiredDateRaw)
	}
	assertPFNameServers(t, result, expected)
}

func assertPFStatuses(t *testing.T, result, expected *ParsedWhois) {
	if len(result.Statuses) != len(expected.Statuses) {
		t.Errorf("Expected %d statuses, got %d", len(expected.Statuses), len(result.Statuses))
		return
	}
	for i, status := range expected.Statuses {
		if result.Statuses[i] != status {
			t.Errorf("Expected status '%s', got '%s'", status, result.Statuses[i])
		}
	}
}

func assertPFNameServers(t *testing.T, result, expected *ParsedWhois) {
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

func assertPFContacts(t *testing.T, result, expected *ParsedWhois) {
	if expected.Contacts == nil {
		return
	}
	assertPFContactWithEmail(t, "registrant", result.Contacts.Registrant, expected.Contacts.Registrant)
	assertPFContactWithEmail(t, "tech", result.Contacts.Tech, expected.Contacts.Tech)
}

func assertPFContactWithEmail(t *testing.T, contactType string, actual, expected *Contact) {
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
	if expected.Email != actual.Email {
		t.Errorf("Expected %s email '%s', got '%s'", contactType, expected.Email, actual.Email)
	}
}

func assertPFRegistrar(t *testing.T, result, expected *ParsedWhois) {
	if expected.Registrar != nil {
		if result.Registrar == nil {
			t.Error("Expected registrar, got nil")
		} else if expected.Registrar.Name != result.Registrar.Name {
			t.Errorf("Expected registrar name '%s', got '%s'", expected.Registrar.Name, result.Registrar.Name)
		}
	}
}

func TestPFTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewPFTLDParser()

	testCases := []struct {
		file string
	}{
		{"testdata/pf/case2.txt"},
		{"testdata/pf/case10.txt"},
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

			expectedStatuses := []string{"not_found"}
			if len(result.Statuses) != len(expectedStatuses) {
				t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(result.Statuses), result.Statuses)
				return
			}

			for i, expected := range expectedStatuses {
				if result.Statuses[i] != expected {
					t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, result.Statuses[i])
				}
			}
		})
	}
}
