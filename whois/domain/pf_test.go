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

			if result.DomainName != tc.expected.DomainName {
				t.Errorf("Expected domain name '%s', got '%s'", tc.expected.DomainName, result.DomainName)
			}

			if len(result.Statuses) != len(tc.expected.Statuses) {
				t.Errorf("Expected %d statuses, got %d", len(tc.expected.Statuses), len(result.Statuses))
			} else {
				for i, status := range tc.expected.Statuses {
					if result.Statuses[i] != status {
						t.Errorf("Expected status '%s', got '%s'", status, result.Statuses[i])
					}
				}
			}

			if result.CreatedDateRaw != tc.expected.CreatedDateRaw {
				t.Errorf("Expected created date '%s', got '%s'", tc.expected.CreatedDateRaw, result.CreatedDateRaw)
			}

			if result.UpdatedDateRaw != tc.expected.UpdatedDateRaw {
				t.Errorf("Expected updated date '%s', got '%s'", tc.expected.UpdatedDateRaw, result.UpdatedDateRaw)
			}

			if result.ExpiredDateRaw != tc.expected.ExpiredDateRaw {
				t.Errorf("Expected expired date '%s', got '%s'", tc.expected.ExpiredDateRaw, result.ExpiredDateRaw)
			}

			if len(result.NameServers) != len(tc.expected.NameServers) {
				t.Errorf("Expected %d nameservers, got %d", len(tc.expected.NameServers), len(result.NameServers))
			} else {
				for i, ns := range tc.expected.NameServers {
					if result.NameServers[i] != ns {
						t.Errorf("Expected nameserver '%s', got '%s'", ns, result.NameServers[i])
					}
				}
			}

			// Test registrant contact
			if tc.expected.Contacts != nil && tc.expected.Contacts.Registrant != nil {
				if result.Contacts == nil || result.Contacts.Registrant == nil {
					t.Error("Expected registrant contact, got nil")
				} else {
					expected := tc.expected.Contacts.Registrant
					actual := result.Contacts.Registrant
					if expected.Organization != actual.Organization {
						t.Errorf("Expected registrant organization '%s', got '%s'", expected.Organization, actual.Organization)
					}
					if expected.Name != actual.Name {
						t.Errorf("Expected registrant name '%s', got '%s'", expected.Name, actual.Name)
					}
					if expected.Email != actual.Email {
						t.Errorf("Expected registrant email '%s', got '%s'", expected.Email, actual.Email)
					}
				}
			}

			// Test tech contact
			if tc.expected.Contacts != nil && tc.expected.Contacts.Tech != nil {
				if result.Contacts == nil || result.Contacts.Tech == nil {
					t.Error("Expected tech contact, got nil")
				} else {
					expected := tc.expected.Contacts.Tech
					actual := result.Contacts.Tech
					if expected.Organization != actual.Organization {
						t.Errorf("Expected tech organization '%s', got '%s'", expected.Organization, actual.Organization)
					}
					if expected.Name != actual.Name {
						t.Errorf("Expected tech name '%s', got '%s'", expected.Name, actual.Name)
					}
					if expected.Email != actual.Email {
						t.Errorf("Expected tech email '%s', got '%s'", expected.Email, actual.Email)
					}
				}
			}

			// Test registrar
			if tc.expected.Registrar != nil {
				if result.Registrar == nil {
					t.Error("Expected registrar, got nil")
				} else if tc.expected.Registrar.Name != result.Registrar.Name {
					t.Errorf("Expected registrar name '%s', got '%s'", tc.expected.Registrar.Name, result.Registrar.Name)
				}
			}
		})
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

			if len(result.Statuses) != 1 || result.Statuses[0] != "free" {
				t.Errorf("Expected status 'free', got %v", result.Statuses)
			}
		})
	}
}
