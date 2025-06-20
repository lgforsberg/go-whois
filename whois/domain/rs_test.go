package domain

import (
	"os"
	"testing"
)

func TestRSTLDParser_Parse(t *testing.T) {
	parser := NewRSTLDParser()
	if parser.GetName() != "rs" {
		t.Errorf("Expected parser name to be 'rs', got '%s'", parser.GetName())
	}

	testCases := []struct {
		file     string
		expected *ParsedWhois
	}{
		{
			file: "testdata/rs/case1.txt",
			expected: &ParsedWhois{
				DomainName:     "google.rs",
				CreatedDateRaw: "10.03.2008 12:31:19",
				UpdatedDateRaw: "07.02.2025 18:17:36",
				ExpiredDateRaw: "10.03.2026 12:31:19",
				Statuses:       []string{"Active", "clientUpdateProhibited"},
				Registrar: &Registrar{
					Name: "Webglobe d.o.o.",
				},
				Contacts: &Contacts{
					Registrant: &Contact{
						Organization: "Google LLC",
						Street:       []string{"1600 Amphitheatre Parkway, Mountain View, CA 94043, United States of America"},
						Postal:       "",
						ID:           "-",
					},
					Admin: &Contact{
						Organization: "Drustvo za marketing Google DOO",
						Street:       []string{"Marsala Birjuzova 47/18, Beograd, Serbia"},
						Postal:       "",
						ID:           "20365099",
					},
					Tech: &Contact{
						Organization: "MarkMonitor, Inc.",
						Street:       []string{"3540 East Longwing Lane, Suite 300, Meridian, ID 83646, United States of America"},
						Postal:       "",
						ID:           "-",
					},
				},
				NameServers: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
				Dnssec:      "no",
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

			if result.DomainName != tc.expected.DomainName {
				t.Errorf("Expected domain name '%s', got '%s'", tc.expected.DomainName, result.DomainName)
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
			if len(result.Statuses) != len(tc.expected.Statuses) {
				t.Errorf("Expected %d statuses, got %d", len(tc.expected.Statuses), len(result.Statuses))
			} else {
				for i, status := range tc.expected.Statuses {
					if result.Statuses[i] != status {
						t.Errorf("Expected status '%s', got '%s'", status, result.Statuses[i])
					}
				}
			}
			if tc.expected.Registrar != nil {
				if result.Registrar == nil {
					t.Error("Expected registrar, got nil")
				} else if tc.expected.Registrar.Name != result.Registrar.Name {
					t.Errorf("Expected registrar name '%s', got '%s'", tc.expected.Registrar.Name, result.Registrar.Name)
				}
			}
			if result.Dnssec != tc.expected.Dnssec {
				t.Errorf("Expected DNSSEC '%s', got '%s'", tc.expected.Dnssec, result.Dnssec)
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
					if expected.ID != actual.ID {
						t.Errorf("Expected registrant ID '%s', got '%s'", expected.ID, actual.ID)
					}
				}
			}

			// Test admin contact
			if tc.expected.Contacts != nil && tc.expected.Contacts.Admin != nil {
				if result.Contacts == nil || result.Contacts.Admin == nil {
					t.Error("Expected admin contact, got nil")
				} else {
					expected := tc.expected.Contacts.Admin
					actual := result.Contacts.Admin
					if expected.Organization != actual.Organization {
						t.Errorf("Expected admin organization '%s', got '%s'", expected.Organization, actual.Organization)
					}
					if expected.ID != actual.ID {
						t.Errorf("Expected admin ID '%s', got '%s'", expected.ID, actual.ID)
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
					if expected.ID != actual.ID {
						t.Errorf("Expected tech ID '%s', got '%s'", expected.ID, actual.ID)
					}
				}
			}
		})
	}
}

func TestRSTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewRSTLDParser()

	testCases := []struct {
		file string
	}{
		{"testdata/rs/case10.txt"},
		{"testdata/rs/case11.txt"},
		{"testdata/rs/case7.txt"},
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
