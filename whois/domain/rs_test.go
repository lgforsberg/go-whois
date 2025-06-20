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

			assertBasicFields(t, result, tc.expected)
			assertContacts(t, result, tc.expected)
		})
	}
}

func assertBasicFields(t *testing.T, result, expected *ParsedWhois) {
	if result.DomainName != expected.DomainName {
		t.Errorf("Expected domain name '%s', got '%s'", expected.DomainName, result.DomainName)
	}
	if result.CreatedDateRaw != expected.CreatedDateRaw {
		t.Errorf("Expected created date '%s', got '%s'", expected.CreatedDateRaw, result.CreatedDateRaw)
	}
	if result.UpdatedDateRaw != expected.UpdatedDateRaw {
		t.Errorf("Expected updated date '%s', got '%s'", expected.UpdatedDateRaw, result.UpdatedDateRaw)
	}
	if result.ExpiredDateRaw != expected.ExpiredDateRaw {
		t.Errorf("Expected expired date '%s', got '%s'", expected.ExpiredDateRaw, result.ExpiredDateRaw)
	}
	assertStatuses(t, result, expected)
	assertRegistrar(t, result, expected)
	if result.Dnssec != expected.Dnssec {
		t.Errorf("Expected DNSSEC '%s', got '%s'", expected.Dnssec, result.Dnssec)
	}
	assertNameServers(t, result, expected)
}

func assertStatuses(t *testing.T, result, expected *ParsedWhois) {
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

func assertRegistrar(t *testing.T, result, expected *ParsedWhois) {
	if expected.Registrar != nil {
		if result.Registrar == nil {
			t.Error("Expected registrar, got nil")
		} else if expected.Registrar.Name != result.Registrar.Name {
			t.Errorf("Expected registrar name '%s', got '%s'", expected.Registrar.Name, result.Registrar.Name)
		}
	}
}

func assertNameServers(t *testing.T, result, expected *ParsedWhois) {
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

func assertContacts(t *testing.T, result, expected *ParsedWhois) {
	if expected.Contacts == nil {
		return
	}
	assertContact(t, "registrant", result.Contacts.Registrant, expected.Contacts.Registrant)
	assertContact(t, "admin", result.Contacts.Admin, expected.Contacts.Admin)
	assertContact(t, "tech", result.Contacts.Tech, expected.Contacts.Tech)
}

func assertContact(t *testing.T, contactType string, actual, expected *Contact) {
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
	if expected.ID != actual.ID {
		t.Errorf("Expected %s ID '%s', got '%s'", contactType, expected.ID, actual.ID)
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
