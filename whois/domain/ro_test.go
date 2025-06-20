package domain

import (
	"os"
	"testing"
)

func TestROTLDParser_Parse(t *testing.T) {
	parser := NewROTLDParser()
	if parser.GetName() != "ro" {
		t.Errorf("Expected parser name to be 'ro', got '%s'", parser.GetName())
	}

	testCases := []struct {
		file     string
		expected *ParsedWhois
	}{
		{
			file: "testdata/ro/case1.txt",
			expected: &ParsedWhois{
				DomainName:     "google.ro",
				CreatedDateRaw: "2000-07-17",
				ExpiredDateRaw: "2025-09-15",
				Registrar: &Registrar{
					Name: "MarkMonitor Inc.",
					URL:  "www.markmonitor.com",
				},
				Dnssec:      "Inactive",
				NameServers: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
				Statuses:    []string{"UpdateProhibited"},
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
			if result.ExpiredDateRaw != tc.expected.ExpiredDateRaw {
				t.Errorf("Expected expired date '%s', got '%s'", tc.expected.ExpiredDateRaw, result.ExpiredDateRaw)
			}
			if tc.expected.Registrar != nil {
				if result.Registrar == nil {
					t.Error("Expected registrar, got nil")
				} else {
					if tc.expected.Registrar.Name != result.Registrar.Name {
						t.Errorf("Expected registrar name '%s', got '%s'", tc.expected.Registrar.Name, result.Registrar.Name)
					}
					if tc.expected.Registrar.URL != result.Registrar.URL {
						t.Errorf("Expected registrar URL '%s', got '%s'", tc.expected.Registrar.URL, result.Registrar.URL)
					}
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
			if len(result.Statuses) != len(tc.expected.Statuses) {
				t.Errorf("Expected %d statuses, got %d", len(tc.expected.Statuses), len(result.Statuses))
			} else {
				for i, status := range tc.expected.Statuses {
					if result.Statuses[i] != status {
						t.Errorf("Expected status '%s', got '%s'", status, result.Statuses[i])
					}
				}
			}
		})
	}
}

func TestROTLDParser_ParseUnregistered(t *testing.T) {
	parser := NewROTLDParser()

	testCases := []struct {
		file string
	}{
		{"testdata/ro/case10.txt"},
		{"testdata/ro/case11.txt"},
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
