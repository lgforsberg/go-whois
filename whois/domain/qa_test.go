package domain

import (
	"os"
	"testing"
)

func TestQATLDParser_Parse(t *testing.T) {
	parser := NewQATLDParser()
	if parser.GetName() != "qa" {
		t.Errorf("Expected parser name to be 'qa', got '%s'", parser.GetName())
	}

	testCases := []struct {
		file     string
		expected *ParsedWhois
	}{
		{
			file: "testdata/qa/case1.txt",
			expected: &ParsedWhois{
				DomainName:     "google.qa",
				UpdatedDateRaw: "18-Nov-2024 06:57:28 UTC",
				Statuses:       []string{"clientDeleteProhibited", "clientUpdateProhibited"},
				NameServers:    []string{"ns1.google.com", "ns3.google.com", "ns2.google.com", "ns4.google.com"},
				Registrar: &Registrar{
					Name: "ROUTEDGE",
				},
			},
		},
		{
			file: "testdata/qa/case2.txt",
			expected: &ParsedWhois{
				DomainName:     "facebook.qa",
				UpdatedDateRaw: "11-Jun-2025 06:54:28 UTC",
				Statuses:       []string{"ok"},
				NameServers:    []string{"b.ns.facebook.com", "a.ns.facebook.com"},
				Registrar: &Registrar{
					Name: "AGIP dba Tag-Domains.com",
				},
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
			if result.UpdatedDateRaw != tc.expected.UpdatedDateRaw {
				t.Errorf("Expected updated date '%s', got '%s'", tc.expected.UpdatedDateRaw, result.UpdatedDateRaw)
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
			if len(result.NameServers) != len(tc.expected.NameServers) {
				t.Errorf("Expected %d nameservers, got %d", len(tc.expected.NameServers), len(result.NameServers))
			} else {
				for i, ns := range tc.expected.NameServers {
					if result.NameServers[i] != ns {
						t.Errorf("Expected nameserver '%s', got '%s'", ns, result.NameServers[i])
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
		})
	}
}

func TestQATLDParser_ParseUnregistered(t *testing.T) {
	parser := NewQATLDParser()

	testCases := []struct {
		file string
	}{
		{"testdata/qa/case3.txt"},
		{"testdata/qa/case4.txt"},
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
