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

			assertQAParsedWhois(t, result, tc.expected)
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

			assertQAUnregisteredDomain(t, result)
		})
	}
}

func assertQAParsedWhois(t *testing.T, result, expected *ParsedWhois) {
	if result.DomainName != expected.DomainName {
		t.Errorf("Expected domain name '%s', got '%s'", expected.DomainName, result.DomainName)
	}
	if result.UpdatedDateRaw != expected.UpdatedDateRaw {
		t.Errorf("Expected updated date '%s', got '%s'", expected.UpdatedDateRaw, result.UpdatedDateRaw)
	}
	assertQAStatuses(t, result.Statuses, expected.Statuses)
	assertQANameservers(t, result.NameServers, expected.NameServers)
	assertQARegistrar(t, result.Registrar, expected.Registrar)
}

func assertQAStatuses(t *testing.T, actual, expected []string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d statuses, got %d", len(expected), len(actual))
		return
	}
	for i, status := range expected {
		if actual[i] != status {
			t.Errorf("Expected status '%s', got '%s'", status, actual[i])
		}
	}
}

func assertQANameservers(t *testing.T, actual, expected []string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d nameservers, got %d", len(expected), len(actual))
		return
	}
	for i, ns := range expected {
		if actual[i] != ns {
			t.Errorf("Expected nameserver '%s', got '%s'", ns, actual[i])
		}
	}
}

func assertQARegistrar(t *testing.T, actual, expected *Registrar) {
	if expected != nil {
		if actual == nil {
			t.Error("Expected registrar, got nil")
		} else if expected.Name != actual.Name {
			t.Errorf("Expected registrar name '%s', got '%s'", expected.Name, actual.Name)
		}
	}
}

func assertQAUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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
}
