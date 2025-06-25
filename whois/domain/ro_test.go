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

			assertROParsedWhois(t, result, tc.expected)
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

			assertROUnregisteredDomain(t, result)
		})
	}
}

func assertROParsedWhois(t *testing.T, result, expected *ParsedWhois) {
	if result.DomainName != expected.DomainName {
		t.Errorf("Expected domain name '%s', got '%s'", expected.DomainName, result.DomainName)
	}
	if result.CreatedDateRaw != expected.CreatedDateRaw {
		t.Errorf("Expected created date '%s', got '%s'", expected.CreatedDateRaw, result.CreatedDateRaw)
	}
	if result.ExpiredDateRaw != expected.ExpiredDateRaw {
		t.Errorf("Expected expired date '%s', got '%s'", expected.ExpiredDateRaw, result.ExpiredDateRaw)
	}
	assertRORegistrar(t, result.Registrar, expected.Registrar)
	if result.Dnssec != expected.Dnssec {
		t.Errorf("Expected DNSSEC '%s', got '%s'", expected.Dnssec, result.Dnssec)
	}
	assertRONameservers(t, result.NameServers, expected.NameServers)
	assertROStatuses(t, result.Statuses, expected.Statuses)
}

func assertRORegistrar(t *testing.T, actual, expected *Registrar) {
	if expected != nil {
		if actual == nil {
			t.Error("Expected registrar, got nil")
		} else {
			if expected.Name != actual.Name {
				t.Errorf("Expected registrar name '%s', got '%s'", expected.Name, actual.Name)
			}
			if expected.URL != actual.URL {
				t.Errorf("Expected registrar URL '%s', got '%s'", expected.URL, actual.URL)
			}
		}
	}
}

func assertRONameservers(t *testing.T, actual, expected []string) {
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

func assertROStatuses(t *testing.T, actual, expected []string) {
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

func assertROUnregisteredDomain(t *testing.T, result *ParsedWhois) {
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
