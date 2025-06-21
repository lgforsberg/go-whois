package utils

import (
	"testing"
	"time"
)

func TestExtractValue(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "normal colon separated",
			line:     "Domain Name: example.com",
			expected: "example.com",
		},
		{
			name:     "with spaces",
			line:     "Created Date:  2023-01-01T00:00:00+00:00",
			expected: "2023-01-01T00:00:00+00:00",
		},
		{
			name:     "no colon",
			line:     "just some text",
			expected: "",
		},
		{
			name:     "colon at end",
			line:     "Empty field:",
			expected: "",
		},
		{
			name:     "empty line",
			line:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractValue(tt.line)
			if result != tt.expected {
				t.Errorf("ExtractValue() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractField(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefix   string
		expected string
	}{
		{
			name:     "normal prefix",
			line:     "Domain Name: example.com",
			prefix:   "Domain Name:",
			expected: "example.com",
		},
		{
			name:     "with extra spaces",
			line:     "  Created Date:  2023-01-01",
			prefix:   "Created Date:",
			expected: "2023-01-01",
		},
		{
			name:     "prefix not found",
			line:     "Some other field: value",
			prefix:   "Domain Name:",
			expected: "Some other field: value",
		},
		{
			name:     "empty line",
			line:     "",
			prefix:   "Domain:",
			expected: "",
		},
		{
			name:     "empty prefix",
			line:     "Domain: example.com",
			prefix:   "",
			expected: "Domain: example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractField(tt.line, tt.prefix)
			if result != tt.expected {
				t.Errorf("ExtractField() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSkipLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "empty line",
			line:     "",
			expected: true,
		},
		{
			name:     "comment line",
			line:     "% This is a comment",
			expected: true,
		},
		{
			name:     "normal line",
			line:     "Domain Name: example.com",
			expected: false,
		},
		{
			name:     "line with percent in middle",
			line:     "Some field: 50% complete",
			expected: false,
		},
		{
			name:     "whitespace only",
			line:     "   ",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SkipLine(tt.line)
			if result != tt.expected {
				t.Errorf("SkipLine() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestInitContact(t *testing.T) {
	contact := InitContact()

	expectedFields := []string{
		"id", "name", "organization", "email", "phone", "fax",
		"country", "city", "state", "postal",
	}

	for _, field := range expectedFields {
		if _, exists := contact[field]; !exists {
			t.Errorf("InitContact() missing field: %s", field)
		}
		if contact[field] != "" {
			t.Errorf("InitContact() field %s should be empty, got: %s", field, contact[field])
		}
	}

	// Check that we don't have unexpected fields
	if len(contact) != len(expectedFields) {
		t.Errorf("InitContact() has %d fields, expected %d", len(contact), len(expectedFields))
	}
}

func TestInitRegistrar(t *testing.T) {
	registrar := InitRegistrar()

	expectedFields := []string{
		"iana_id", "name", "abuse_contact_email", "abuse_contact_phone",
		"whois_server", "url",
	}

	for _, field := range expectedFields {
		if _, exists := registrar[field]; !exists {
			t.Errorf("InitRegistrar() missing field: %s", field)
		}
		if registrar[field] != "" {
			t.Errorf("InitRegistrar() field %s should be empty, got: %s", field, registrar[field])
		}
	}

	// Check that we don't have unexpected fields
	if len(registrar) != len(expectedFields) {
		t.Errorf("InitRegistrar() has %d fields, expected %d", len(registrar), len(expectedFields))
	}
}

func TestParseDateField(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefix   string
		expected *time.Time
	}{
		{
			name:   "standard format",
			line:   "Created Date: 2023-01-01T00:00:00+00:00",
			prefix: "Created Date:",
			expected: func() *time.Time {
				t, _ := time.Parse(WhoisTimeFmt, "2023-01-01T00:00:00+00:00")
				return &t
			}(),
		},
		{
			name:   "date only format",
			line:   "Created: 2023-01-01",
			prefix: "Created:",
			expected: func() *time.Time {
				t, _ := time.Parse("2006-01-02", "2023-01-01")
				return &t
			}(),
		},
		{
			name:     "invalid date",
			line:     "Created: invalid-date",
			prefix:   "Created:",
			expected: nil,
		},
		{
			name:     "empty value",
			line:     "Created:",
			prefix:   "Created:",
			expected: nil,
		},
		{
			name:     "prefix not found",
			line:     "Some other field: 2023-01-01",
			prefix:   "Created:",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseDateField(tt.line, tt.prefix)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("ParseDateField() = %v, want nil", result)
				}
			} else {
				if result == nil {
					t.Errorf("ParseDateField() = nil, want %v", tt.expected)
				} else if !result.Equal(*tt.expected) {
					t.Errorf("ParseDateField() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestParseNameServers(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected []string
	}{
		{
			name: "normal nameserver lines",
			lines: []string{
				"nserver: ns1.example.com",
				"nserver: ns2.example.com",
				"Domain Name: example.com",
			},
			expected: []string{"ns1.example.com", "ns2.example.com"},
		},
		{
			name: "mixed case prefixes",
			lines: []string{
				"Nserver: ns1.example.com",
				"nameserver: ns2.example.com",
				"Name Server: ns3.example.com",
			},
			expected: []string{"ns1.example.com", "ns2.example.com", "ns3.example.com"},
		},
		{
			name: "with comments and empty lines",
			lines: []string{
				"% Comment line",
				"",
				"nserver: ns1.example.com",
				"nserver: ns2.example.com",
			},
			expected: []string{"ns1.example.com", "ns2.example.com"},
		},
		{
			name:     "no nameserver lines",
			lines:    []string{"Domain Name: example.com", "Status: active"},
			expected: []string{},
		},
		{
			name:     "empty lines",
			lines:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseNameServers(tt.lines)
			if len(result) != len(tt.expected) {
				t.Errorf("ParseNameServers() returned %d nameservers, want %d", len(result), len(tt.expected))
				return
			}
			for i, ns := range result {
				if ns != tt.expected[i] {
					t.Errorf("ParseNameServers()[%d] = %q, want %q", i, ns, tt.expected[i])
				}
			}
		})
	}
}

func TestIsNameserverLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefix   string
		expected bool
	}{
		{
			name:     "normal nameserver line",
			line:     "nserver: ns1.example.com",
			prefix:   "nserver:",
			expected: true,
		},
		{
			name:     "uppercase prefix",
			line:     "Nserver: ns1.example.com",
			prefix:   "Nserver:",
			expected: true,
		},
		{
			name:     "with spaces",
			line:     "  nserver:  ns1.example.com",
			prefix:   "nserver:",
			expected: true,
		},
		{
			name:     "prefix not found",
			line:     "Domain Name: example.com",
			prefix:   "nserver:",
			expected: false,
		},
		{
			name:     "prefix in middle",
			line:     "Some field: nserver: value",
			prefix:   "nserver:",
			expected: false,
		},
		{
			name:     "empty line",
			line:     "",
			prefix:   "nserver:",
			expected: false,
		},
		{
			name:     "empty prefix",
			line:     "nserver: ns1.example.com",
			prefix:   "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNameserverLine(tt.line, tt.prefix)
			if result != tt.expected {
				t.Errorf("IsNameserverLine() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsRegistrarLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefix   string
		expected bool
	}{
		{
			name:     "normal registrar line",
			line:     "Registrar: Example Registrar",
			prefix:   "Registrar:",
			expected: true,
		},
		{
			name:     "with spaces",
			line:     "  Registrar:  Example Registrar",
			prefix:   "Registrar:",
			expected: true,
		},
		{
			name:     "prefix not found",
			line:     "Domain Name: example.com",
			prefix:   "Registrar:",
			expected: false,
		},
		{
			name:     "prefix in middle",
			line:     "Some field: Registrar: value",
			prefix:   "Registrar:",
			expected: false,
		},
		{
			name:     "empty line",
			line:     "",
			prefix:   "Registrar:",
			expected: false,
		},
		{
			name:     "empty prefix",
			line:     "Registrar: Example Registrar",
			prefix:   "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRegistrarLine(tt.line, tt.prefix)
			if result != tt.expected {
				t.Errorf("IsRegistrarLine() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsContactSection(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "registrant section",
			line:     "Registrant:",
			expected: true,
		},
		{
			name:     "administrative contact section",
			line:     "Administrative Contact:",
			expected: true,
		},
		{
			name:     "technical contact section",
			line:     "Technical Contact:",
			expected: true,
		},
		{
			name:     "admin contact section",
			line:     "Admin Contact:",
			expected: true,
		},
		{
			name:     "tech contact section",
			line:     "Tech Contact:",
			expected: true,
		},
		{
			name:     "billing contact section",
			line:     "Billing Contact:",
			expected: true,
		},
		{
			name:     "with spaces",
			line:     "  Registrant:  ",
			expected: true,
		},
		{
			name:     "mixed case",
			line:     "REGISTRANT:",
			expected: true,
		},
		{
			name:     "not a contact section",
			line:     "Domain Name: example.com",
			expected: false,
		},
		{
			name:     "contact in middle",
			line:     "Some field: Registrant: value",
			expected: false,
		},
		{
			name:     "empty line",
			line:     "",
			expected: false,
		},
		{
			name:     "partial match",
			line:     "Registrant Info:",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsContactSection(tt.line)
			if result != tt.expected {
				t.Errorf("IsContactSection() = %v, want %v", result, tt.expected)
			}
		})
	}
}
