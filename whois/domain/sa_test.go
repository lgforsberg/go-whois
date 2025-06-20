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

			if result.DomainName != tc.expected.DomainName {
				t.Errorf("Expected domain name '%s', got '%s'", tc.expected.DomainName, result.DomainName)
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
					if len(expected.Street) != len(actual.Street) {
						t.Errorf("Expected %d registrant street lines, got %d", len(expected.Street), len(actual.Street))
					} else {
						for i, street := range expected.Street {
							if actual.Street[i] != street {
								t.Errorf("Expected registrant street '%s', got '%s'", street, actual.Street[i])
							}
						}
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
					if expected.Name != actual.Name {
						t.Errorf("Expected admin name '%s', got '%s'", expected.Name, actual.Name)
					}
					if len(expected.Street) != len(actual.Street) {
						t.Errorf("Expected %d admin street lines, got %d", len(expected.Street), len(actual.Street))
					} else {
						for i, street := range expected.Street {
							if actual.Street[i] != street {
								t.Errorf("Expected admin street '%s', got '%s'", street, actual.Street[i])
							}
						}
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
					if expected.Name != actual.Name {
						t.Errorf("Expected tech name '%s', got '%s'", expected.Name, actual.Name)
					}
					if len(expected.Street) != len(actual.Street) {
						t.Errorf("Expected %d tech street lines, got %d", len(expected.Street), len(actual.Street))
					} else {
						for i, street := range expected.Street {
							if actual.Street[i] != street {
								t.Errorf("Expected tech street '%s', got '%s'", street, actual.Street[i])
							}
						}
					}
				}
			}
		})
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
