package domain

import (
	"os"
	"testing"
)

func TestEDUTLDParser_UCLA(t *testing.T) {
	// Test case 1: UCLA.EDU - classic .edu domain
	exp := &ParsedWhois{
		DomainName:     "UCLA.EDU",
		CreatedDateRaw: "24-Apr-1985",
		CreatedDate:    "1985-04-24T00:00:00+00:00",
		UpdatedDateRaw: "15-Jan-2025",
		UpdatedDate:    "2025-01-15T00:00:00+00:00",
		ExpiredDateRaw: "31-Jul-2027",
		ExpiredDate:    "2027-07-31T00:00:00+00:00",
		NameServers: []string{
			"ns3.dns.ucla.edu",
			"ns1.dns.ucla.edu",
			"ns2.dns.ucla.edu",
			"ns4.dns.ucla.edu",
		},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:         "UCLA",
				Organization: "Office of the Secretary of the Regents",
				Street:       []string{"1111 Franklin Street, 12th Floor"},
				City:         "Oakland",
				State:        "CA",
				Postal:       "94607",
				Country:      "USA",
			},
			Admin: &Contact{
				Name:         "Gary Stevens",
				Organization: "UCLA Marketing & Special Events",
				Street:       []string{"10920 Wilshire Boulevard, #1000"},
				City:         "Los Angeles",
				State:        "CA",
				Postal:       "90024",
				Country:      "USA",
				Phone:        "+1.3107949061",
				Email:        "marketing@support.ucla.edu",
			},
			Tech: &Contact{
				Name:         "UCLA Network Operations Center",
				Organization: "UCLA IT Services",
				Street:       []string{"Bldg CSB1 2nd floor", "741 Circle Dr South"},
				City:         "Los Angeles",
				State:        "CA",
				Postal:       "90095-1363",
				Country:      "USA",
				Phone:        "+1.3102065345",
				Email:        "noc@ucla.edu",
			},
		},
	}

	checkParserResult(t, "whois.educause.edu", "testdata/edu/case1.txt", "edu", exp)
}

func TestEDUTLDParser_MIT(t *testing.T) {
	// Test case 2: MIT.EDU
	exp := &ParsedWhois{
		DomainName:     "MIT.EDU",
		CreatedDateRaw: "23-May-1985",
		CreatedDate:    "1985-05-23T00:00:00+00:00",
		UpdatedDateRaw: "10-Dec-2024",
		UpdatedDate:    "2024-12-10T00:00:00+00:00",
		ExpiredDateRaw: "31-Jul-2027",
		ExpiredDate:    "2027-07-31T00:00:00+00:00",
		NameServers: []string{
			"bitsy.mit.edu",
			"strawb.mit.edu",
			"w20ns.mit.edu",
		},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:         "Massachusetts Institute of Technology",
				Organization: "77 Massachusetts Avenue",
				City:         "Cambridge",
				State:        "MA",
				Postal:       "02139",
				Country:      "USA",
			},
			Admin: &Contact{
				Name:         "MIT Domain Registration",
				Organization: "MIT Information Systems and Technology",
				Street:       []string{"77 Massachusetts Avenue, Building N42"},
				City:         "Cambridge",
				State:        "MA",
				Postal:       "02139",
				Country:      "USA",
				Phone:        "+1.6172535400",
				Email:        "domreg@mit.edu",
			},
			Tech: &Contact{
				Name:         "MIT Network Operations",
				Organization: "MIT Information Systems and Technology",
				Street:       []string{"77 Massachusetts Avenue, Building N42"},
				City:         "Cambridge",
				State:        "MA",
				Postal:       "02139",
				Country:      "USA",
				Phone:        "+1.6172535400",
				Email:        "noc@mit.edu",
			},
		},
	}

	checkParserResult(t, "whois.educause.edu", "testdata/edu/case2.txt", "edu", exp)
}

func TestEDUTLDParser_Stanford(t *testing.T) {
	// Test case 3: STANFORD.EDU
	exp := &ParsedWhois{
		DomainName:     "STANFORD.EDU",
		CreatedDateRaw: "04-Oct-1985",
		CreatedDate:    "1985-10-04T00:00:00+00:00",
		UpdatedDateRaw: "05-Nov-2024",
		UpdatedDate:    "2024-11-05T00:00:00+00:00",
		ExpiredDateRaw: "31-Jul-2027",
		ExpiredDate:    "2027-07-31T00:00:00+00:00",
		NameServers: []string{
			"argus.stanford.edu",
			"avallone.stanford.edu",
		},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:         "Stanford University",
				Organization: "450 Jane Stanford Way",
				City:         "Stanford",
				State:        "CA",
				Postal:       "94305",
				Country:      "USA",
			},
			Admin: &Contact{
				Name:         "Domain Administrator",
				Organization: "University IT",
				Street:       []string{"Pine Hall, Floor 3"},
				City:         "Stanford",
				State:        "CA",
				Postal:       "94305",
				Country:      "USA",
				Phone:        "+1.6507232300",
				Email:        "domain-admin@stanford.edu",
			},
			Tech: &Contact{
				Name:         "Network Operations",
				Organization: "University IT",
				Street:       []string{"Pine Hall, Floor 2"},
				City:         "Stanford",
				State:        "CA",
				Postal:       "94305",
				Country:      "USA",
				Phone:        "+1.6507232300",
				Email:        "noc@stanford.edu",
			},
		},
	}

	checkParserResult(t, "whois.educause.edu", "testdata/edu/case3.txt", "edu", exp)
}

func TestEDUTLDParser_NotFound(t *testing.T) {
	// Test case: Domain not found
	rawtext, err := os.ReadFile("testdata/edu/case_notfound.txt")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	parser := NewEDUTLDParser()
	result, err := parser.GetParsedWhois(string(rawtext))
	if err != nil {
		t.Fatalf("Parser returned error: %v", err)
	}

	// Domain should be marked as available via "not_found" status
	if len(result.Statuses) != 1 || result.Statuses[0] != "not_found" {
		t.Errorf("Expected status 'not_found', got %v", result.Statuses)
	}
}

func TestEDUTLDParser_GetName(t *testing.T) {
	parser := NewEDUTLDParser()
	if parser.GetName() != "edu" {
		t.Errorf("Expected parser name 'edu', got '%s'", parser.GetName())
	}
}

func TestEDUTLDParser_DateParsing(t *testing.T) {
	// Test various date formats
	testCases := []struct {
		input       string
		expectedRaw string
		expectedFmt string
	}{
		{"Domain record activated:    24-Apr-1985", "24-Apr-1985", "1985-04-24T00:00:00+00:00"},
		{"Domain record last updated: 15-Jan-2025", "15-Jan-2025", "2025-01-15T00:00:00+00:00"},
		{"Domain expires:             31-Jul-2027", "31-Jul-2027", "2027-07-31T00:00:00+00:00"},
		{"Domain record activated:    01-Dec-2000", "01-Dec-2000", "2000-12-01T00:00:00+00:00"},
	}

	parser := NewEDUTLDParser()

	for _, tc := range testCases {
		parsedWhois := &ParsedWhois{}
		if parser.parseDateLine(tc.input, parsedWhois) {
			// Check which field was populated
			var rawDate, fmtDate string
			if parsedWhois.CreatedDateRaw != "" {
				rawDate = parsedWhois.CreatedDateRaw
				fmtDate = parsedWhois.CreatedDate
			} else if parsedWhois.UpdatedDateRaw != "" {
				rawDate = parsedWhois.UpdatedDateRaw
				fmtDate = parsedWhois.UpdatedDate
			} else if parsedWhois.ExpiredDateRaw != "" {
				rawDate = parsedWhois.ExpiredDateRaw
				fmtDate = parsedWhois.ExpiredDate
			}

			if rawDate != tc.expectedRaw {
				t.Errorf("For input '%s': expected raw date '%s', got '%s'", tc.input, tc.expectedRaw, rawDate)
			}
			if fmtDate != tc.expectedFmt {
				t.Errorf("For input '%s': expected formatted date '%s', got '%s'", tc.input, tc.expectedFmt, fmtDate)
			}
		} else {
			t.Errorf("Failed to parse date line: %s", tc.input)
		}
	}
}

func TestEDUTLDParser_ContactParsing(t *testing.T) {
	// Test contact block parsing with various formats
	parser := NewEDUTLDParser()

	rawtext := `Domain Name: TEST.EDU

Registrant:
	Test Organization
	123 Main Street
	Suite 100
	New York, NY 10001
	USA

Name Servers:
	NS1.TEST.EDU

Domain record activated:    01-Jan-2000
Domain record last updated: 01-Jan-2024
Domain expires:             31-Dec-2025
`

	result, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Parser returned error: %v", err)
	}

	if result.DomainName != "TEST.EDU" {
		t.Errorf("Expected domain 'TEST.EDU', got '%s'", result.DomainName)
	}

	if result.Contacts == nil || result.Contacts.Registrant == nil {
		t.Fatal("Expected registrant contact to be parsed")
	}

	reg := result.Contacts.Registrant
	if reg.Name != "Test Organization" {
		t.Errorf("Expected registrant name 'Test Organization', got '%s'", reg.Name)
	}
	if reg.City != "New York" {
		t.Errorf("Expected city 'New York', got '%s'", reg.City)
	}
	if reg.State != "NY" {
		t.Errorf("Expected state 'NY', got '%s'", reg.State)
	}
	if reg.Postal != "10001" {
		t.Errorf("Expected postal '10001', got '%s'", reg.Postal)
	}
	if reg.Country != "USA" {
		t.Errorf("Expected country 'USA', got '%s'", reg.Country)
	}
}

func TestEDUTLDParser_NameServerParsing(t *testing.T) {
	parser := NewEDUTLDParser()

	rawtext := `Domain Name: TEST.EDU

Name Servers:
	NS1.TEST.EDU
	NS2.TEST.EDU
	NS3.TEST.EDU

Domain record activated:    01-Jan-2000
Domain record last updated: 01-Jan-2024
Domain expires:             31-Dec-2025
`

	result, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Fatalf("Parser returned error: %v", err)
	}

	expectedNS := []string{"ns1.test.edu", "ns2.test.edu", "ns3.test.edu"}
	if len(result.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d name servers, got %d", len(expectedNS), len(result.NameServers))
	}

	for i, ns := range expectedNS {
		if i < len(result.NameServers) && result.NameServers[i] != ns {
			t.Errorf("Expected name server '%s' at position %d, got '%s'", ns, i, result.NameServers[i])
		}
	}
}

