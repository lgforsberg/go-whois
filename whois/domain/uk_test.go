package domain

import (
	"testing"
)

func TestUKParser(t *testing.T) {
	// whois.nic.uk
	exp := &ParsedWhois{
		DomainName: "abc.co.uk",
		Registrar: &Registrar{
			Name: "Moose Internet Services Ltd t/a Moose Internet Services [Tag = MOOSE]",
			URL:  "http://www.moose.co.uk",
		},
		NameServers: []string{
			"ns1.moose.co.uk 85.91.32.11", "ns2.moose.co.uk 85.91.37.37", "ns3.moose.co.uk 185.14.88.117", "ns4.moose.co.uk 185.14.88.117",
		},
		CreatedDateRaw: "before Aug-1996",
		CreatedDate:    "", // invalid format...
		UpdatedDateRaw: "05-Nov-2019",
		UpdatedDate:    "2019-11-05T00:00:00+00:00",
		ExpiredDateRaw: "02-Dec-2021",
		ExpiredDate:    "2021-12-02T00:00:00+00:00",
	}

	checkParserResult(t, "whois.nic.uk", "testdata/uk/case1.txt", "uk", exp)
}

func TestUKParserJaNet(t *testing.T) {
	// whois.ja.net
	exp := &ParsedWhois{
		DomainName: "sunderland.ac.uk",
		Registrar: &Registrar{
			Name: "University of Sunderland",
		},
		NameServers: []string{
			"ns10.ja.net", "ns11.ja.net", "ns12.ja.net",
		},
		CreatedDateRaw: "Monday 10th November 2003",
		CreatedDate:    "2003-11-10T00:00:00+00:00",
		UpdatedDateRaw: "Wednesday 13th October 2021",
		UpdatedDate:    "2021-10-13T00:00:00+00:00",
		ExpiredDateRaw: "Tuesday 1st Feb 2022",
		ExpiredDate:    "2022-02-01T00:00:00+00:00",
	}

	checkParserResult(t, "whois.ja.net", "testdata/uk/case2.txt", "uk", exp)
}

func TestUKParserNotFound(t *testing.T) {
	// Test data from whois/domain/testdata/uk/case3.txt
	rawtext := `# whois.nic.uk


    No match for "dsfsdfasdfasdfasdfasdf.co.uk".

    This domain name has not been registered.

    WHOIS lookup made at 20:24:53 24-Jun-2025`

	parser := NewUKTLDParser()
	result, err := parser.GetParsedWhois(rawtext)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should have dual status for backward compatibility
	expected := []string{"not_found"}
	if len(result.Statuses) != len(expected) {
		t.Fatalf("Expected %d statuses, got %d: %v", len(expected), len(result.Statuses), result.Statuses)
	}

	for i, exp := range expected {
		if result.Statuses[i] != exp {
			t.Errorf("Expected status %d to be %s, got %s", i, exp, result.Statuses[i])
		}
	}
}
