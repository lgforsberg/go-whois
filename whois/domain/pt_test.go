package domain

import (
	"fmt"
	"testing"

	"github.com/lgforsberg/go-whois/whois/domain/testdata"
)

func sortParsedWhois(exp *ParsedWhois) {
	if exp == nil {
		return
	}
	// Do not sort NameServers or Statuses; keep the order as in the test data
}

func TestPTParserCase1(t *testing.T) {
	exp := &ParsedWhois{
		DomainName:     "dns.pt",
		CreatedDateRaw: "03/10/1991 00:00:00",
		CreatedDate:    "1991-10-03T00:00:00+00:00",
		ExpiredDateRaw: "31/12/2025 23:59:00",
		ExpiredDate:    "2025-12-31T23:59:00+00:00",
		Statuses:       []string{"Registered"},
		NameServers:    []string{"b.dns.pt", "c.dns.pt", "dns01.dns.pt", "dns02.dns.pt", "europe1.dnsnode.net", "nsp.dnsnode.net"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
			Admin: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
		},
	}
	sortParsedWhois(exp)
	checkParserResult(t, "whois.dns.pt", "pt/case1.txt", "pt", exp)
}

func TestPTParserCase2(t *testing.T) {
	exp := &ParsedWhois{
		DomainName:     "google.pt",
		CreatedDateRaw: "09/01/2003 00:00:00",
		CreatedDate:    "2003-01-09T00:00:00+00:00",
		ExpiredDateRaw: "28/02/2026 23:59:00",
		ExpiredDate:    "2026-02-28T23:59:00+00:00",
		Statuses:       []string{"Registered"},
		NameServers:    []string{"ns3.google.com", "ns4.google.com", "ns1.google.com", "ns2.google.com"},
		Contacts: &Contacts{
			Admin: &Contact{
				Name:    "MarkMonitor Inc.",
				Street:  []string{"1120 S. Rackham Way Suite 300"},
				City:    "Meridian",
				Postal:  "83642",
				Country: "US",
				Email:   "ccops@markmonitor.com",
			},
		},
	}
	parsed := getParsedWhoisForTest(t, "whois.dns.pt", "pt/case2.txt")
	fmt.Println("EXPECTED:", exp.NameServers)
	fmt.Println("ACTUAL:", parsed.NameServers)
	sortParsedWhois(exp)
	checkParserResult(t, "whois.dns.pt", "pt/case2.txt", "pt", exp)
}

func TestPTParserCase3(t *testing.T) {
	exp := &ParsedWhois{
		DomainName:     "edu.pt",
		CreatedDateRaw: "20/01/2000 00:00:00",
		CreatedDate:    "2000-01-20T00:00:00+00:00",
		ExpiredDateRaw: "19/04/2026 23:59:00",
		ExpiredDate:    "2026-04-19T23:59:00+00:00",
		Statuses:       []string{"Reserved"},
		NameServers:    []string{},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
			Admin: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
		},
	}
	sortParsedWhois(exp)
	checkParserResult(t, "whois.dns.pt", "pt/case3.txt", "pt", exp)
}

func TestPTParserCase4(t *testing.T) {
	exp := &ParsedWhois{
		DomainName:     "org.pt",
		CreatedDateRaw: "06/10/1999 00:00:00",
		CreatedDate:    "1999-10-06T00:00:00+00:00",
		ExpiredDateRaw: "06/10/2025 23:59:00",
		ExpiredDate:    "2025-10-06T23:59:00+00:00",
		Statuses:       []string{"Reserved"},
		NameServers:    []string{},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
			Admin: &Contact{
				Name:    "Associação DNS.PT",
				Street:  []string{"Rua Eça de Queirós  29"},
				City:    "Lisboa",
				Postal:  "1050-095",
				Country: "PT",
				Email:   "secretariado@pt.pt,request@pt.pt",
			},
		},
	}
	sortParsedWhois(exp)
	checkParserResult(t, "whois.dns.pt", "pt/case4.txt", "pt", exp)
}

// getParsedWhoisForTest is a helper to get the actual parsed result for debugging
func getParsedWhoisForTest(t *testing.T, whoisServer, rawtextPath string) *ParsedWhois {
	parser := NewTLDDomainParser(whoisServer)
	b, err := testdata.ReadRawtext(rawtextPath)
	if err != nil {
		t.Fatalf("failed to read rawtext: %v", err)
	}
	parsedWhois, err := parser.GetParsedWhois(string(b))
	if err != nil {
		t.Fatalf("failed to parse whois: %v", err)
	}
	return parsedWhois
}
