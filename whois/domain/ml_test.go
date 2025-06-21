package domain

import (
	"testing"
)

func TestMLTLDParser_Parse(t *testing.T) {
	c := &Contact{
		Name:         "Mr DNS Admin",
		Email:        "google@domainthenet.net",
		Organization: "Google Inc",
		Country:      "U.S.A.",
		City:         "Mountain View",
		State:        "California",
		Street:       []string{"1600 Amphitheatre Parkway"},
		Postal:       "94043",
		Phone:        "+1-650-6234000",
		Fax:          "+1-650-6188571",
	}
	exp := &ParsedWhois{
		DomainName:     "GOOGLE.ML",
		NameServers:    []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
		CreatedDateRaw: "03/25/2013",
		CreatedDate:    "2013-03-25T00:00:00+00:00",
		ExpiredDateRaw: "06/25/2023",
		ExpiredDate:    "2023-06-25T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
			Billing:    c,
		},
	}

	checkParserResult(t, "whois.dot.ml", "tk_ml_gq/case2.txt", "ml", exp)
}

func TestMLTLDParser_GetName(t *testing.T) {
	parser := NewMLTLDParser()
	if parser.GetName() != "ml" {
		t.Errorf("Expected parser name 'ml', got '%s'", parser.GetName())
	}
}
