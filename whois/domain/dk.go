package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	dkTimeFmt = "2006-01-02"
)

var DKMap = map[string]string{
	"Domain":    "domain",
	"Registrar": "reg/name",
	"Status":    "statuses",
}

type DKParser struct{}

type DKTLDParser struct {
	parser IParser
}

func NewDKTLDParser() *DKTLDParser {
	return &DKTLDParser{
		parser: NewParser(),
	}
}

func (dkw *DKTLDParser) GetName() string {
	return "dk"
}

func (dkw *DKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "No entries found for the selected source.") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois, err := dkw.parser.Do(rawtext, nil, DKMap)
	if err != nil {
		return nil, err
	}

	// Parse the response line by line
	lines := strings.Split(rawtext, "\n")

	// Parse dates
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Registered:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Registered:"))
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, dkTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "Expires:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Expires:"))
			parsedWhois.ExpiredDateRaw = dateStr
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, dkTimeFmt, WhoisTimeFmt)
		}
	}

	// Parse name servers
	parsedWhois.NameServers = []string{}
	inNameservers := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Nameservers") {
			inNameservers = true
			continue
		}
		if inNameservers && strings.HasPrefix(line, "Hostname:") {
			nsLine := strings.TrimSpace(strings.TrimPrefix(line, "Hostname:"))
			if nsLine != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
			}
		}
		// Stop parsing nameservers when we hit an empty line or another section
		if inNameservers && line == "" {
			inNameservers = false
		}
	}

	// Parse registrant information
	inRegistrant := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Registrant") {
			inRegistrant = true
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			continue
		}
		if inRegistrant {
			if strings.HasPrefix(line, "Name:") {
				nameStr := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				if parsedWhois.Contacts.Registrant.Name == "" {
					parsedWhois.Contacts.Registrant.Name = nameStr
				}
			} else if strings.HasPrefix(line, "Address:") {
				addrStr := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
				parsedWhois.Contacts.Registrant.Street = append(parsedWhois.Contacts.Registrant.Street, addrStr)
			} else if strings.HasPrefix(line, "Postalcode:") {
				postalStr := strings.TrimSpace(strings.TrimPrefix(line, "Postalcode:"))
				parsedWhois.Contacts.Registrant.Postal = postalStr
			} else if strings.HasPrefix(line, "City:") {
				cityStr := strings.TrimSpace(strings.TrimPrefix(line, "City:"))
				parsedWhois.Contacts.Registrant.City = cityStr
			} else if strings.HasPrefix(line, "Country:") {
				countryStr := strings.TrimSpace(strings.TrimPrefix(line, "Country:"))
				parsedWhois.Contacts.Registrant.Country = countryStr
			} else if strings.HasPrefix(line, "Phone:") {
				phoneStr := strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
				parsedWhois.Contacts.Registrant.Phone = phoneStr
			}
		}
		// Stop parsing registrant when we hit an empty line or another section
		if inRegistrant && line == "" {
			inRegistrant = false
		}
	}

	// Set status to "Active" for registered domains if not already set
	if len(parsedWhois.Statuses) == 0 {
		parsedWhois.Statuses = []string{"Active"}
	} else {
		// Clear any duplicate statuses and ensure we have "Active"
		parsedWhois.Statuses = []string{"Active"}
	}

	return parsedWhois, nil
}
