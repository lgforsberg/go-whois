package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	dkTimeFmt = "2006-01-02"
)

var DKMap = map[string]string{
	"Domain":      "domain",
	"Status":      "statuses",
	"Registered":  "created_date",
	"Expires":     "expired_date",
	"Nameservers": "name_servers",
	"Dnssec":      "dnssec",
}

type DKParser struct{}

// DKTLDParser is a specialized parser for .dk domain whois responses.
// It handles the specific format used by DK Hostmaster A/S, the Danish registry.
type DKTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

// NewDKTLDParser creates a new parser for .dk domain whois responses.
// The parser is configured to handle Danish registry field layouts and stop at copyright notices.
func NewDKTLDParser() *DKTLDParser {
	return &DKTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "Copyright notice") },
	}
}

func (dkw *DKTLDParser) GetName() string {
	return "dk"
}

func (dkw *DKTLDParser) handleDates(line string, parsedWhois *ParsedWhois) {
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

func (dkw *DKTLDParser) handleNameServers(line string, inNameservers *bool, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Nameservers") {
		*inNameservers = true
		return
	}
	if *inNameservers {
		if strings.HasPrefix(line, "Hostname:") {
			nsLine := strings.TrimSpace(strings.TrimPrefix(line, "Hostname:"))
			if nsLine != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
			}
		}
		if line == "" {
			*inNameservers = false
		}
	}
}

func (dkw *DKTLDParser) handleRegistrant(line string, inRegistrant *bool, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Registrant") {
		*inRegistrant = true
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		return
	}
	if *inRegistrant {
		if strings.HasPrefix(line, "Name:") {
			parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Address:") {
			parsedWhois.Contacts.Registrant.Street = append(parsedWhois.Contacts.Registrant.Street, strings.TrimSpace(strings.TrimPrefix(line, "Address:")))
		} else if strings.HasPrefix(line, "Postalcode:") {
			parsedWhois.Contacts.Registrant.Postal = strings.TrimSpace(strings.TrimPrefix(line, "Postalcode:"))
		} else if strings.HasPrefix(line, "City:") {
			parsedWhois.Contacts.Registrant.City = strings.TrimSpace(strings.TrimPrefix(line, "City:"))
		} else if strings.HasPrefix(line, "Country:") {
			parsedWhois.Contacts.Registrant.Country = strings.TrimSpace(strings.TrimPrefix(line, "Country:"))
		} else if strings.HasPrefix(line, "Phone:") {
			parsedWhois.Contacts.Registrant.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
		}
		if line == "" {
			*inRegistrant = false
		}
	}
}

func (dkw *DKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "No entries found for the selected source.") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := dkw.parser.Do(rawtext, nil, DKMap)
	if err != nil {
		return nil, err
	}

	// Initialize contacts if nil
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	// Parse the response line by line
	lines := strings.Split(rawtext, "\n")
	inNameservers := false
	inRegistrant := false
	parsedWhois.NameServers = []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		dkw.handleDates(line, parsedWhois)
		dkw.handleNameServers(line, &inNameservers, parsedWhois)
		dkw.handleRegistrant(line, &inRegistrant, parsedWhois)
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
