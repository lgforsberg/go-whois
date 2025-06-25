package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	ptTimeFmt = "02/01/2006 15:04:05"
)

var PTMap = map[string]string{
	"Owner Name":         "c/registrant/name",
	"Owner Address":      "c/registrant/street",
	"Owner Locality":     "c/registrant/city",
	"Owner ZipCode":      "c/registrant/postal",
	"Owner Country Code": "c/registrant/country",
	"Owner Email":        "c/registrant/email",
	"Admin Name":         "c/admin/name",
	"Admin Address":      "c/admin/street",
	"Admin Locality":     "c/admin/city",
	"Admin ZipCode":      "c/admin/postal",
	"Admin Country Code": "c/admin/country",
	"Admin Email":        "c/admin/email",
}

type PTParser struct{}

type PTTLDParser struct {
	parser IParser
}

func NewPTTLDParser() *PTTLDParser {
	return &PTTLDParser{
		parser: NewParser(),
	}
}

func (ptw *PTTLDParser) GetName() string {
	return "pt"
}

func (ptw *PTTLDParser) parseDates(lines []string, parsedWhois *ParsedWhois) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Creation Date:") {
			dateStr := utils.ExtractField(line, "Creation Date:")
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, ptTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "Expiration Date:") {
			dateStr := utils.ExtractField(line, "Expiration Date:")
			parsedWhois.ExpiredDateRaw = dateStr
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, ptTimeFmt, WhoisTimeFmt)
		}
	}
}

func (ptw *PTTLDParser) parseNameServers(lines []string, parsedWhois *ParsedWhois) {
	parsedWhois.NameServers = []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name Server:") {
			nsLine := utils.ExtractField(line, "Name Server:")
			// Extract just the name server name (before the |)
			if pipeIndex := strings.Index(nsLine, " | "); pipeIndex != -1 {
				nsName := strings.TrimSpace(nsLine[:pipeIndex])
				if nsName != "" {
					parsedWhois.NameServers = append(parsedWhois.NameServers, nsName)
				}
			} else {
				// If no pipe, use the whole line
				if nsLine != "" {
					parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
				}
			}
		}
	}
}

func (ptw *PTTLDParser) cleanupEmptyContacts(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts != nil {
		if parsedWhois.Contacts.Registrant != nil && isContactEmpty(parsedWhois.Contacts.Registrant) {
			parsedWhois.Contacts.Registrant = nil
		}
		if parsedWhois.Contacts.Admin != nil && isContactEmpty(parsedWhois.Contacts.Admin) {
			parsedWhois.Contacts.Admin = nil
		}
		if parsedWhois.Contacts.Tech != nil && isContactEmpty(parsedWhois.Contacts.Tech) {
			parsedWhois.Contacts.Tech = nil
		}
		if parsedWhois.Contacts.Billing != nil && isContactEmpty(parsedWhois.Contacts.Billing) {
			parsedWhois.Contacts.Billing = nil
		}
	}
}

func (ptw *PTTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := ptw.parser.Do(rawtext, nil, PTMap)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(rawtext, "\n")

	// Parse dates in PT format
	ptw.parseDates(lines, parsedWhois)

	// Parse name servers with IP addresses
	ptw.parseNameServers(lines, parsedWhois)

	// Remove empty contacts
	ptw.cleanupEmptyContacts(parsedWhois)

	return parsedWhois, nil
}

// isContactEmpty returns true if all fields in the contact are empty or only contain empty strings
func isContactEmpty(c *Contact) bool {
	if c == nil {
		return true
	}

	return isBasicFieldsEmpty(c) && isAddressFieldsEmpty(c) && isContactFieldsEmpty(c) && isStreetEmpty(c)
}

func isBasicFieldsEmpty(c *Contact) bool {
	return c.ID == "" && c.Name == "" && c.Email == "" && c.Organization == ""
}

func isAddressFieldsEmpty(c *Contact) bool {
	return c.Country == "" && c.City == "" && c.State == "" && c.Postal == ""
}

func isContactFieldsEmpty(c *Contact) bool {
	return c.Phone == "" && c.PhoneExt == "" && c.Fax == "" && c.FaxExt == ""
}

func isStreetEmpty(c *Contact) bool {
	return len(c.Street) == 0 || (len(c.Street) == 1 && c.Street[0] == "")
}
