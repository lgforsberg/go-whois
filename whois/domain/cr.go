package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	crTimeFmt = "02.01.2006 15:04:05"
	crDateFmt = "02.01.2006"
)

type CRParser struct{}

type CRTLDParser struct {
	parser IParser
}

func NewCRTLDParser() *CRTLDParser {
	return &CRTLDParser{
		parser: NewParser(),
	}
}

func (crw *CRTLDParser) GetName() string {
	return "cr"
}

func (crw *CRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "%ERROR:101: no entries found") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var inContactSection bool
	var inNssetSection bool
	var currentContact *Contact
	var currentContactID string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if crw.parseDomainFields(line, parsedWhois) {
			continue
		}
		if crw.parseChangedField(line, inContactSection, parsedWhois) {
			continue
		}
		if crw.handleSectionChange(line, &inContactSection, &inNssetSection, &currentContact, &currentContactID, parsedWhois, rawtext) {
			continue
		}
		if crw.parseContactFields(line, inContactSection, currentContact) {
			continue
		}
		if crw.parseNameserverFields(line, inNssetSection, parsedWhois) {
			continue
		}
	}

	// Set status to "active" if no specific status found
	if len(parsedWhois.Statuses) == 0 {
		parsedWhois.Statuses = []string{"active"}
	}

	return parsedWhois, nil
}

func (crw *CRTLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "domain:"):
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
		return true
	case strings.HasPrefix(line, "registrant:"):
		// Store registrant handle for later contact lookup
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		return true
	case strings.HasPrefix(line, "registrar:"):
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
		return true
	case strings.HasPrefix(line, "status:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
		parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		return true
	case strings.HasPrefix(line, "registered:"):
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "registered:"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, crTimeFmt, WhoisTimeFmt)
		return true
	case strings.HasPrefix(line, "expire:"):
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, crDateFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (crw *CRTLDParser) parseChangedField(line string, inContactSection bool, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "changed:") && !inContactSection {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "changed:"))
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, crTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (crw *CRTLDParser) handleSectionChange(line string, inContactSection, inNssetSection *bool, currentContact **Contact, currentContactID *string, parsedWhois *ParsedWhois, rawtext string) bool {
	switch {
	case strings.HasPrefix(line, "contact:"):
		*inContactSection = true
		*inNssetSection = false
		*currentContactID = strings.TrimSpace(strings.TrimPrefix(line, "contact:"))
		*currentContact = &Contact{}
		return true
	case strings.HasPrefix(line, "nsset:"):
		*inContactSection = false
		*inNssetSection = true
		// Store contact if it was the registrant
		if *currentContact != nil && *currentContactID != "" {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			// Check if this was the registrant contact
			if strings.Contains(rawtext, "registrant: "+*currentContactID) {
				parsedWhois.Contacts.Registrant = *currentContact
			}
		}
		*currentContact = nil
		*currentContactID = ""
		return true
	}
	return false
}

func (crw *CRTLDParser) parseContactFields(line string, inContactSection bool, currentContact *Contact) bool {
	if !inContactSection || line == "" || strings.HasPrefix(line, "contact:") || strings.HasPrefix(line, "nsset:") {
		return false
	}
	if currentContact == nil {
		return false
	}

	return crw.assignContactField(line, currentContact)
}

func (crw *CRTLDParser) assignContactField(line string, c *Contact) bool {
	switch {
	case strings.HasPrefix(line, "org:"):
		c.Organization = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
		return true
	case strings.HasPrefix(line, "name:"):
		c.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		return true
	case strings.HasPrefix(line, "address:"):
		c.Street = append(c.Street, strings.TrimSpace(strings.TrimPrefix(line, "address:")))
		return true
	case strings.HasPrefix(line, "phone:"):
		c.Phone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
		return true
	case strings.HasPrefix(line, "e-mail:"):
		c.Email = strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
		return true
	}
	return false
}

func (crw *CRTLDParser) parseNameserverFields(line string, inNssetSection bool, parsedWhois *ParsedWhois) bool {
	if inNssetSection && strings.HasPrefix(line, "nserver:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "nserver:")))
		return true
	}
	return false
}
