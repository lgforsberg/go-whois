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

		if strings.HasPrefix(line, "domain:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
		} else if strings.HasPrefix(line, "registrant:") {
			// Store registrant handle for later contact lookup
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			// We'll populate this when we find the contact section
		} else if strings.HasPrefix(line, "registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
		} else if strings.HasPrefix(line, "status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		} else if strings.HasPrefix(line, "registered:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "registered:"))
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, crTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "changed:") && !inContactSection {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "changed:"))
			parsedWhois.UpdatedDateRaw = dateStr
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, crTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "expire:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
			parsedWhois.ExpiredDateRaw = dateStr
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, crDateFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "contact:") {
			inContactSection = true
			inNssetSection = false
			currentContactID = strings.TrimSpace(strings.TrimPrefix(line, "contact:"))
			currentContact = &Contact{}
		} else if strings.HasPrefix(line, "nsset:") {
			inContactSection = false
			inNssetSection = true
			// Store contact if it was the registrant
			if currentContact != nil && currentContactID != "" {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				// Check if this was the registrant contact
				if strings.Contains(rawtext, "registrant: "+currentContactID) {
					parsedWhois.Contacts.Registrant = currentContact
				}
			}
			currentContact = nil
			currentContactID = ""
		} else if inContactSection && line != "" && !strings.HasPrefix(line, "contact:") && !strings.HasPrefix(line, "nsset:") {
			if currentContact != nil {
				if strings.HasPrefix(line, "org:") {
					currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
				} else if strings.HasPrefix(line, "name:") {
					currentContact.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				} else if strings.HasPrefix(line, "address:") {
					currentContact.Street = append(currentContact.Street, strings.TrimSpace(strings.TrimPrefix(line, "address:")))
				} else if strings.HasPrefix(line, "phone:") {
					currentContact.Phone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
				} else if strings.HasPrefix(line, "e-mail:") {
					currentContact.Email = strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
				}
			}
		} else if inNssetSection && strings.HasPrefix(line, "nserver:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "nserver:")))
		}
	}

	// Set status to "active" if no specific status found
	if len(parsedWhois.Statuses) == 0 {
		parsedWhois.Statuses = []string{"active"}
	}

	return parsedWhois, nil
}
