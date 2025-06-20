package domain

import (
	"strings"
)

type ISTLDParser struct {
	parser IParser
}

func NewISTLDParser() *ISTLDParser {
	return &ISTLDParser{
		parser: NewParser(),
	}
}

func (isw *ISTLDParser) GetName() string {
	return "is"
}

func (isw *ISTLDParser) parseDomainSection(lines []string, parsedWhois *ParsedWhois) (map[string]string, bool) {
	handles := make(map[string]string)
	var domainSectionDone bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if !domainSectionDone {
			if strings.HasPrefix(line, "domain:") {
				parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
			} else if strings.HasPrefix(line, "registrant:") {
				handles["registrant"] = strings.TrimSpace(strings.TrimPrefix(line, "registrant:"))
			} else if strings.HasPrefix(line, "admin-c:") {
				handles["admin"] = strings.TrimSpace(strings.TrimPrefix(line, "admin-c:"))
			} else if strings.HasPrefix(line, "tech-c:") {
				handles["tech"] = strings.TrimSpace(strings.TrimPrefix(line, "tech-c:"))
			} else if strings.HasPrefix(line, "zone-c:") {
				handles["zone"] = strings.TrimSpace(strings.TrimPrefix(line, "zone-c:"))
			} else if strings.HasPrefix(line, "billing-c:") {
				handles["billing"] = strings.TrimSpace(strings.TrimPrefix(line, "billing-c:"))
			} else if strings.HasPrefix(line, "nserver:") {
				parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "nserver:")))
			} else if strings.HasPrefix(line, "dnssec:") {
				parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "dnssec:"))
			} else if strings.HasPrefix(line, "created:") {
				parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "created:"))
			} else if strings.HasPrefix(line, "expires:") {
				parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "expires:"))
			} else if strings.HasPrefix(line, "source:") {
				domainSectionDone = true
			}
		}
	}
	return handles, domainSectionDone
}

func (isw *ISTLDParser) parseRoleSections(lines []string) map[string]*Contact {
	roleMap := make(map[string]*Contact)
	var currentHandle string
	var currentContact *Contact
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "role:") {
			currentContact = &Contact{}
			currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(line, "role:"))
			currentHandle = ""
		} else if strings.HasPrefix(line, "nic-hdl:") && currentContact != nil {
			currentHandle = strings.TrimSpace(strings.TrimPrefix(line, "nic-hdl:"))
		} else if strings.HasPrefix(line, "address:") && currentContact != nil {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
			if addr != "" {
				currentContact.Street = append(currentContact.Street, addr)
			}
		} else if strings.HasPrefix(line, "phone:") && currentContact != nil {
			currentContact.Phone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
		} else if strings.HasPrefix(line, "e-mail:") && currentContact != nil {
			currentContact.Email = strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
		} else if strings.HasPrefix(line, "source:") && currentContact != nil && currentHandle != "" {
			roleMap[currentHandle] = currentContact
			currentContact = nil
			currentHandle = ""
		}
	}
	return roleMap
}

func (isw *ISTLDParser) mapHandlesToContacts(handles map[string]string, roleMap map[string]*Contact, parsedWhois *ParsedWhois) {
	if len(handles) > 0 {
		parsedWhois.Contacts = &Contacts{}
		if h, ok := handles["registrant"]; ok {
			if c, ok2 := roleMap[h]; ok2 {
				parsedWhois.Contacts.Registrant = c
			}
		}
		if h, ok := handles["admin"]; ok {
			if c, ok2 := roleMap[h]; ok2 {
				parsedWhois.Contacts.Admin = c
			}
		}
		if h, ok := handles["tech"]; ok {
			if c, ok2 := roleMap[h]; ok2 {
				parsedWhois.Contacts.Tech = c
			}
		}
		if h, ok := handles["billing"]; ok {
			if c, ok2 := roleMap[h]; ok2 {
				parsedWhois.Contacts.Billing = c
			}
		}
	}
}

func (isw *ISTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "No entries found for query") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	// First pass: parse domain section and collect handle references
	handles, _ := isw.parseDomainSection(lines, parsedWhois)

	// Second pass: parse role sections and map handles to contact info
	roleMap := isw.parseRoleSections(lines)

	// Map handles to contacts
	isw.mapHandlesToContacts(handles, roleMap, parsedWhois)

	return parsedWhois, nil
}
