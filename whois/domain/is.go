package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
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
		if utils.SkipLine(line) {
			continue
		}
		if !domainSectionDone {
			if isw.parseDomainFields(line, parsedWhois) {
				continue
			}
			if isw.parseHandleReferences(line, handles) {
				continue
			}
			if strings.HasPrefix(line, "source:") {
				domainSectionDone = true
			}
		}
	}
	return handles, domainSectionDone
}

func (isw *ISTLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "domain:"):
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
		return true
	case strings.HasPrefix(line, "nserver:"):
		parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "nserver:")))
		return true
	case strings.HasPrefix(line, "dnssec:"):
		parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "dnssec:"))
		return true
	case strings.HasPrefix(line, "created:"):
		parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "created:"))
		return true
	case strings.HasPrefix(line, "expires:"):
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "expires:"))
		return true
	}
	return false
}

func (isw *ISTLDParser) parseHandleReferences(line string, handles map[string]string) bool {
	switch {
	case strings.HasPrefix(line, "registrant:"):
		handles["registrant"] = strings.TrimSpace(strings.TrimPrefix(line, "registrant:"))
		return true
	case strings.HasPrefix(line, "admin-c:"):
		handles["admin"] = strings.TrimSpace(strings.TrimPrefix(line, "admin-c:"))
		return true
	case strings.HasPrefix(line, "tech-c:"):
		handles["tech"] = strings.TrimSpace(strings.TrimPrefix(line, "tech-c:"))
		return true
	case strings.HasPrefix(line, "zone-c:"):
		handles["zone"] = strings.TrimSpace(strings.TrimPrefix(line, "zone-c:"))
		return true
	case strings.HasPrefix(line, "billing-c:"):
		handles["billing"] = strings.TrimSpace(strings.TrimPrefix(line, "billing-c:"))
		return true
	}
	return false
}

func (isw *ISTLDParser) parseRoleSections(lines []string) map[string]*Contact {
	roleMap := make(map[string]*Contact)
	var currentHandle string
	var currentContact *Contact
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if isw.parseRoleHeader(line, &currentContact, &currentHandle) {
			continue
		}
		if isw.parseContactFields(line, currentContact) {
			continue
		}
		if isw.finalizeContact(line, currentContact, currentHandle, roleMap) {
			currentContact = nil
			currentHandle = ""
		}
	}
	return roleMap
}

func (isw *ISTLDParser) parseRoleHeader(line string, currentContact **Contact, currentHandle *string) bool {
	switch {
	case strings.HasPrefix(line, "role:"):
		*currentContact = &Contact{}
		(*currentContact).Organization = strings.TrimSpace(strings.TrimPrefix(line, "role:"))
		*currentHandle = ""
		return true
	case strings.HasPrefix(line, "nic-hdl:") && *currentContact != nil:
		*currentHandle = strings.TrimSpace(strings.TrimPrefix(line, "nic-hdl:"))
		return true
	}
	return false
}

func (isw *ISTLDParser) parseContactFields(line string, currentContact *Contact) bool {
	if currentContact == nil {
		return false
	}
	switch {
	case strings.HasPrefix(line, "address:"):
		addr := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
		if addr != "" {
			currentContact.Street = append(currentContact.Street, addr)
		}
		return true
	case strings.HasPrefix(line, "phone:"):
		currentContact.Phone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
		return true
	case strings.HasPrefix(line, "e-mail:"):
		currentContact.Email = strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
		return true
	}
	return false
}

func (isw *ISTLDParser) finalizeContact(line string, currentContact *Contact, currentHandle string, roleMap map[string]*Contact) bool {
	if strings.HasPrefix(line, "source:") && currentContact != nil && currentHandle != "" {
		roleMap[currentHandle] = currentContact
		return true
	}
	return false
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
