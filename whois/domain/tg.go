package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TGTLDParser struct {
	parser IParser
}

func NewTGTLDParser() *TGTLDParser {
	return &TGTLDParser{
		parser: NewParser(),
	}
}

func (p *TGTLDParser) GetName() string {
	return "tg"
}

func (p *TGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "NO OBJECT FOUND!") {
		SetDomainAvailabilityStatus(parsed, true)
		return parsed, nil
	}

	// Split into sections
	sections := strings.Split(rawtext, "----------------------------------------")

	// Process the first section (they all contain the same domain info)
	if len(sections) > 0 {
		p.parseDomainSection(sections[0], parsed)
	}

	// Process contact information from all sections
	var owner, admin, tech Contact
	for _, section := range sections {
		if strings.TrimSpace(section) == "" {
			continue
		}
		p.parseContactSection(section, &owner, &admin, &tech)
	}

	if owner.Name != "" {
		parsed.Contacts.Registrant = &owner
	}
	if admin.Name != "" {
		parsed.Contacts.Admin = &admin
	}
	if tech.Name != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *TGTLDParser) parseDomainSection(section string, parsed *ParsedWhois) {
	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if p.skipLine(line) {
			continue
		}
		p.parseDomainField(line, parsed)
	}
}

func (p *TGTLDParser) skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "This is") || strings.HasPrefix(line, "Java Whois") ||
		strings.HasPrefix(line, "All rights") || strings.HasPrefix(line, "Copyright")
}

func (p *TGTLDParser) parseDomainField(line string, parsed *ParsedWhois) {
	switch {
	case strings.HasPrefix(line, "Domain:"):
		parsed.DomainName = extractValue(line)
	case strings.HasPrefix(line, "Registrar:"):
		parsed.Registrar.Name = extractValue(line)
	case strings.HasPrefix(line, "Activation:"):
		parsed.CreatedDateRaw = extractValue(line)
	case strings.HasPrefix(line, "Expiration:"):
		parsed.ExpiredDateRaw = extractValue(line)
	case strings.HasPrefix(line, "Status:"):
		status := extractValue(line)
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
	case strings.HasPrefix(line, "Name Server (DB):"):
		ns := extractValue(line)
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
	}
}

func (p *TGTLDParser) parseContactSection(section string, owner, admin, tech *Contact) {
	lines := strings.Split(section, "\n")
	var currentContact *Contact
	var contactType string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Contact Type:") {
			contactType = extractValue(line)
			currentContact = p.getContactByType(contactType, owner, admin, tech)
			continue
		}

		if currentContact == nil {
			continue
		}

		if p.parseContactField(line, currentContact) {
			continue
		}
		// Handle address continuation lines
		if len(currentContact.Street) > 0 &&
			!strings.Contains(line, ":") && line != "" {
			currentContact.Street = append(currentContact.Street, line)
		}
	}
}

func (p *TGTLDParser) getContactByType(contactType string, owner, admin, tech *Contact) *Contact {
	switch contactType {
	case "owner":
		return owner
	case "administrative":
		return admin
	case "technical":
		return tech
	default:
		return nil
	}
}

func (p *TGTLDParser) parseContactField(line string, currentContact *Contact) bool {
	switch {
	case strings.HasPrefix(line, "Last Name:"):
		currentContact.Name = extractValue(line)
		return true
	case strings.HasPrefix(line, "First Name:"):
		firstName := extractValue(line)
		if currentContact.Name != "" {
			currentContact.Name = firstName + " " + currentContact.Name
		} else {
			currentContact.Name = firstName
		}
		return true
	case strings.HasPrefix(line, "Address:"):
		address := extractValue(line)
		currentContact.Street = append(currentContact.Street, address)
		return true
	case strings.HasPrefix(line, "Tel:"):
		currentContact.Phone = extractValue(line)
		return true
	case strings.HasPrefix(line, "Fax:"):
		currentContact.Fax = extractValue(line)
		return true
	case strings.HasPrefix(line, "e-mail:"):
		currentContact.Email = extractValue(line)
		return true
	}
	return false
}

// extractValue extracts the value after dots for alignment
func extractValue(line string) string {
	// Find the colon
	colonIndex := strings.Index(line, ":")
	if colonIndex == -1 {
		return strings.TrimSpace(line)
	}

	// Start after the colon
	start := colonIndex + 1

	// Find the first non-dot character after the colon
	for start < len(line) && line[start] == '.' {
		start++
	}

	// Extract everything from the first non-dot character
	if start < len(line) {
		return strings.TrimSpace(line[start:])
	}

	return ""
}
