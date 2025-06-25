package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type SATLDParser struct {
	parser IParser
}

func NewSATLDParser() *SATLDParser {
	return &SATLDParser{
		parser: NewParser(),
	}
}

func (s *SATLDParser) GetName() string {
	return "sa"
}

func (s *SATLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered domains
	for _, line := range lines {
		if strings.Contains(line, "No Match for") {
			SetDomainAvailabilityStatus(parsedWhois, true)
			return parsedWhois, nil
		}
	}

	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if s.handleSectionChange(line, &currentSection, parsedWhois) {
			continue
		}
		if s.parseDomainFields(line, parsedWhois) {
			continue
		}
		if s.parseNameserverFields(line, currentSection, parsedWhois) {
			continue
		}
		if s.parseContactFields(line, currentSection, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}

func (s *SATLDParser) handleSectionChange(line string, currentSection *string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Registrant:"):
		*currentSection = "registrant"
		s.ensureContact(parsedWhois, "registrant")
		return true
	case strings.HasPrefix(line, "Administrative Contact:"):
		*currentSection = "admin"
		s.ensureContact(parsedWhois, "admin")
		return true
	case strings.HasPrefix(line, "Technical Contact:"):
		*currentSection = "tech"
		s.ensureContact(parsedWhois, "tech")
		return true
	case strings.HasPrefix(line, "Name Servers:"):
		*currentSection = "nameservers"
		return true
	case strings.HasPrefix(line, "DS Records:"):
		*currentSection = "dsrecords"
		return true
	}
	return false
}

func (s *SATLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name:"):
		parsedWhois.DomainName = utils.ExtractField(line, "Domain Name:")
		return true
	case strings.HasPrefix(line, "DNSSEC:"):
		parsedWhois.Dnssec = utils.ExtractField(line, "DNSSEC:")
		return true
	}
	return false
}

func (s *SATLDParser) parseNameserverFields(line, currentSection string, parsedWhois *ParsedWhois) bool {
	if currentSection == "nameservers" && line != "" {
		// Parse nameserver lines (can include IP addresses in parentheses)
		ns := line
		if idx := strings.Index(ns, " ("); idx != -1 {
			ns = strings.TrimSpace(ns[:idx])
		}
		if ns != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
		return true
	}
	return false
}

func (s *SATLDParser) parseContactFields(line, currentSection string, parsedWhois *ParsedWhois) bool {
	if currentSection == "dsrecords" && line != "" {
		// DS records are not stored in the ParsedWhois struct, so we skip them
		return true
	}
	if currentSection == "" || line == "" {
		return false
	}

	var c *Contact
	switch currentSection {
	case "registrant":
		c = parsedWhois.Contacts.Registrant
	case "admin":
		c = parsedWhois.Contacts.Admin
	case "tech":
		c = parsedWhois.Contacts.Tech
	default:
		return false
	}

	return s.assignContactField(line, c, currentSection)
}

func (s *SATLDParser) assignContactField(line string, c *Contact, section string) bool {
	switch section {
	case "registrant":
		if c.Organization == "" {
			c.Organization = line
			return true
		}
	case "admin", "tech":
		if c.Name == "" {
			c.Name = line
			return true
		}
	}

	if strings.HasPrefix(line, "Address:") {
		// Extract address content after "Address:"
		address := utils.ExtractField(line, "Address:")
		if address != "" {
			c.Street = append(c.Street, address)
		}
		return true
	}
	c.Street = append(c.Street, line)
	return true
}

func (s *SATLDParser) ensureContact(parsedWhois *ParsedWhois, contactType string) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	switch contactType {
	case "registrant":
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
	case "admin":
		if parsedWhois.Contacts.Admin == nil {
			parsedWhois.Contacts.Admin = &Contact{}
		}
	case "tech":
		if parsedWhois.Contacts.Tech == nil {
			parsedWhois.Contacts.Tech = &Contact{}
		}
	}
}
