package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type RSTLDParser struct {
	parser IParser
}

func NewRSTLDParser() *RSTLDParser {
	return &RSTLDParser{
		parser: NewParser(),
	}
}

func (r *RSTLDParser) GetName() string {
	return "rs"
}

func (r *RSTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered or reserved domains
	for _, line := range lines {
		if strings.Contains(line, "Domain is not registered") || strings.Contains(line, "This domain is reserved") {
			SetDomainAvailabilityStatus(parsedWhois, true)
			return parsedWhois, nil
		}
	}

	var currentSection string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if r.parseDomainFields(line, parsedWhois, &currentSection) {
			continue
		}
		if r.parseContactFields(line, parsedWhois, currentSection) {
			continue
		}
	}

	return parsedWhois, nil
}

func (r *RSTLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois, currentSection *string) bool {
	switch {
	case strings.HasPrefix(line, "Domain name:"):
		return r.parseDomainName(line, parsedWhois)
	case strings.HasPrefix(line, "Domain status:"):
		return r.parseDomainStatus(line, parsedWhois)
	case strings.HasPrefix(line, "Registration date:"):
		return r.parseRegistrationDate(line, parsedWhois)
	case strings.HasPrefix(line, "Modification date:"):
		return r.parseModificationDate(line, parsedWhois)
	case strings.HasPrefix(line, "Expiration date:"):
		return r.parseExpirationDate(line, parsedWhois)
	case strings.HasPrefix(line, "Registrar:"):
		return r.parseRegistrar(line, parsedWhois)
	case strings.HasPrefix(line, "Registrant:"):
		return r.parseRegistrant(line, parsedWhois, currentSection)
	case strings.HasPrefix(line, "Administrative contact:"):
		return r.parseAdminContact(line, parsedWhois, currentSection)
	case strings.HasPrefix(line, "Technical contact:"):
		return r.parseTechContact(line, parsedWhois, currentSection)
	case strings.HasPrefix(line, "DNS:"):
		return r.parseDNS(line, parsedWhois)
	case strings.HasPrefix(line, "DNSSEC signed:"):
		return r.parseDNSSEC(line, parsedWhois)
	}
	return false
}

func (r *RSTLDParser) parseDomainName(line string, parsedWhois *ParsedWhois) bool {
	parsedWhois.DomainName = utils.ExtractField(line, "Domain name:")
	return true
}

func (r *RSTLDParser) parseDomainStatus(line string, parsedWhois *ParsedWhois) bool {
	status := utils.ExtractField(line, "Domain status:")
	status = r.cleanStatus(status)
	if status != "" {
		parsedWhois.Statuses = append(parsedWhois.Statuses, status)
	}
	return true
}

func (r *RSTLDParser) cleanStatus(status string) string {
	if idx := strings.Index(status, " http"); idx != -1 {
		status = strings.TrimSpace(status[:idx])
	}
	return status
}

func (r *RSTLDParser) parseRegistrationDate(line string, parsedWhois *ParsedWhois) bool {
	parsedWhois.CreatedDateRaw = utils.ExtractField(line, "Registration date:")
	return true
}

func (r *RSTLDParser) parseModificationDate(line string, parsedWhois *ParsedWhois) bool {
	parsedWhois.UpdatedDateRaw = utils.ExtractField(line, "Modification date:")
	return true
}

func (r *RSTLDParser) parseExpirationDate(line string, parsedWhois *ParsedWhois) bool {
	parsedWhois.ExpiredDateRaw = utils.ExtractField(line, "Expiration date:")
	return true
}

func (r *RSTLDParser) parseRegistrar(line string, parsedWhois *ParsedWhois) bool {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	parsedWhois.Registrar.Name = utils.ExtractField(line, "Registrar:")
	return true
}

func (r *RSTLDParser) parseRegistrant(line string, parsedWhois *ParsedWhois, currentSection *string) bool {
	*currentSection = "registrant"
	r.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}
	parsedWhois.Contacts.Registrant.Organization = utils.ExtractField(line, "Registrant:")
	return true
}

func (r *RSTLDParser) parseAdminContact(line string, parsedWhois *ParsedWhois, currentSection *string) bool {
	*currentSection = "admin"
	r.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Admin == nil {
		parsedWhois.Contacts.Admin = &Contact{}
	}
	parsedWhois.Contacts.Admin.Organization = utils.ExtractField(line, "Administrative contact:")
	return true
}

func (r *RSTLDParser) parseTechContact(line string, parsedWhois *ParsedWhois, currentSection *string) bool {
	*currentSection = "tech"
	r.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Tech == nil {
		parsedWhois.Contacts.Tech = &Contact{}
	}
	parsedWhois.Contacts.Tech.Organization = utils.ExtractField(line, "Technical contact:")
	return true
}

func (r *RSTLDParser) parseDNS(line string, parsedWhois *ParsedWhois) bool {
	nsRaw := utils.ExtractField(line, "DNS:")
	parsed := r.cleanDNS(nsRaw)
	if parsed != "" {
		parsedWhois.NameServers = append(parsedWhois.NameServers, parsed)
	}
	return true
}

func (r *RSTLDParser) cleanDNS(nsRaw string) string {
	parsed := nsRaw
	if idx := strings.Index(parsed, " -"); idx != -1 {
		parsed = parsed[:idx]
	}
	return strings.TrimSpace(parsed)
}

func (r *RSTLDParser) parseDNSSEC(line string, parsedWhois *ParsedWhois) bool {
	parsedWhois.Dnssec = utils.ExtractField(line, "DNSSEC signed:")
	return true
}

func (r *RSTLDParser) ensureContacts(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
}

func (r *RSTLDParser) parseContactFields(line string, parsedWhois *ParsedWhois, currentSection string) bool {
	if !strings.Contains(line, ":") {
		return false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

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

	switch key {
	case "Address":
		c.Street = append(c.Street, value)
	case "Postal Code":
		c.Postal = value
	case "ID Number":
		c.ID = value
	case "Tax ID":
		// Tax ID is not stored in Contact struct
	}
	return true
}
