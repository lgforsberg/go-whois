package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type UGParser struct{}

type UGTLDParser struct {
	parser IParser
}

func NewUGTLDParser() *UGTLDParser {
	return &UGTLDParser{
		parser: NewParser(),
	}
}

func (p *UGTLDParser) GetName() string {
	return "ug"
}

func (p *UGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "The domain contains special characters not allowed") ||
		strings.Contains(rawtext, "This domain violates registry policy") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var section string
	var registrant, admin, tech Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, ">>>") {
			continue
		}

		if p.handleBasicFields(line, parsed) {
			continue
		}

		if p.handleSectionHeaders(line, &section) {
			continue
		}

		p.handleContactFields(line, section, &registrant, &admin, &tech)
	}

	p.assignContacts(parsed, registrant, admin, tech)

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *UGTLDParser) handleBasicFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain name:"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		return true
	case strings.HasPrefix(line, "Status:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Registered On:"):
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registered On:"))
		return true
	case strings.HasPrefix(line, "Expires On:"):
		parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires On:"))
		return true
	case strings.HasPrefix(line, "Nameserver:"):
		if utils.IsNameserverLine(line, "Nameserver:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Nameserver:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleSectionHeaders(line string, section *string) bool {
	switch {
	case strings.HasPrefix(line, "Registrant Contact Information:"):
		*section = "registrant"
		return true
	case strings.HasPrefix(line, "Administrative Contact Information:"):
		*section = "admin"
		return true
	case strings.HasPrefix(line, "Technical Contact Information:"):
		*section = "tech"
		return true
	}
	return false
}

func (p *UGTLDParser) handleContactFields(line, section string, registrant, admin, tech *Contact) {
	var c *Contact
	switch section {
	case "registrant":
		c = registrant
	case "admin":
		c = admin
	case "tech":
		c = tech
	default:
		return
	}

	p.parseContactField(line, c)
}

func (p *UGTLDParser) parseContactField(line string, c *Contact) {
	if p.handleNameField(line, c) {
		return
	}
	if p.handleOrganizationField(line, c) {
		return
	}
	if p.handleCountryField(line, c) {
		return
	}
	if p.handleStateField(line, c) {
		return
	}
	if p.handleCityField(line, c) {
		return
	}
	if p.handleAddressField(line, c) {
		return
	}
	if p.handlePostalField(line, c) {
		return
	}
	if p.handlePhoneField(line, c) {
		return
	}
	p.handleEmailField(line, c)
}

func (p *UGTLDParser) handleNameField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Name:") || strings.HasPrefix(line, "Admin Name:") || strings.HasPrefix(line, "Tech Name:") {
		name := p.extractValue(line, "Registrant Name:", "Admin Name:", "Tech Name:")
		if name != "" {
			c.Name = name
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleOrganizationField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Organization:") || strings.HasPrefix(line, "Admin Organization:") || strings.HasPrefix(line, "Tech Organization:") {
		org := p.extractValue(line, "Registrant Organization:", "Admin Organization:", "Tech Organization:")
		if org != "" {
			c.Organization = org
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleCountryField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Country:") || strings.HasPrefix(line, "Admin Country:") || strings.HasPrefix(line, "Tech Country:") {
		country := p.extractValue(line, "Registrant Country:", "Admin Country:", "Tech Country:")
		if country != "" && country != "UNKNOWN" {
			c.Country = country
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleStateField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant State / Province:") || strings.HasPrefix(line, "Admin State / Province:") || strings.HasPrefix(line, "Tech State / Province:") {
		state := p.extractValue(line, "Registrant State / Province:", "Admin State / Province:", "Tech State / Province:")
		if state != "" && state != "UNKNOWN" {
			c.State = state
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleCityField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant City:") || strings.HasPrefix(line, "Admin City:") || strings.HasPrefix(line, "Tech City:") {
		city := p.extractValue(line, "Registrant City:", "Admin City:", "Tech City:")
		if city != "" && city != "UNKNOWN" {
			c.City = city
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleAddressField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Address:") || strings.HasPrefix(line, "Admin Address:") || strings.HasPrefix(line, "Tech Address:") {
		addr := p.extractValue(line, "Registrant Address:", "Admin Address:", "Tech Address:")
		if addr != "" {
			c.Street = append(c.Street, addr)
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handlePostalField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Postal Code:") || strings.HasPrefix(line, "Admin Postal Code:") || strings.HasPrefix(line, "Tech Postal Code:") {
		postal := p.extractValue(line, "Registrant Postal Code:", "Admin Postal Code:", "Tech Postal Code:")
		if postal != "" {
			c.Postal = postal
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handlePhoneField(line string, c *Contact) bool {
	if strings.HasPrefix(line, "Registrant Phone:") || strings.HasPrefix(line, "Admin Phone:") || strings.HasPrefix(line, "Tech Phone:") {
		phone := p.extractValue(line, "Registrant Phone:", "Admin Phone:", "Tech Phone:")
		if phone != "" && phone != "UNKNOWN" {
			c.Phone = phone
		}
		return true
	}
	return false
}

func (p *UGTLDParser) handleEmailField(line string, c *Contact) {
	if strings.HasPrefix(line, "Registrant Email:") || strings.HasPrefix(line, "Admin Email:") || strings.HasPrefix(line, "Tech Email:") {
		email := p.extractValue(line, "Registrant Email:", "Admin Email:", "Tech Email:")
		if email != "" {
			c.Email = email
		}
	}
}

func (p *UGTLDParser) extractValue(line string, prefixes ...string) string {
	for _, prefix := range prefixes {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func (p *UGTLDParser) assignContacts(parsed *ParsedWhois, registrant, admin, tech Contact) {
	if registrant.Name != "" || registrant.Organization != "" || registrant.Email != "" {
		parsed.Contacts.Registrant = &registrant
	}
	if admin.Name != "" || admin.Organization != "" || admin.Email != "" {
		parsed.Contacts.Admin = &admin
	}
	if tech.Name != "" || tech.Organization != "" || tech.Email != "" {
		parsed.Contacts.Tech = &tech
	}
}
